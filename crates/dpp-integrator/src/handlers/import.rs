//! `POST /api/v1/import/{sector}` — CSV/XLSX bulk import with sync and async paths.

use axum::{
    Json,
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use dpp_common::http_problem::{self, Problem};
use serde::Serialize;
use uuid::Uuid;

use std::collections::HashMap;

use crate::{
    domain::{
        batch_runner::{BatchResult, run_batch},
        csv_parser,
        import_report::{FindingKind, ImportMode, ImportReport, ReportRow, RowFinding},
        matcher::{self, Classification},
        request::CreatePassportRequest,
        validate::{self, RowValidationError},
        xlsx_parser,
    },
    infra::job_store::{ImportJob, JobStatus},
    state::AppState,
};

/// Rows at or below this threshold are handled synchronously; above it an async
/// job is spawned and a `202 Accepted` is returned immediately.
const SYNC_THRESHOLD: usize = 100;

// ─── Response shapes ─────────────────────────────────────────────────────────

/// Response body for a synchronous import (≤ 100 valid rows).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncImportResponse {
    /// Id of the import job this response's report was persisted under —
    /// every import now mints one, sync or async, so the report is
    /// retrievable later via `GET /api/v1/imports/{jobId}`.
    pub job_id: String,
    /// Total data rows in the uploaded file (excluding header).
    pub total_rows: usize,
    /// Rows that did not error: created + updated + unchanged +
    /// conflict-published (the last two make no vault call but are not
    /// failures either — see the persisted report for the per-row breakdown).
    pub success_count: usize,
    /// Number of rows that failed validation or vault creation/update.
    pub error_count: usize,
    /// Newly created passports with their row positions.
    pub created: Vec<CreatedEntry>,
    /// Rows that matched an existing draft and were updated in place.
    pub updated: Vec<UpdatedEntry>,
    /// Per-row errors with field names and messages.
    pub errors: Vec<ErrorEntry>,
}

/// A successfully created passport in the sync response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedEntry {
    /// 1-based row number from the uploaded file.
    pub row: usize,
    /// Vault-assigned passport id.
    pub passport_id: String,
    /// Always `"draft"` — passports are created in Draft status.
    pub status: String,
}

/// A successfully updated draft passport in the sync response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatedEntry {
    /// 1-based row number from the uploaded file.
    pub row: usize,
    /// The matched passport's id.
    pub passport_id: String,
}

/// A per-row import error in the sync or dry-run response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEntry {
    /// 1-based row number from the uploaded file.
    pub row: usize,
    /// Column name that triggered the error, or `"vault"` / `"auth"` / `"internal"`.
    pub field: String,
    /// Human-readable error message.
    pub message: String,
}

/// Response body for an async import (> 100 valid rows). Poll `GET
/// /api/v1/imports/{jobId}` to track progress.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncImportResponse {
    /// Unique id of the background import job.
    pub job_id: String,
    /// Always `"queued"` at creation time.
    pub status: String,
    /// Total data rows in the uploaded file (excluding header).
    pub total_rows: usize,
}

// ─── Handler ─────────────────────────────────────────────────────────────────

/// `POST /api/v1/import/{sector}`
///
/// Accepts a `multipart/form-data` upload with the following fields:
/// - `file`  — CSV or XLSX file (required)
/// - `mode`  — `"dry_run"` to validate without creating records; any other
///   value (or the field's absence) means `"apply"`, today's only write
///   behaviour (create-only — delta upsert lands in a later segment).
///
/// Every import — dry-run or apply, sync or async — mints a job id and
/// persists a row-addressed report retrievable via `GET
/// /api/v1/imports/{jobId}`; the dry-run report and the apply report share
/// the same shape.
///
/// The caller's `Authorization: Bearer` JWT is forwarded to the vault service.
pub async fn import_file(
    Path(sector): Path<String>,
    State(state): State<AppState>,
    request_headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Validate sector early
    if !validate::SUPPORTED_SECTORS.contains(&sector.as_str()) {
        metrics::counter!("import_rejections_total", "reason" => "unknown_sector").increment(1);
        return Problem::new(StatusCode::NOT_FOUND, "Not Found")
            .with_detail(format!(
                "Unknown sector: '{sector}'. Valid values: {}.",
                validate::SUPPORTED_SECTORS.join(", ")
            ))
            .into_response();
    }

    // Require a Bearer token BEFORE parsing the file, so anonymous callers never
    // reach the (allocation-heavy) parser.
    let auth_token = match extract_bearer_token(&request_headers) {
        Some(t) if !t.is_empty() => t,
        _ => {
            metrics::counter!("import_rejections_total", "reason" => "auth").increment(1);
            return Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail("Missing or empty Authorization: Bearer token.")
                .into_response();
        }
    };

    // A merely non-empty token is not enough — otherwise an attacker supplies any
    // junk string (`Bearer x`) and still drives the parser (RT2-1). Validate it
    // against the vault (same side-effect-free check the job-status endpoint
    // uses) before reading the body, so only authenticated operators get there.
    if !state.vault_client.verify_token(&auth_token).await {
        metrics::counter!("import_rejections_total", "reason" => "auth").increment(1);
        return Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
            .with_detail("Invalid or unauthorized Authorization: Bearer token.")
            .into_response();
    }

    // Parse multipart fields
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut is_xlsx = false;
    let mut mode = ImportMode::Apply;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_owned();
                let content_type = field.content_type().map(|s| s.to_owned());
                let filename = field.file_name().map(|s| s.to_owned());

                match name.as_str() {
                    "file" => {
                        // Detect XLSX from content-type or filename extension
                        is_xlsx = content_type
                            .as_deref()
                            .map(|ct| {
                                ct.contains("spreadsheet")
                                    || ct.contains("excel")
                                    || ct.contains("xlsx")
                            })
                            .unwrap_or(false)
                            || filename
                                .as_deref()
                                .map(|f| f.ends_with(".xlsx") || f.ends_with(".ods"))
                                .unwrap_or(false);

                        match field.bytes().await {
                            Ok(b) => file_bytes = Some(b.to_vec()),
                            Err(e) => {
                                return http_problem::bad_request(format!(
                                    "Failed to read uploaded file: {e}"
                                ))
                                .into_response();
                            }
                        }
                    }
                    "mode" => {
                        let val = field.text().await.unwrap_or_default();
                        mode = match val.trim() {
                            "dry_run" | "dryRun" => ImportMode::DryRun,
                            _ => ImportMode::Apply,
                        };
                    }
                    _ => {
                        // Unknown fields are silently ignored
                        let _ = field.bytes().await;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                return http_problem::bad_request(format!("Multipart read error: {e}"))
                    .into_response();
            }
        }
    }

    let file_bytes = match file_bytes {
        Some(b) => b,
        None => {
            return http_problem::bad_request(
                "Request must include a 'file' field in the multipart body.",
            )
            .into_response();
        }
    };

    // Parse the file into raw rows
    let raw_rows = if is_xlsx {
        match xlsx_parser::parse_xlsx(&file_bytes) {
            Ok(rows) => rows,
            Err(e) => {
                metrics::counter!("import_rejections_total", "reason" => "parse").increment(1);
                return http_problem::unprocessable(format!("XLSX parse error: {e}"))
                    .into_response();
            }
        }
    } else {
        match csv_parser::parse_csv(&file_bytes) {
            Ok(rows) => rows,
            Err(e) => {
                metrics::counter!("import_rejections_total", "reason" => "parse").increment(1);
                return http_problem::unprocessable(format!("CSV parse error: {e}"))
                    .into_response();
            }
        }
    };

    if raw_rows.is_empty() {
        return http_problem::unprocessable("The uploaded file contains no data rows.")
            .into_response();
    }

    let total_rows = raw_rows.len();
    metrics::counter!("import_rows_total").increment(total_rows as u64);

    // Validate every row; collect results without aborting on first error
    let mut valid_rows: Vec<(usize, CreatePassportRequest)> = Vec::new();
    let mut row_errors: Vec<ErrorEntry> = Vec::new();

    for (i, raw_row) in raw_rows.iter().enumerate() {
        let row_num = i + 1; // 1-based for user-facing messages
        match validate::validate_row(&sector, raw_row, row_num) {
            Ok(req) => valid_rows.push((row_num, req)),
            Err(RowValidationError::Invalid(errs)) => {
                for e in errs {
                    row_errors.push(ErrorEntry {
                        row: e.row,
                        field: e.field,
                        message: e.message,
                    });
                }
            }
            // The pre-upload SUPPORTED_SECTORS check above already rejected any
            // sector that would land here — kept as a real, typed branch rather
            // than `unreachable!()` so this stays correct if the two checks
            // ever move apart.
            Err(RowValidationError::UnsupportedSector) => {
                metrics::counter!("import_rejections_total", "reason" => "unknown_sector")
                    .increment(1);
                return Problem::new(StatusCode::NOT_FOUND, "Not Found")
                    .with_detail(format!("Unknown sector: '{sector}'."))
                    .into_response();
            }
        }
    }

    // Every import — dry-run or apply, sync or async — mints a job id and
    // persists a row-addressed report, so it's retrievable via
    // GET /api/v1/imports/{jobId} even when the response below is synchronous.
    // Gate on the job actually being persisted: returning a job id the caller
    // can never poll is worse than failing.
    let job_id = Uuid::now_v7();
    if let Err(e) = state
        .job_store
        .insert(ImportJob::new(job_id, total_rows))
        .await
    {
        tracing::error!(%job_id, error = %e, "could not create import job");
        return http_problem::internal_error("Could not create the import job. Please retry.")
            .into_response();
    }
    // Advisory plausibility lint on every accepted row — non-gating
    // (never removes a row from valid_rows, never invalidates it), same
    // contract as the vault's own lint step.
    let mut lint_findings: std::collections::HashMap<usize, Vec<RowFinding>> =
        std::collections::HashMap::new();
    for (row_num, req) in &valid_rows {
        let Some(ref sd) = req.sector_data else {
            continue;
        };
        let findings = dpp_domain::lint_sector_data(sd, chrono::Utc::now());
        if !findings.is_empty() {
            lint_findings.insert(
                *row_num,
                findings
                    .into_iter()
                    .map(|f| RowFinding {
                        kind: FindingKind::Lint,
                        field: f.field,
                        message: f.message,
                        severity: Some(f.severity),
                    })
                    .collect(),
            );
        }
    }

    // Delta-matcher: classify each valid row against existing passports by
    // exact identity (sector, GTIN, batch). Apply's write path below reads
    // this same map back to decide create/update/skip per row.
    let classifications = matcher::classify_batch(
        &valid_rows,
        &state.vault_client,
        &auth_token,
        state.batch_concurrency,
    )
    .await;

    let report = ImportReport {
        mode,
        total_rows,
        rows: build_report_rows(
            total_rows,
            &valid_rows,
            &row_errors,
            lint_findings,
            &classifications,
        ),
    };
    if let Err(e) = state.job_store.record_report(job_id, report).await {
        tracing::error!(%job_id, error = %e, "failed to persist import report");
    }

    // Dry run: return validation report without creating anything
    if mode == ImportMode::DryRun {
        let _ = state
            .job_store
            .set_status(job_id, JobStatus::Completed)
            .await;
        return (
            StatusCode::OK,
            Json(SyncImportResponse {
                job_id: job_id.to_string(),
                total_rows,
                success_count: 0,
                error_count: row_errors.len(),
                created: vec![],
                updated: vec![],
                errors: row_errors,
            }),
        )
            .into_response();
    }

    // ── Sync path (≤ SYNC_THRESHOLD valid rows) ───────────────────────────────
    if valid_rows.len() <= SYNC_THRESHOLD {
        let batch = run_batch(
            valid_rows,
            &classifications,
            &state.vault_client,
            &auth_token,
            state.batch_concurrency,
        )
        .await;
        let (created, updated, batch_errors) = batch_result_into_entries(batch.clone());
        let mut all_errors = row_errors;
        all_errors.extend(batch_errors);
        if let Err(e) = state.job_store.complete(job_id, batch).await {
            tracing::error!(%job_id, error = %e, "failed to record import job completion");
        }

        return (
            StatusCode::OK,
            Json(SyncImportResponse {
                job_id: job_id.to_string(),
                total_rows,
                success_count: total_rows - all_errors.len(),
                error_count: all_errors.len(),
                created,
                updated,
                errors: all_errors,
            }),
        )
            .into_response();
    }

    // ── Async path (> SYNC_THRESHOLD rows) ───────────────────────────────────
    let vault_client = state.vault_client.clone();
    let job_store = state.job_store.clone();
    let concurrency = state.batch_concurrency;

    tokio::spawn(async move {
        if let Err(e) = job_store.set_status(job_id, JobStatus::Processing).await {
            tracing::error!(%job_id, error = %e, "failed to mark import job processing");
        }
        let batch = run_batch(
            valid_rows,
            &classifications,
            &vault_client,
            &auth_token,
            concurrency,
        )
        .await;
        if let Err(e) = job_store.complete(job_id, batch).await {
            tracing::error!(%job_id, error = %e, "failed to record import job completion");
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(AsyncImportResponse {
            job_id: job_id.to_string(),
            status: "queued".into(),
            total_rows,
        }),
    )
        .into_response()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the raw token string from an `Authorization: Bearer <token>` header.
/// Returns `None` if the header is absent or the prefix does not match.
pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(|s| s.to_owned())
}

/// Build the persisted, row-addressed report from this pass's validation,
/// lint, and matcher results. Every row from `1..=total_rows` lands in
/// exactly one of `valid_rows`/`row_errors` (the validation loop above
/// guarantees it), so this reconstructs a complete per-row outcome without a
/// third pass over the raw rows. `lint_findings` and `classifications` only
/// ever have entries for rows already in `valid_rows`; lint is advisory
/// (appends findings, never flips `valid` to `false`). `classifications` is
/// borrowed, not drained — the caller still needs it afterward to run apply.
fn build_report_rows(
    total_rows: usize,
    valid_rows: &[(usize, CreatePassportRequest)],
    row_errors: &[ErrorEntry],
    mut lint_findings: std::collections::HashMap<usize, Vec<RowFinding>>,
    classifications: &HashMap<usize, Classification>,
) -> Vec<ReportRow> {
    let valid_row_nums: std::collections::HashSet<usize> =
        valid_rows.iter().map(|(n, _)| *n).collect();
    let mut findings_by_row: std::collections::HashMap<usize, Vec<RowFinding>> =
        std::collections::HashMap::new();
    for e in row_errors {
        findings_by_row.entry(e.row).or_default().push(RowFinding {
            kind: FindingKind::Validation,
            field: e.field.clone(),
            message: e.message.clone(),
            severity: None,
        });
    }
    (1..=total_rows)
        .map(|row| {
            let mut findings = findings_by_row.remove(&row).unwrap_or_default();
            if let Some(mut lint) = lint_findings.remove(&row) {
                findings.append(&mut lint);
            }
            let classification = classifications.get(&row);
            ReportRow {
                row,
                valid: valid_row_nums.contains(&row),
                action: classification.map(|c| c.action),
                existing_passport_id: classification.and_then(|c| c.existing_id.clone()),
                findings,
            }
        })
        .collect()
}

fn batch_result_into_entries(
    result: BatchResult,
) -> (Vec<CreatedEntry>, Vec<UpdatedEntry>, Vec<ErrorEntry>) {
    let created = result
        .created
        .into_iter()
        .map(|c| CreatedEntry {
            row: c.row,
            passport_id: c.passport_id,
            status: "draft".into(),
        })
        .collect();

    let updated = result
        .updated
        .into_iter()
        .map(|u| UpdatedEntry {
            row: u.row,
            passport_id: u.passport_id,
        })
        .collect();

    let errors = result
        .errors
        .into_iter()
        .map(|e| ErrorEntry {
            row: e.row,
            field: e.field,
            message: e.message,
        })
        .collect();

    (created, updated, errors)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use axum::{Router, body::Body, http::Request};
    use tower::ServiceExt;

    use crate::{
        domain::import_report::{FindingKind, ImportMode},
        domain::matcher::RowAction,
        infra::{job_store::InMemoryJobStore, job_store::JobStatus, vault_client::VaultHttpClient},
        state::AppState,
    };

    /// A real Ed25519-free GTIN with a valid checksum (shared elsewhere in this
    /// codebase as the canonical "known good" test fixture) — reused across every
    /// row here since row-level validation runs a real mod-10 checksum, not just a
    /// length check.
    const VALID_GTIN: &str = "09506000134352";
    const BATTERY_CSV_HEADER: &str = "productName,gtin,batchId,manufacturerName,manufacturerCountry,batteryChemistry,nominalVoltageV,nominalCapacityAh,expectedLifetimeCycles,co2ePerUnitKg";

    fn battery_csv_row(gtin: &str) -> String {
        format!("EV Battery 48V,{gtin},BATCH-1,Acme Energy,DE,LFP,48.0,100.0,3000,85.4")
    }

    fn battery_csv(num_rows: usize) -> String {
        let mut s = String::from(BATTERY_CSV_HEADER);
        s.push('\n');
        for _ in 0..num_rows {
            s.push_str(&battery_csv_row(VALID_GTIN));
            s.push('\n');
        }
        s
    }

    /// Hand-builds a `multipart/form-data` body — no request-side multipart
    /// builder is available as a dependency here.
    fn multipart_body(
        boundary: &str,
        filename: &str,
        file_contents: &str,
        mode: Option<&str>,
    ) -> Vec<u8> {
        let mut body = String::new();
        body.push_str(&format!("--{boundary}\r\n"));
        body.push_str(&format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        ));
        body.push_str("Content-Type: text/csv\r\n\r\n");
        body.push_str(file_contents);
        body.push_str("\r\n");
        if let Some(m) = mode {
            body.push_str(&format!("--{boundary}\r\n"));
            body.push_str("Content-Disposition: form-data; name=\"mode\"\r\n\r\n");
            body.push_str(m);
            body.push_str("\r\n");
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        body.into_bytes()
    }

    /// Byte-oriented sibling of `multipart_body` — that one builds the body as
    /// a `String`, which can't carry a binary XLSX payload (it isn't valid
    /// UTF-8). Used only by the XLSX-parity test.
    fn multipart_body_bytes(
        boundary: &str,
        filename: &str,
        file_bytes: &[u8],
        content_type: &str,
        mode: Option<&str>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        if let Some(m) = mode {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"mode\"\r\n\r\n");
            body.extend_from_slice(m.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// 0-based column index -> spreadsheet column letters (`0` -> `A`, `25` ->
    /// `Z`, `26` -> `AA`, ...). Only ever called with single digits here (10
    /// battery columns), but written as the general bijective base-26 rule
    /// rather than hardcoding `A`..`J`.
    fn column_letter(mut idx: usize) -> String {
        let mut letters = Vec::new();
        idx += 1;
        while idx > 0 {
            let rem = (idx - 1) % 26;
            letters.push(b'A' + rem as u8);
            idx = (idx - 1) / 26;
        }
        letters.reverse();
        String::from_utf8(letters).unwrap()
    }

    /// Build a minimal, valid XLSX workbook (single sheet, every cell an
    /// inline string) from the exact same comma-separated row text the CSV
    /// tests already build — so the XLSX and CSV paths are proven against
    /// byte-identical row content, not two fixtures written by hand that only
    /// look equivalent. No `sharedStrings.xml`/`styles.xml` (both optional to
    /// calamine); the five parts here are the ones it actually reads.
    fn build_xlsx_from_csv(csv_text: &str) -> Vec<u8> {
        let mut sheet_data = String::new();
        for (r, line) in csv_text.lines().filter(|l| !l.is_empty()).enumerate() {
            let row_num = r + 1;
            sheet_data.push_str(&format!(r#"<row r="{row_num}">"#));
            for (c, value) in line.split(',').enumerate() {
                let col = column_letter(c);
                let escaped = value
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");
                sheet_data.push_str(&format!(
                    r#"<c r="{col}{row_num}" t="inlineStr"><is><t>{escaped}</t></is></c>"#
                ));
            }
            sheet_data.push_str("</row>");
        }

        let worksheet = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{sheet_data}</sheetData></worksheet>"#
        );

        const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#;

        const ROOT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;

        const WORKBOOK: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#;

        const WORKBOOK_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#;

        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("[Content_Types].xml", opts).unwrap();
            zw.write_all(CONTENT_TYPES.as_bytes()).unwrap();
            zw.start_file("_rels/.rels", opts).unwrap();
            zw.write_all(ROOT_RELS.as_bytes()).unwrap();
            zw.start_file("xl/workbook.xml", opts).unwrap();
            zw.write_all(WORKBOOK.as_bytes()).unwrap();
            zw.start_file("xl/_rels/workbook.xml.rels", opts).unwrap();
            zw.write_all(WORKBOOK_RELS.as_bytes()).unwrap();
            zw.start_file("xl/worksheets/sheet1.xml", opts).unwrap();
            zw.write_all(worksheet.as_bytes()).unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    fn import_request(sector: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/import/{sector}"))
            .header("authorization", "Bearer test-token")
            .header("content-type", "multipart/form-data; boundary=X")
            .body(Body::from(body))
            .unwrap()
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A mock vault: `GET /api/v1/dpps` answers `verify_token`, `POST /api/v1/dpp`
    /// answers `create_passport` (and remembers what it created), `GET
    /// /api/v1/dpp/by-identity` answers the matcher's lookup against whatever
    /// has been created or directly seeded. This module is testing
    /// `import_file`'s own logic (parsing, validation, sync/async dispatch,
    /// matching), not `run_batch`'s retry behaviour (covered separately at the
    /// vault-client level).
    mod mock_vault {
        use axum::{
            Json, Router,
            extract::{Path, Query, State},
            http::StatusCode,
            response::{IntoResponse, Response},
            routing::{get, post, put},
        };
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Default)]
        pub(super) struct State_ {
            pub(super) create_hits: AtomicUsize,
            pub(super) update_hits: AtomicUsize,
            /// `pub(super)` so tests can flip a created passport to `active`
            /// directly — `create_handler` only ever produces `draft`.
            pub(super) passports: Mutex<Vec<serde_json::Value>>,
        }

        async fn verify_handler() -> Response {
            (StatusCode::OK, Json(serde_json::json!({"items": []}))).into_response()
        }

        async fn create_handler(
            State(state): State<Arc<State_>>,
            Json(mut body): Json<serde_json::Value>,
        ) -> Response {
            let n = state.create_hits.fetch_add(1, Ordering::SeqCst) + 1;
            let id = format!("pp-{n}");
            body["id"] = serde_json::json!(id);
            body["status"] = serde_json::json!("draft");
            state.passports.lock().unwrap().push(body.clone());
            (StatusCode::CREATED, Json(body)).into_response()
        }

        /// Shallow merge-patch onto the matched passport, matching the real
        /// vault's `PUT /api/v1/dpp/{dppId}` semantics.
        async fn update_handler(
            State(state): State<Arc<State_>>,
            Path(id): Path<String>,
            Json(body): Json<serde_json::Value>,
        ) -> Response {
            state.update_hits.fetch_add(1, Ordering::SeqCst);
            let mut passports = state.passports.lock().unwrap();
            let Some(existing) = passports
                .iter_mut()
                .find(|p| p.get("id").and_then(|v| v.as_str()) == Some(id.as_str()))
            else {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"detail": "not found"})),
                )
                    .into_response();
            };
            if let (Some(existing_obj), Some(body_obj)) =
                (existing.as_object_mut(), body.as_object())
            {
                for (k, v) in body_obj {
                    existing_obj.insert(k.clone(), v.clone());
                }
            }
            (StatusCode::OK, Json(existing.clone())).into_response()
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct IdentityParams {
            sector: String,
            gtin: String,
            #[serde(default)]
            batch_id: Option<String>,
        }

        async fn find_by_identity_handler(
            State(state): State<Arc<State_>>,
            Query(q): Query<IdentityParams>,
        ) -> Response {
            let found = state
                .passports
                .lock()
                .unwrap()
                .iter()
                .find(|p| {
                    p.get("sectorData")
                        .and_then(|sd| sd.get("sector"))
                        .and_then(|s| s.as_str())
                        == Some(q.sector.as_str())
                        && p.get("sectorData")
                            .and_then(|sd| sd.get("gtin"))
                            .and_then(|g| g.as_str())
                            == Some(q.gtin.as_str())
                        && p.get("batchId").and_then(|b| b.as_str()) == q.batch_id.as_deref()
                })
                .cloned();
            match found {
                Some(p) => (StatusCode::OK, Json(p)).into_response(),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"detail": "no passport matches that identity"})),
                )
                    .into_response(),
            }
        }

        pub(super) async fn spawn() -> (String, Arc<State_>) {
            let state = Arc::new(State_::default());
            let app = Router::new()
                .route("/api/v1/dpps", get(verify_handler))
                .route("/api/v1/dpp", post(create_handler))
                .route("/api/v1/dpp/by-identity", get(find_by_identity_handler))
                .route("/api/v1/dpp/{id}", put(update_handler))
                .with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (format!("http://{addr}"), state)
        }
    }

    async fn live_vault_state() -> (AppState, Arc<mock_vault::State_>) {
        let (base_url, mock_state) = mock_vault::spawn().await;
        let state = AppState {
            vault_client: Arc::new(VaultHttpClient::new(&base_url)),
            job_store: Arc::new(InMemoryJobStore::new()),
            batch_concurrency: 4,
        };
        (state, mock_state)
    }

    fn build_router(state: AppState) -> Router {
        crate::router::build(state)
    }

    #[tokio::test]
    async fn sync_import_creates_passports_for_valid_rows() {
        let (state, mock) = live_vault_state().await;
        let app = build_router(state);

        let body = multipart_body("X", "battery.csv", &battery_csv(3), None);
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["totalRows"], 3);
        assert_eq!(json["successCount"], 3);
        assert_eq!(json["errorCount"], 0);
        assert_eq!(mock.create_hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn dry_run_validates_without_creating_anything() {
        let (state, mock) = live_vault_state().await;
        let app = build_router(state);

        let body = multipart_body("X", "battery.csv", &battery_csv(2), Some("dry_run"));
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["successCount"], 0);
        assert_eq!(json["created"].as_array().unwrap().len(), 0);
        assert_eq!(
            mock.create_hits.load(Ordering::SeqCst),
            0,
            "dry run must never call the vault"
        );
    }

    /// GS1 mod-10 check digit for a 13-digit data prefix — lets tests mint
    /// several distinct, individually valid GTIN-14s (battery's row
    /// validator runs a real checksum, not just a length check).
    fn nth_valid_gtin(n: u32) -> String {
        let data13 = format!("{n:013}");
        let digits: Vec<u8> = data13.bytes().map(|b| b - b'0').collect();
        let check = dpp_domain::domain::gtin::gs1_check_digit(&digits);
        format!("{data13}{check}")
    }

    /// Golden CSV pair — S3's own gate: dry-run names every action correctly
    /// with zero writes, against real prior state (created through the same
    /// import path, not hand-built fixtures).
    #[tokio::test]
    async fn golden_csv_pair_classifies_every_action_correctly() {
        let (state, mock) = live_vault_state().await;
        let job_store = state.job_store.clone();
        let app = build_router(state);

        let unchanged_gtin = nth_valid_gtin(1);
        let edited_gtin = nth_valid_gtin(2);
        let published_gtin = nth_valid_gtin(3);
        let new_gtin = nth_valid_gtin(4);

        fn row(product_name: &str, gtin: &str, batch: &str) -> String {
            format!("{product_name},{gtin},{batch},Acme Energy,DE,LFP,48.0,100.0,3000,85.4")
        }

        // ── "v1 sheet": apply-mode import creates three draft passports ──────
        let mut v1 = String::from(BATTERY_CSV_HEADER);
        v1.push('\n');
        v1.push_str(&row("Steady Battery", &unchanged_gtin, "BATCH-1"));
        v1.push('\n');
        v1.push_str(&row("Original Name", &edited_gtin, "BATCH-2"));
        v1.push('\n');
        v1.push_str(&row("Published Original", &published_gtin, "BATCH-3"));
        v1.push('\n');

        let body = multipart_body("X", "v1.csv", &v1, None);
        let resp = app
            .clone()
            .oneshot(import_request("battery", body))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "v1 import must succeed"
        );
        assert_eq!(mock.create_hits.load(Ordering::SeqCst), 3);

        // Simulate that BATCH-3 was published since the v1 import.
        {
            let mut passports = mock.passports.lock().unwrap();
            let published = passports
                .iter_mut()
                .find(|p| p["sectorData"]["gtin"].as_str() == Some(published_gtin.as_str()))
                .expect("BATCH-3 passport must exist after v1 import");
            published["status"] = serde_json::json!("active");
        }

        // ── "v2 sheet": one unchanged, one edited, one conflicting-published,
        //    one brand new ────────────────────────────────────────────────
        let mut v2 = String::from(BATTERY_CSV_HEADER);
        v2.push('\n');
        v2.push_str(&row("Steady Battery", &unchanged_gtin, "BATCH-1")); // identical
        v2.push('\n');
        v2.push_str(&row("Edited Name", &edited_gtin, "BATCH-2")); // draft, changed
        v2.push('\n');
        v2.push_str(&row("Published Edited", &published_gtin, "BATCH-3")); // published, changed
        v2.push('\n');
        v2.push_str(&row("Brand New Battery", &new_gtin, "BATCH-4")); // no match
        v2.push('\n');

        let body = multipart_body("X", "v2.csv", &v2, Some("dry_run"));
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            mock.create_hits.load(Ordering::SeqCst),
            3,
            "dry run must not create anything — v1's 3 creates must be the only ones"
        );

        let json = response_json(resp).await;
        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();
        let job = job_store
            .get(job_id)
            .await
            .expect("v2 job must be retrievable");
        let report = job.report.expect("v2 report must be persisted");
        assert_eq!(report.rows.len(), 4, "one report row per v2 row");

        assert_eq!(
            report.rows[0].action,
            Some(RowAction::Unchanged),
            "identical content against a draft match must be Unchanged"
        );
        assert_eq!(
            report.rows[1].action,
            Some(RowAction::UpdateDraft),
            "changed content against a draft match must be UpdateDraft"
        );
        assert_eq!(
            report.rows[2].action,
            Some(RowAction::ConflictPublished),
            "changed content against a published match must be ConflictPublished, never mutated"
        );
        assert_eq!(
            report.rows[3].action,
            Some(RowAction::Create),
            "no existing match must be Create"
        );
    }

    /// S5's own gate: apply acts on the matcher's classification instead of
    /// unconditionally creating — same v1/v2 setup as the golden pair, but
    /// "v2" runs in apply mode and asserts the actual vault calls made.
    #[tokio::test]
    async fn apply_acts_on_classification_instead_of_always_creating() {
        let (state, mock) = live_vault_state().await;
        let job_store = state.job_store.clone();
        let app = build_router(state);

        let unchanged_gtin = nth_valid_gtin(11);
        let edited_gtin = nth_valid_gtin(12);
        let published_gtin = nth_valid_gtin(13);
        let new_gtin = nth_valid_gtin(14);

        fn row(product_name: &str, gtin: &str, batch: &str) -> String {
            format!("{product_name},{gtin},{batch},Acme Energy,DE,LFP,48.0,100.0,3000,85.4")
        }

        let mut v1 = String::from(BATTERY_CSV_HEADER);
        v1.push('\n');
        v1.push_str(&row("Steady Battery", &unchanged_gtin, "BATCH-1"));
        v1.push('\n');
        v1.push_str(&row("Original Name", &edited_gtin, "BATCH-2"));
        v1.push('\n');
        v1.push_str(&row("Published Original", &published_gtin, "BATCH-3"));
        v1.push('\n');

        let body = multipart_body("X", "v1.csv", &v1, None);
        let resp = app
            .clone()
            .oneshot(import_request("battery", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(mock.create_hits.load(Ordering::SeqCst), 3);

        {
            let mut passports = mock.passports.lock().unwrap();
            let published = passports
                .iter_mut()
                .find(|p| p["sectorData"]["gtin"].as_str() == Some(published_gtin.as_str()))
                .expect("BATCH-3 passport must exist after v1 import");
            published["status"] = serde_json::json!("active");
        }

        let mut v2 = String::from(BATTERY_CSV_HEADER);
        v2.push('\n');
        v2.push_str(&row("Steady Battery", &unchanged_gtin, "BATCH-1")); // identical
        v2.push('\n');
        v2.push_str(&row("Edited Name", &edited_gtin, "BATCH-2")); // draft, changed
        v2.push('\n');
        v2.push_str(&row("Published Edited", &published_gtin, "BATCH-3")); // published, changed
        v2.push('\n');
        v2.push_str(&row("Brand New Battery", &new_gtin, "BATCH-4")); // no match
        v2.push('\n');

        // Apply mode this time (mode omitted — apply is the default).
        let body = multipart_body("X", "v2.csv", &v2, None);
        let resp = app
            .clone()
            .oneshot(import_request("battery", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["totalRows"], 4);
        assert_eq!(json["errorCount"], 0);
        assert_eq!(
            json["successCount"], 4,
            "no row errored — created/updated/unchanged/conflict all count as success"
        );
        assert_eq!(
            json["created"].as_array().unwrap().len(),
            1,
            "only the brand-new row should be created"
        );
        assert_eq!(
            json["updated"].as_array().unwrap().len(),
            1,
            "only the edited-draft row should be updated"
        );

        assert_eq!(
            mock.create_hits.load(Ordering::SeqCst),
            4,
            "v1's 3 creates plus exactly 1 new create from v2 — not 4 more"
        );
        assert_eq!(
            mock.update_hits.load(Ordering::SeqCst),
            1,
            "exactly one PUT — the edited draft row — unchanged and conflict rows must never call update"
        );

        // ── S6: re-submit the identical v2 sheet a third time ────────────────
        // Proves idempotence through a real state transition, not just against
        // a hand-set fixture: BATCH-2 and BATCH-4 were just mutated by the call
        // above, so this checks the matcher correctly treats its own prior
        // output as the new baseline, not that "unchanged rows stay unchanged"
        // (already covered by the golden pair and by BATCH-1 above).
        let body = multipart_body("X", "v2.csv", &v2, None);
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(
            json["created"].as_array().unwrap().len(),
            0,
            "re-applying the same sheet must create nothing new"
        );
        assert_eq!(
            json["updated"].as_array().unwrap().len(),
            0,
            "re-applying the same sheet must update nothing — BATCH-2 is now identical to its own draft"
        );
        assert_eq!(
            mock.create_hits.load(Ordering::SeqCst),
            4,
            "zero additional creates on re-apply"
        );
        assert_eq!(
            mock.update_hits.load(Ordering::SeqCst),
            1,
            "zero additional updates on re-apply"
        );

        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();
        let report = job_store
            .get(job_id)
            .await
            .expect("third-call job must be retrievable")
            .report
            .expect("third-call report must be persisted");
        assert_eq!(
            report.rows[0].action,
            Some(RowAction::Unchanged),
            "BATCH-1 was already unchanged and stays that way"
        );
        assert_eq!(
            report.rows[1].action,
            Some(RowAction::Unchanged),
            "BATCH-2's prior update is now the baseline — re-submitting it must read as Unchanged, not UpdateDraft again"
        );
        assert_eq!(
            report.rows[2].action,
            Some(RowAction::ConflictPublished),
            "BATCH-3 never resolves itself — the published passport was never mutated, so this conflict recurs on every resubmission"
        );
        assert_eq!(
            report.rows[3].action,
            Some(RowAction::Unchanged),
            "BATCH-4's prior create is now the baseline — re-submitting it must read as Unchanged, not Create again"
        );
    }

    /// S7's own gate: the XLSX parser must feed the exact same downstream
    /// pipeline as CSV. Same v1/v2 golden pair as S3's own gate, but "v2" is
    /// uploaded as a hand-built XLSX workbook (`build_xlsx_from_csv`) instead
    /// of CSV text, asserting the matcher classifies every row identically.
    #[tokio::test]
    async fn xlsx_upload_classifies_identically_to_the_csv_golden_pair() {
        let (state, mock) = live_vault_state().await;
        let job_store = state.job_store.clone();
        let app = build_router(state);

        let unchanged_gtin = nth_valid_gtin(21);
        let edited_gtin = nth_valid_gtin(22);
        let published_gtin = nth_valid_gtin(23);
        let new_gtin = nth_valid_gtin(24);

        fn row(product_name: &str, gtin: &str, batch: &str) -> String {
            format!("{product_name},{gtin},{batch},Acme Energy,DE,LFP,48.0,100.0,3000,85.4")
        }

        let mut v1 = String::from(BATTERY_CSV_HEADER);
        v1.push('\n');
        v1.push_str(&row("Steady Battery", &unchanged_gtin, "BATCH-1"));
        v1.push('\n');
        v1.push_str(&row("Original Name", &edited_gtin, "BATCH-2"));
        v1.push('\n');
        v1.push_str(&row("Published Original", &published_gtin, "BATCH-3"));
        v1.push('\n');

        let body = multipart_body("X", "v1.csv", &v1, None);
        let resp = app
            .clone()
            .oneshot(import_request("battery", body))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "v1 import must succeed"
        );
        assert_eq!(mock.create_hits.load(Ordering::SeqCst), 3);

        // Simulate that BATCH-3 was published since the v1 import.
        {
            let mut passports = mock.passports.lock().unwrap();
            let published = passports
                .iter_mut()
                .find(|p| p["sectorData"]["gtin"].as_str() == Some(published_gtin.as_str()))
                .expect("BATCH-3 passport must exist after v1 import");
            published["status"] = serde_json::json!("active");
        }

        let mut v2 = String::from(BATTERY_CSV_HEADER);
        v2.push('\n');
        v2.push_str(&row("Steady Battery", &unchanged_gtin, "BATCH-1")); // identical
        v2.push('\n');
        v2.push_str(&row("Edited Name", &edited_gtin, "BATCH-2")); // draft, changed
        v2.push('\n');
        v2.push_str(&row("Published Edited", &published_gtin, "BATCH-3")); // published, changed
        v2.push('\n');
        v2.push_str(&row("Brand New Battery", &new_gtin, "BATCH-4")); // no match
        v2.push('\n');

        // Same v2 row content as the CSV golden pair, byte-sourced from the
        // same string, but encoded as a real XLSX workbook — proves the
        // parser front-end doesn't change the matcher's behaviour, not just
        // that XLSX "parses" in isolation (that's xlsx_parser's own tests).
        let xlsx_bytes = build_xlsx_from_csv(&v2);
        let body = multipart_body_bytes(
            "X",
            "v2.xlsx",
            &xlsx_bytes,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            Some("dry_run"),
        );
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            mock.create_hits.load(Ordering::SeqCst),
            3,
            "dry run must not create anything, XLSX or not — v1's 3 creates must be the only ones"
        );

        let json = response_json(resp).await;
        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();
        let job = job_store
            .get(job_id)
            .await
            .expect("xlsx job must be retrievable");
        let report = job.report.expect("xlsx report must be persisted");
        assert_eq!(report.rows.len(), 4, "one report row per xlsx row");

        assert_eq!(
            report.rows[0].action,
            Some(RowAction::Unchanged),
            "identical content against a draft match must be Unchanged, same as CSV"
        );
        assert_eq!(
            report.rows[1].action,
            Some(RowAction::UpdateDraft),
            "changed content against a draft match must be UpdateDraft, same as CSV"
        );
        assert_eq!(
            report.rows[2].action,
            Some(RowAction::ConflictPublished),
            "changed content against a published match must be ConflictPublished, same as CSV"
        );
        assert_eq!(
            report.rows[3].action,
            Some(RowAction::Create),
            "no existing match must be Create, same as CSV"
        );
    }

    #[tokio::test]
    async fn sync_apply_persists_a_retrievable_report() {
        let (state, _mock) = live_vault_state().await;
        let job_store = state.job_store.clone();
        let app = build_router(state);

        let mut csv = String::from(BATTERY_CSV_HEADER);
        csv.push('\n');
        csv.push_str(&battery_csv_row(VALID_GTIN));
        csv.push('\n');
        // GTIN too short — fails the row-level checksum/length check.
        csv.push_str("EV Battery Bad,1234,BATCH-2,Acme Energy,DE,LFP,48.0,100.0,3000,85.4\n");

        let body = multipart_body("X", "battery.csv", &csv, None);
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = response_json(resp).await;
        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();

        let job = job_store
            .get(job_id)
            .await
            .expect("job must be retrievable");
        assert!(matches!(job.status, JobStatus::Completed));
        let report = job.report.expect("report must be persisted");
        assert!(matches!(report.mode, ImportMode::Apply));
        assert_eq!(report.rows.len(), 2, "one report row per input row");
        assert!(report.rows[0].valid);
        assert!(!report.rows[1].valid);
        assert_eq!(report.rows[1].findings[0].field, "gtin");
    }

    #[tokio::test]
    async fn dry_run_persists_a_retrievable_report() {
        let (state, _mock) = live_vault_state().await;
        let job_store = state.job_store.clone();
        let app = build_router(state);

        let body = multipart_body("X", "battery.csv", &battery_csv(2), Some("dry_run"));
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        let json = response_json(resp).await;
        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();

        let job = job_store
            .get(job_id)
            .await
            .expect("job must be retrievable");
        let report = job.report.expect("report must be persisted");
        assert!(matches!(report.mode, ImportMode::DryRun));
        assert_eq!(report.rows.len(), 2);
        assert!(report.rows.iter().all(|r| r.valid));
    }

    #[tokio::test]
    async fn dry_run_surfaces_lint_findings_alongside_validation() {
        let (state, mock) = live_vault_state().await;
        let job_store = state.job_store.clone();
        let app = build_router(state);

        // repairScore >= 8 with neither disassemblyInstructions nor
        // sparePartsAvailable=true triggers textile.repair_score_high_without_support
        // (dpp-rules::lint::textile) — and the CSV path never sets either of
        // those two fields, so this is a deterministic, always-firing trigger.
        let header = "productName,gtin,batchId,manufacturerName,manufacturerCountry,fibreComposition,countryOfManufacturing,careInstructions,chemicalComplianceStandard,recycledContentPct,repairScore,carbonFootprintKgCo2e";
        let row = format!(
            "Organic Cotton Tee,{VALID_GTIN},BATCH-T-1,EcoWear,BD,\"[{{\"\"fibre\"\":\"\"cotton\"\",\"\"pct\"\":100}}]\",BD,30C wash,OEKO-TEX 100,,9.0,"
        );
        let csv = format!("{header}\n{row}\n");

        let body = multipart_body("X", "textile.csv", &csv, Some("dry_run"));
        let resp = app.oneshot(import_request("textile", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = response_json(resp).await;
        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();

        let job = job_store
            .get(job_id)
            .await
            .expect("job must be retrievable");
        let report = job.report.expect("report must be persisted");
        assert_eq!(report.rows.len(), 1);
        assert!(
            report.rows[0].valid,
            "a lint finding is advisory — it must not block the row"
        );
        let lint = report.rows[0]
            .findings
            .iter()
            .find(|f| matches!(f.kind, FindingKind::Lint))
            .expect("lint finding must surface in the dry-run report");
        assert_eq!(lint.field, "repairScore");
        assert_eq!(
            mock.create_hits.load(Ordering::SeqCst),
            0,
            "dry run must never call the vault"
        );
    }

    #[tokio::test]
    async fn unknown_sector_is_rejected_before_any_vault_call() {
        // Intentionally a dead vault URL: the sector check must reject this
        // before auth or parsing ever contact it.
        let state = AppState {
            vault_client: Arc::new(VaultHttpClient::new("http://127.0.0.1:1")),
            job_store: Arc::new(InMemoryJobStore::new()),
            batch_concurrency: 1,
        };
        let app = build_router(state);

        let body = multipart_body("X", "x.csv", "a,b\n1,2\n", None);
        let resp = app
            .oneshot(import_request("not-a-real-sector", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_file_field_is_rejected() {
        let (state, _mock) = live_vault_state().await;
        let app = build_router(state);

        let body =
            "--X\r\nContent-Disposition: form-data; name=\"dry_run\"\r\n\r\ntrue\r\n--X--\r\n"
                .to_owned()
                .into_bytes();
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_row_reports_error_and_lets_valid_rows_through() {
        let (state, mock) = live_vault_state().await;
        let app = build_router(state);

        let mut csv = String::from(BATTERY_CSV_HEADER);
        csv.push('\n');
        csv.push_str(&battery_csv_row(VALID_GTIN));
        csv.push('\n');
        // GTIN too short — fails the row-level checksum/length check.
        csv.push_str("EV Battery Bad,1234,BATCH-2,Acme Energy,DE,LFP,48.0,100.0,3000,85.4\n");

        let body = multipart_body("X", "battery.csv", &csv, None);
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["successCount"], 1);
        assert_eq!(json["errorCount"], 1);
        assert_eq!(json["errors"][0]["field"], "gtin");
        assert_eq!(mock.create_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn async_path_processes_the_job_in_the_background() {
        let (state, mock) = live_vault_state().await;
        let app = build_router(state.clone());

        // SYNC_THRESHOLD is 100 — 101 valid rows forces the async path.
        let body = multipart_body("X", "battery.csv", &battery_csv(101), None);
        let resp = app.oneshot(import_request("battery", body)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::ACCEPTED);

        let json = response_json(resp).await;
        assert_eq!(json["status"], "queued");
        assert_eq!(json["totalRows"], 101);
        let job_id = uuid::Uuid::parse_str(json["jobId"].as_str().unwrap()).unwrap();

        let job = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(job) = state.job_store.get(job_id).await
                    && matches!(job.status, JobStatus::Completed)
                {
                    return job;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("import job must complete within 10s");

        let result = job.result.expect("completed job must carry a result");
        assert_eq!(result.created.len(), 101);
        assert_eq!(mock.create_hits.load(Ordering::SeqCst), 101);
    }
}
