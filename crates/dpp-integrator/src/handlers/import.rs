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

use crate::{
    domain::{
        batch_runner::{BatchResult, run_batch},
        csv_parser,
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
    /// Total data rows in the uploaded file (excluding header).
    pub total_rows: usize,
    /// Number of rows that were successfully created as passports.
    pub success_count: usize,
    /// Number of rows that failed validation or vault creation.
    pub error_count: usize,
    /// Successfully created passports with their row positions.
    pub created: Vec<CreatedEntry>,
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
/// - `file`      — CSV or XLSX file (required)
/// - `dry_run`   — `"true"` or `"1"` to validate without creating records
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
    let mut dry_run = false;

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
                    "dry_run" => {
                        let val = field.text().await.unwrap_or_default();
                        dry_run = matches!(val.trim(), "true" | "1");
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

    // Dry run: return validation report without creating anything
    if dry_run {
        return (
            StatusCode::OK,
            Json(SyncImportResponse {
                total_rows,
                success_count: 0,
                error_count: row_errors.len(),
                created: vec![],
                errors: row_errors,
            }),
        )
            .into_response();
    }

    // ── Sync path (≤ SYNC_THRESHOLD valid rows) ───────────────────────────────
    if valid_rows.len() <= SYNC_THRESHOLD {
        let batch = run_batch(
            valid_rows,
            &state.vault_client,
            &auth_token,
            state.batch_concurrency,
        )
        .await;
        let (created, batch_errors) = batch_result_into_entries(batch);
        let mut all_errors = row_errors;
        all_errors.extend(batch_errors);

        return (
            StatusCode::OK,
            Json(SyncImportResponse {
                total_rows,
                success_count: created.len(),
                error_count: all_errors.len(),
                created,
                errors: all_errors,
            }),
        )
            .into_response();
    }

    // ── Async path (> SYNC_THRESHOLD rows) ───────────────────────────────────
    let job_id = Uuid::now_v7();
    // Gate the 202 on the job actually being persisted. If we can't store the
    // job, returning a job id the caller can never poll is worse than failing.
    if let Err(e) = state
        .job_store
        .insert(ImportJob::new(job_id, total_rows))
        .await
    {
        tracing::error!(%job_id, error = %e, "could not create import job");
        return http_problem::internal_error("Could not create the import job. Please retry.")
            .into_response();
    }

    let vault_client = state.vault_client.clone();
    let job_store = state.job_store.clone();
    let concurrency = state.batch_concurrency;

    tokio::spawn(async move {
        if let Err(e) = job_store.set_status(job_id, JobStatus::Processing).await {
            tracing::error!(%job_id, error = %e, "failed to mark import job processing");
        }
        let batch = run_batch(valid_rows, &vault_client, &auth_token, concurrency).await;
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

fn batch_result_into_entries(result: BatchResult) -> (Vec<CreatedEntry>, Vec<ErrorEntry>) {
    let created = result
        .created
        .into_iter()
        .map(|c| CreatedEntry {
            row: c.row,
            passport_id: c.passport_id,
            status: "draft".into(),
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

    (created, errors)
}
