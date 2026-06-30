//! Passport actions: import, export, list, publish, suspend, archive, history, validate.

use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde_json::json;

use super::types::{
    ArchiveParams, AuditEntry, ExportParams, ExportResult, HistoryParams, ImportParams,
    ImportSummary, ListParams, PassportPage, PassportPublishResult, PassportSummary, ProgressEvent,
    PublishParams, PublishSummary, SuspendParams, ValidationRecord, ValidationReport,
};
use crate::{config::Config, http::OdalClient};

// ── Import ───────────────────────────────────────────────────────────────────

pub async fn action_import(
    params: &ImportParams,
    client: &OdalClient,
    cfg: &Config,
    progress: Option<&dyn Fn(ProgressEvent)>,
) -> Result<ImportSummary> {
    // JSON files are posted record-by-record to the vault create endpoint.
    if params.file.to_ascii_lowercase().ends_with(".json") {
        let content = std::fs::read_to_string(&params.file)
            .with_context(|| format!("Cannot read file: {}", params.file))?;
        let payloads = parse_json_payloads(&content)
            .with_context(|| format!("Cannot parse JSON: {}", params.file))?;
        return import_json_records(payloads, client, cfg, progress).await;
    }

    // CSV/XLSX go through the integrator's bulk endpoint — the single validated
    // path that maps every column (Annex XIII fields, materials) and runs the
    // compliance determination server-side via the vault create handler. The
    // sector is detected from the file's `sector` (or `productCategory`) column.
    let bytes = std::fs::read(&params.file)
        .with_context(|| format!("Cannot read file: {}", params.file))?;
    let filename = std::path::Path::new(&params.file)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.csv")
        .to_owned();
    let sector = detect_sector(&bytes).with_context(|| {
        format!(
            "Could not determine the sector for {}. Add a `sector` column \
             (battery, textile, steel, aluminium, tyre).",
            params.file
        )
    })?;

    if let Some(f) = progress {
        f(ProgressEvent::Started { total: None });
    }
    let url = format!("{}/api/v1/import/{}", cfg.integrator_url(), sector);
    let (status, body) = client.upload_file(&url, &filename, bytes).await?;
    if let Some(f) = progress {
        f(ProgressEvent::Done);
    }
    summarize_import_response(status, &body, client, cfg).await
}

/// Post each JSON record to the vault create endpoint (the `.json` import path).
async fn import_json_records(
    payloads: Vec<serde_json::Value>,
    client: &OdalClient,
    cfg: &Config,
    progress: Option<&dyn Fn(ProgressEvent)>,
) -> Result<ImportSummary> {
    if payloads.is_empty() {
        return Ok(ImportSummary {
            created: 0,
            failed: 0,
            errors: vec![],
        });
    }
    if let Some(f) = progress {
        f(ProgressEvent::Started {
            total: Some(payloads.len() as u64),
        });
    }
    let mut created = 0usize;
    let mut failed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let url = format!("{}/api/v1/dpp", cfg.vault_url);
    for (i, payload) in payloads.iter().enumerate() {
        match client.post_json(&url, payload).await {
            Ok((status, _)) if status.is_success() => created += 1,
            Ok((status, body)) => {
                failed += 1;
                errors.push(format!(
                    "Record {}: HTTP {} — {}",
                    i + 1,
                    status,
                    &body[..body.len().min(200)]
                ));
            }
            Err(e) => {
                failed += 1;
                errors.push(format!("Record {}: {}", i + 1, e));
            }
        }
        if let Some(f) = progress {
            f(ProgressEvent::Tick {
                current: (i + 1) as u64,
            });
        }
    }
    if let Some(f) = progress {
        f(ProgressEvent::Done);
    }
    Ok(ImportSummary {
        created,
        failed,
        errors,
    })
}

pub fn parse_json_payloads(content: &str) -> Result<Vec<serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    match value {
        serde_json::Value::Array(items) => Ok(items),
        obj @ serde_json::Value::Object(_) => Ok(vec![obj]),
        _ => anyhow::bail!("JSON must be a DPP object or an array of DPP objects"),
    }
}

/// Detect the import sector from a CSV's `sector` (or `productCategory`) column.
///
/// Returns `None` for non-UTF-8 input (e.g. XLSX) or when no recognisable sector
/// column/value is present. Delimiter is auto-detected (comma / tab / semicolon).
///
/// Uses a real CSV reader so a quoted field containing the delimiter (e.g. an
/// address `"Street 1, City, DE"`) does not shift the column positions — a naive
/// `split` would mis-locate the sector value.
pub fn detect_sector(bytes: &[u8]) -> Option<String> {
    let first_line = bytes.split(|&b| b == b'\n').next().unwrap_or(bytes);
    let delim = if first_line.contains(&b'\t') {
        b'\t'
    } else if first_line.contains(&b';') && !first_line.contains(&b',') {
        b';'
    } else {
        b','
    };
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(bytes);
    let headers: Vec<String> = reader.headers().ok()?.iter().map(str::to_owned).collect();
    let record = reader.records().next()?.ok()?;
    let value_for = |name: &str| {
        headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .and_then(|i| record.get(i))
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let raw = value_for("sector")
        .or_else(|| value_for("productCategory"))
        .or_else(|| value_for("product_category"))?;
    Some(raw.to_ascii_lowercase())
}

/// Map the integrator's import response (sync `200` or async `202`) into an
/// [`ImportSummary`]. Async jobs are polled to completion.
async fn summarize_import_response(
    status: StatusCode,
    body: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<ImportSummary> {
    if status == StatusCode::ACCEPTED {
        let resp: serde_json::Value =
            serde_json::from_str(body).context("Failed to parse async import response")?;
        let job_id = resp
            .get("jobId")
            .and_then(|v| v.as_str())
            .context("async import response missing jobId")?;
        return poll_import_job(client, cfg, job_id).await;
    }
    if !status.is_success() {
        anyhow::bail!(
            "Import failed (HTTP {status}): {}",
            &body[..body.len().min(300)]
        );
    }
    let resp: serde_json::Value =
        serde_json::from_str(body).context("Failed to parse import response")?;
    Ok(ImportSummary {
        created: resp
            .get("successCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
        failed: resp.get("errorCount").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        errors: error_entries(resp.get("errors")),
    })
}

/// Poll an async import job until it completes or fails (bounded to ~2 minutes).
async fn poll_import_job(client: &OdalClient, cfg: &Config, job_id: &str) -> Result<ImportSummary> {
    let url = format!("{}/api/v1/imports/{}", cfg.integrator_url(), job_id);
    for _ in 0..120 {
        let (status, body) = client.get(&url).await?;
        if !status.is_success() {
            anyhow::bail!(
                "Failed to poll import job (HTTP {status}): {}",
                &body[..body.len().min(200)]
            );
        }
        let resp: serde_json::Value =
            serde_json::from_str(&body).context("Failed to parse job status")?;
        match resp.get("status").and_then(|v| v.as_str()) {
            Some("completed") => {
                let result = resp
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let created = result
                    .get("created")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let errors = error_entries(result.get("errors"));
                return Ok(ImportSummary {
                    created,
                    failed: errors.len(),
                    errors,
                });
            }
            Some("failed") => {
                let reason = resp
                    .get("result")
                    .and_then(|r| r.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                anyhow::bail!("Import job failed: {reason}");
            }
            _ => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
    anyhow::bail!("Import job did not complete within the polling window")
}

/// Format the integrator's per-row error array into human-readable lines.
fn error_entries(errors: Option<&serde_json::Value>) -> Vec<String> {
    errors
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|e| {
                    let row = e.get("row").and_then(|v| v.as_u64()).unwrap_or(0);
                    let field = e.get("field").and_then(|v| v.as_str()).unwrap_or("-");
                    let msg = e.get("message").and_then(|v| v.as_str()).unwrap_or("");
                    format!("Row {row} [{field}]: {msg}")
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── Validate ─────────────────────────────────────────────────────────────────

pub async fn action_validate(client: &OdalClient, cfg: &Config) -> Result<ValidationReport> {
    let url = format!("{}/api/v1/dpps?status=draft", cfg.vault_url);
    let (http_status, body) = client.get(&url).await?;
    if !http_status.is_success() {
        anyhow::bail!(
            "Failed to fetch draft DPPs (HTTP {}): {}",
            http_status,
            body
        );
    }

    let envelope: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse vault response")?;
    let records: Vec<serde_json::Value> = envelope
        .get("dpps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    Ok(ValidationReport {
        records: records
            .iter()
            .map(|rec| ValidationRecord {
                id: rec
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_owned(),
                product_name: rec
                    .get("productName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_owned(),
                issues: find_issues(rec),
            })
            .collect(),
    })
}

pub fn find_issues(rec: &serde_json::Value) -> Vec<String> {
    let mut issues = Vec::new();

    for field in &["productName", "sectorData"] {
        if rec.get(field).is_none() || rec[field].is_null() {
            issues.push(format!("missing {field}"));
        }
    }

    if let Some(sd) = rec.get("sectorData").and_then(|v| v.as_object()) {
        match sd.get("sector").and_then(|s| s.as_str()) {
            Some("battery") => {
                for f in &[
                    "gtin",
                    "batteryChemistry",
                    "nominalVoltageV",
                    "nominalCapacityAh",
                    "expectedLifetimeCycles",
                    "co2ePerUnitKg",
                ] {
                    if sd.get(*f).is_none() {
                        issues.push(format!("sectorData.{f} missing"));
                    }
                }
            }
            Some("textile") => {
                for f in &[
                    "fibreComposition",
                    "countryOfManufacturing",
                    "careInstructions",
                    "chemicalComplianceStandard",
                ] {
                    if sd.get(*f).is_none() {
                        issues.push(format!("sectorData.{f} missing"));
                    }
                }
            }
            _ => {
                issues.push("unknown sector".into());
            }
        }
    }

    issues
}

// ── Publish ──────────────────────────────────────────────────────────────────

pub async fn action_publish(
    params: &PublishParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<PublishSummary> {
    match &params.id {
        Some(id) => publish_one(client, &cfg.vault_url, id).await,
        None => publish_all(client, &cfg.vault_url).await,
    }
}

async fn publish_one(client: &OdalClient, vault_url: &str, id: &str) -> Result<PublishSummary> {
    let url = format!("{vault_url}/api/v1/dpp/{id}/publish");
    let (status, body) = client
        .post_json(&url, &json!({}))
        .await
        .with_context(|| format!("Failed to publish passport {id}"))?;

    if status.is_success() {
        let resp: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let name = resp
            .get("productName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_owned();
        let qr_url = resp
            .get("qrCodeUrl")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        Ok(PublishSummary {
            published: 1,
            failed: 0,
            errors: vec![],
            items: vec![PassportPublishResult {
                id: id.to_owned(),
                name,
                success: true,
                qr_url,
                error: None,
            }],
        })
    } else {
        let err = format!(
            "Failed to publish {id} (HTTP {status}): {}",
            &body[..body.len().min(300)]
        );
        Ok(PublishSummary {
            published: 0,
            failed: 1,
            errors: vec![err.clone()],
            items: vec![PassportPublishResult {
                id: id.to_owned(),
                name: "Unknown".to_owned(),
                success: false,
                qr_url: None,
                error: Some(err),
            }],
        })
    }
}

async fn publish_all(client: &OdalClient, vault_url: &str) -> Result<PublishSummary> {
    let list_url = format!("{vault_url}/api/v1/dpps?status=draft");
    let (http_status, body) = client
        .get(&list_url)
        .await
        .context("Failed to fetch draft passports")?;

    if !http_status.is_success() {
        anyhow::bail!("Failed to list drafts (HTTP {http_status}): {body}");
    }

    let envelope: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse draft list")?;
    let drafts: Vec<serde_json::Value> = envelope
        .get("dpps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut published = 0usize;
    let mut failed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut items: Vec<PassportPublishResult> = Vec::new();

    for dpp in &drafts {
        let id = dpp.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = dpp
            .get("productName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let url = format!("{vault_url}/api/v1/dpp/{id}/publish");

        match client.post_json(&url, &json!({})).await {
            Ok((status, resp_body)) if status.is_success() => {
                let resp: serde_json::Value = serde_json::from_str(&resp_body).unwrap_or_default();
                let qr_url = resp
                    .get("qrCodeUrl")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                items.push(PassportPublishResult {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    success: true,
                    qr_url,
                    error: None,
                });
                published += 1;
            }
            Ok((status, resp_body)) => {
                let err = format!(
                    "{name}: HTTP {status} — {}",
                    &resp_body[..resp_body.len().min(200)]
                );
                errors.push(err.clone());
                items.push(PassportPublishResult {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    success: false,
                    qr_url: None,
                    error: Some(err),
                });
                failed += 1;
            }
            Err(e) => {
                let err = format!("{name}: {e}");
                errors.push(err.clone());
                items.push(PassportPublishResult {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    success: false,
                    qr_url: None,
                    error: Some(err),
                });
                failed += 1;
            }
        }
    }

    Ok(PublishSummary {
        published,
        failed,
        errors,
        items,
    })
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

pub async fn action_suspend(
    params: &SuspendParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    lifecycle_transition(&params.id, "suspend", client, cfg).await
}

pub async fn action_archive(
    params: &ArchiveParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    lifecycle_transition(&params.id, "archive", client, cfg).await
}

async fn lifecycle_transition(
    id: &str,
    action: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let url = format!("{}/api/v1/dpp/{id}/{action}", cfg.vault_url);
    let (status, body) = client.post_json(&url, &json!({})).await?;
    if !status.is_success() {
        anyhow::bail!("{action} failed (HTTP {status}): {body}");
    }
    Ok(())
}

pub async fn action_history(
    params: &HistoryParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<AuditEntry>> {
    let url = format!("{}/api/v1/dpp/{}/history", cfg.vault_url, params.id);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!("failed to fetch history (HTTP {status}): {body}");
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default();

    Ok(arr
        .iter()
        .map(|e| AuditEntry {
            timestamp: e
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            action: e
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            actor: e
                .get("actor")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
        })
        .collect())
}

// ── Export ───────────────────────────────────────────────────────────────────

pub async fn action_export(
    params: &ExportParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<ExportResult> {
    const PAGE: u32 = 100;
    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut skip = 0u32;

    loop {
        let mut url = format!("{}/api/v1/dpps?limit={PAGE}&skip={skip}", cfg.vault_url);
        if let Some(s) = &params.status_filter {
            url.push_str(&format!("&status={s}"));
        }

        let (http_status, body) = client.get(&url).await?;
        if !http_status.is_success() {
            anyhow::bail!("Export request failed (HTTP {}): {}", http_status, body);
        }

        let envelope: serde_json::Value =
            serde_json::from_str(&body).context("Failed to parse vault response as JSON")?;
        let page: Vec<serde_json::Value> = envelope
            .get("dpps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let fetched = page.len();
        all.extend(page);

        let total = envelope.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        if all.len() >= total || fetched < PAGE as usize {
            break;
        }
        skip += PAGE;
    }

    let records = serde_json::Value::Array(all);

    let data = match params.format.as_str() {
        "csv" => records_to_csv(&records)?,
        _ => serde_json::to_string_pretty(&records)?,
    };

    Ok(ExportResult { data })
}

// ── List / Browse ────────────────────────────────────────────────────────────

/// Fetch one page of passports, optionally filtered by status and free-text `q`.
/// Mirrors the vault's `GET /api/v1/dpps` (status + q + pagination + total).
pub async fn action_list(
    params: &ListParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<PassportPage> {
    let mut url = format!(
        "{}/api/v1/dpps?limit={}&skip={}",
        cfg.vault_url, params.limit, params.skip
    );
    if let Some(s) = params.status.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&status={s}"));
    }
    if let Some(q) = params.q.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&q={}", pct_encode(q)));
    }
    if let Some(f) = params.facility_id.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&facilityId={}", pct_encode(f)));
    }

    let (http_status, body) = client.get(&url).await?;
    if !http_status.is_success() {
        anyhow::bail!("List request failed (HTTP {http_status}): {body}");
    }
    let envelope: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse vault response as JSON")?;
    let total = envelope.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let rows: Vec<PassportSummary> = envelope
        .get("dpps")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(summary_from_doc).collect())
        .unwrap_or_default();

    // `total` is exact only without a text search (the vault's count ignores q).
    // So derive "more pages?" from total when we can, else from a full page.
    let searching = params.q.as_deref().is_some_and(|s| !s.is_empty());
    let shown = params.skip as u64 + rows.len() as u64;
    let has_more = if searching {
        rows.len() as u32 == params.limit
    } else {
        shown < total
    };

    Ok(PassportPage {
        rows,
        total,
        skip: params.skip,
        limit: params.limit,
        has_more,
    })
}

/// Fetch the full passport document by id (for the details view).
pub async fn action_get(id: &str, client: &OdalClient, cfg: &Config) -> Result<serde_json::Value> {
    let url = format!("{}/api/v1/dpp/{id}", cfg.vault_url);
    let (http_status, body) = client.get(&url).await?;
    if !http_status.is_success() {
        anyhow::bail!("Read request failed (HTTP {http_status}): {body}");
    }
    serde_json::from_str(&body).context("Failed to parse passport JSON")
}

/// Map a passport doc to a list-row summary. Field names match the vault's
/// camelCase JSON; missing fields degrade gracefully.
fn summary_from_doc(doc: &serde_json::Value) -> PassportSummary {
    let s = |k: &str| doc.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let product_name = {
        let n = s("productName");
        if n.is_empty() {
            "(unnamed)".to_owned()
        } else {
            n
        }
    };
    let batch = {
        let b = s("batchId");
        if b.is_empty() { None } else { Some(b) }
    };
    // "2026-06-20T14:41:01Z" → "2026-06-20 14:41"
    let updated = {
        let u = s("updatedAt");
        u.get(..16).unwrap_or(&u).replace('T', " ")
    };
    PassportSummary {
        id: s("id"),
        product_name,
        sector: s("sector"),
        status: s("status"),
        batch,
        updated,
    }
}

/// Percent-encode a query value (RFC 3986 unreserved set passes through).
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn records_to_csv(records: &serde_json::Value) -> Result<String> {
    let rows = records
        .as_array()
        .context("Expected a JSON array from the vault")?;

    if rows.is_empty() {
        return Ok(String::new());
    }

    let mut keys: Vec<String> = rows
        .iter()
        .filter_map(|r| r.as_object())
        .flat_map(|o| o.keys().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    keys.sort();

    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&keys)?;
    for row in rows {
        let obj = row.as_object();
        let record: Vec<String> = keys
            .iter()
            .map(|k| {
                let value = obj
                    .and_then(|o| o.get(k))
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                neutralize_csv_formula(value)
            })
            .collect();
        wtr.write_record(&record)?;
    }
    String::from_utf8(wtr.into_inner()?).context("CSV output is not valid UTF-8")
}

/// Defuse CSV formula injection (CWE-1236): prefix cells that begin with
/// `= + - @`, TAB or CR with a single quote so they render as literal text.
pub fn neutralize_csv_formula(value: String) -> String {
    match value.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{value}"),
        _ => value,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summary_from_doc_maps_fields() {
        let doc = json!({
            "id": "019ee576-ca26-7532-8d21-730f17e65ce8",
            "productName": "Amor Linen Blouse",
            "sector": "textile",
            "status": "active",
            "batchId": "BATCH-SS26-004",
            "updatedAt": "2026-06-20T14:41:01.688Z"
        });
        let s = summary_from_doc(&doc);
        assert_eq!(s.id, "019ee576-ca26-7532-8d21-730f17e65ce8");
        assert_eq!(s.product_name, "Amor Linen Blouse");
        assert_eq!(s.sector, "textile");
        assert_eq!(s.status, "active");
        assert_eq!(s.batch.as_deref(), Some("BATCH-SS26-004"));
        assert_eq!(s.updated, "2026-06-20 14:41");
    }

    #[test]
    fn summary_from_doc_degrades_gracefully() {
        let s = summary_from_doc(&json!({ "id": "x", "status": "draft" }));
        assert_eq!(s.product_name, "(unnamed)");
        assert!(s.batch.is_none());
        assert_eq!(s.sector, "");
    }

    #[test]
    fn pct_encode_escapes_reserved() {
        assert_eq!(pct_encode("linen blouse"), "linen%20blouse");
        assert_eq!(pct_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(pct_encode("plain-Name_1.0~"), "plain-Name_1.0~");
    }

    // --- import: sector detection ---

    #[test]
    fn detect_sector_reads_sector_column() {
        let csv = b"productName,sector,gtin\nCell A,battery,09506000134352\n";
        assert_eq!(detect_sector(csv).as_deref(), Some("battery"));
    }

    #[test]
    fn detect_sector_falls_back_to_product_category() {
        let csv = b"productName,productCategory,gtin\nTee,TEXTILE,09506000134352\n";
        assert_eq!(detect_sector(csv).as_deref(), Some("textile"));
    }

    #[test]
    fn detect_sector_handles_semicolon_delimiter() {
        let csv = b"productName;sector;gtin\nCell;battery;09506000134352\n";
        assert_eq!(detect_sector(csv).as_deref(), Some("battery"));
    }

    #[test]
    fn detect_sector_none_without_sector_column() {
        let csv = b"productName,gtin\nWidget,09506000134352\n";
        assert!(detect_sector(csv).is_none());
    }

    #[test]
    fn detect_sector_handles_quoted_comma_in_earlier_field() {
        // Regression: a quoted address with embedded commas must not shift the
        // sector column (the bug that produced "Unknown sector: '90.0'").
        let csv = b"productName,address,sector,gtin\n\
                    Cell,\"Prenzlauer Berg 12, 10405 Berlin, DE\",battery,09506000134352\n";
        assert_eq!(detect_sector(csv).as_deref(), Some("battery"));
    }

    // --- validate helpers ---

    #[test]
    fn no_issues_for_complete_textile() {
        let rec = json!({
            "productName": "T-Shirt",
            "sectorData": {
                "sector": "textile",
                "fibreComposition": [{"fibre": "cotton", "pct": 100.0}],
                "countryOfManufacturing": "DE",
                "careInstructions": "Machine wash 30°C",
                "chemicalComplianceStandard": "OEKO-TEX 100"
            }
        });
        assert!(find_issues(&rec).is_empty());
    }

    #[test]
    fn no_issues_for_complete_battery() {
        let rec = json!({
            "productName": "EV Battery",
            "sectorData": {
                "sector": "battery",
                "gtin": "09876543210123",
                "batteryChemistry": "NMC",
                "nominalVoltageV": 3.7,
                "nominalCapacityAh": 50.0,
                "expectedLifetimeCycles": 2000,
                "co2ePerUnitKg": 120.5
            }
        });
        assert!(find_issues(&rec).is_empty(), "got: {:?}", find_issues(&rec));
    }

    #[test]
    fn missing_product_name() {
        let rec = json!({ "sectorData": { "sector": "textile" } });
        assert!(find_issues(&rec).iter().any(|i| i.contains("productName")));
    }

    #[test]
    fn missing_gtin() {
        let rec = json!({ "productName": "Widget", "sectorData": { "sector": "battery" } });
        assert!(find_issues(&rec).iter().any(|i| i.contains("gtin")));
    }

    #[test]
    fn missing_sector_data() {
        let rec = json!({ "productName": "Widget" });
        assert!(find_issues(&rec).iter().any(|i| i.contains("sectorData")));
    }

    #[test]
    fn textile_missing_fibre_composition() {
        let rec = json!({
            "productName": "T-Shirt",
            "sectorData": {
                "sector": "textile",
                "countryOfManufacturing": "DE",
                "careInstructions": "wash",
                "chemicalComplianceStandard": "REACH"
            }
        });
        assert!(
            find_issues(&rec)
                .iter()
                .any(|i| i.contains("fibreComposition"))
        );
    }

    #[test]
    fn battery_missing_chemistry() {
        let rec = json!({
            "productName": "Battery",
            "sectorData": {
                "sector": "battery",
                "nominalVoltageV": 3.7,
                "nominalCapacityAh": 50.0,
                "expectedLifetimeCycles": 2000,
                "co2ePerUnitKg": 120.5
            }
        });
        assert!(
            find_issues(&rec)
                .iter()
                .any(|i| i.contains("batteryChemistry"))
        );
    }

    #[test]
    fn unknown_sector_flagged() {
        let rec = json!({ "productName": "Widget", "sectorData": { "sector": "alien" } });
        assert!(
            find_issues(&rec)
                .iter()
                .any(|i| i.contains("unknown sector"))
        );
    }

    #[test]
    fn multiple_issues_combined() {
        let rec = json!({});
        assert!(find_issues(&rec).len() >= 2);
    }

    // --- export helpers ---

    #[test]
    fn neutralizes_formula_leading_cells() {
        for s in [
            "=1+1",
            "+1",
            "-1",
            "@cmd",
            "=HYPERLINK(\"http://evil\")",
            "\tx",
            "\rx",
        ] {
            let out = neutralize_csv_formula(s.to_string());
            assert!(
                out.starts_with('\''),
                "{s:?} must be neutralized, got {out:?}"
            );
        }
    }

    #[test]
    fn leaves_safe_cells_untouched() {
        for s in ["cotton", "48.0", "GB", "Acme GmbH", ""] {
            assert_eq!(neutralize_csv_formula(s.to_string()), s);
        }
    }
}
