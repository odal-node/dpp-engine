//! Import: CSV/XLSX via the integrator's bulk endpoint, JSON record-by-record.

use anyhow::{Context, Result};
use reqwest::StatusCode;

use super::super::types::{ImportParams, ImportSummary, ProgressEvent};
use crate::{config::Config, http::OdalClient};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
