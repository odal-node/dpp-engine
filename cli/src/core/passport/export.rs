//! Export: page through passports and render as JSON or CSV.

use anyhow::{Context, Result};

use super::super::types::{ExportParams, ExportResult};
use crate::{config::Config, http::OdalClient};

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

#[cfg(test)]
mod tests {
    use super::*;

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
