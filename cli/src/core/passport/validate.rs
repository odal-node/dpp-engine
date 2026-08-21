//! Validate: fetch drafts and flag rows missing required sector-data fields.

use anyhow::{Context, Result};

use super::super::types::{DryRunVerdict, ValidationRecord, ValidationReport};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

pub async fn action_validate(client: &OdalClient, cfg: &Config) -> Result<ValidationReport> {
    let url = format!("{}/api/v1/dpps?status=draft", cfg.vault_url);
    let (http_status, body) = client.get(&url).await?;
    if !http_status.is_success() {
        anyhow::bail!(
            "Failed to fetch draft DPPs: {}",
            describe_error(http_status, &body)
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

/// `POST /api/v1/dpp/validate` — would this body be accepted, without creating
/// anything.
///
/// A rejection comes back as **the identical response `create` would have
/// sent**, so a non-2xx here is the verdict rather than a transport failure.
/// The exception is 401/403: the dry run is write-scoped, because it runs
/// schema validation on caller-supplied input, so those mean the caller was not
/// entitled to ask — which says nothing about the file and must not be reported
/// as though it did.
pub async fn action_validate_body(
    path: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<DryRunVerdict> {
    let bytes = std::fs::read(path).with_context(|| format!("Cannot read file: {path}"))?;
    let url = format!("{}/api/v1/dpp/validate", cfg.vault_url);
    // Sent verbatim, so the node judges exactly what is on disk.
    let (http_status, body) = client.post_bytes(&url, bytes).await?;

    if matches!(http_status.as_u16(), 401 | 403) {
        anyhow::bail!("cannot validate: {}", describe_error(http_status, &body));
    }
    if !http_status.is_success() {
        return Ok(DryRunVerdict {
            create_valid: false,
            publish_valid: false,
            detail: Some(describe_error(http_status, &body)),
        });
    }

    let v: serde_json::Value =
        serde_json::from_str(&body).context("could not parse the validation verdict")?;
    Ok(DryRunVerdict {
        create_valid: v
            .get("createValid")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        publish_valid: v
            .get("publishValid")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        detail: v.get("detail").and_then(|d| d.as_str()).map(str::to_owned),
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
                    "gtin",
                    "fibreComposition",
                    "countryOfOrigin",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_issues_for_complete_textile() {
        let rec = json!({
            "productName": "T-Shirt",
            "sectorData": {
                "sector": "textile",
                "gtin": "09506000134352",
                "fibreComposition": [{"fibre": "cotton", "pct": 100.0}],
                "countryOfOrigin": "DE",
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
    fn textile_missing_gtin() {
        let rec = json!({
            "productName": "T-Shirt",
            "sectorData": {
                "sector": "textile",
                "fibreComposition": [{"fibre": "cotton", "pct": 100.0}],
                "countryOfOrigin": "DE",
                "careInstructions": "wash",
                "chemicalComplianceStandard": "REACH"
            }
        });
        assert!(find_issues(&rec).iter().any(|i| i.contains("gtin")));
    }

    #[test]
    fn textile_missing_fibre_composition() {
        let rec = json!({
            "productName": "T-Shirt",
            "sectorData": {
                "sector": "textile",
                "countryOfOrigin": "DE",
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
}
