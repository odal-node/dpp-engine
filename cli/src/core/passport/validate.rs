//! Validate: fetch drafts and flag rows missing required product group-data fields.

use anyhow::{Context, Result};
use dpp_domain::product_group::ProductGroupData;

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
            product_group_data_valid: false,
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
        product_group_data_valid: v
            .get("productGroupDataValid")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        detail: v.get("detail").and_then(|d| d.as_str()).map(str::to_owned),
    })
}

pub fn find_issues(rec: &serde_json::Value) -> Vec<String> {
    let mut issues = Vec::new();

    for field in &["productName", "productGroupData"] {
        if rec.get(field).is_none() || rec[field].is_null() {
            issues.push(format!("missing {field}"));
        }
    }

    if let Some(data) = rec.get("productGroupData").filter(|d| !d.is_null()) {
        issues.extend(product_group_data_issues(data));
    }

    issues
}

/// What a draft's `productGroupData` fails, asked of the function the node asks.
///
/// This check kept its own list of the fields each product group requires, and
/// the list was wrong the day it was written: it demanded `co2ePerUnitKg` of a
/// battery, which the node's rule treats as optional, so `validate` exited 1 on
/// a draft the same node publishes. A second copy of a rule agrees with the first
/// until somebody edits one of them. Core's `validate_product_group_data` is the
/// first step of the node's publish gate, so the verdict comes from there and
/// there is nothing here to edit when a product group's requirements change.
fn product_group_data_issues(data: &serde_json::Value) -> Vec<String> {
    // The node stored this through the same type, so a draft it holds always
    // reads back. A body that does not is reported, not skipped.
    let parsed: ProductGroupData = match serde_json::from_value(data.clone()) {
        Ok(parsed) => parsed,
        Err(e) => return vec![format!("productGroupData: {e}")],
    };
    match dpp_domain::validate_product_group_data(&parsed) {
        Ok(()) => Vec::new(),
        Err(rejected) => rejected
            .errors
            .into_iter()
            .map(|e| format!("productGroupData{}: {}", e.field, e.message))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The reference passports the demo loads, which the node publishes.
    fn reference_battery() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../ops/demo/samples/battery-full.json"
        ))
        .expect("the reference battery is JSON")
    }

    fn reference_textile() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../ops/demo/samples/textile-full.json"
        ))
        .expect("the reference textile is JSON")
    }

    fn without(mut rec: serde_json::Value, field: &str) -> serde_json::Value {
        rec["productGroupData"]
            .as_object_mut()
            .expect("group data is an object")
            .remove(field);
        rec
    }

    #[test]
    fn no_issues_for_a_complete_textile() {
        let issues = find_issues(&reference_textile());
        assert!(issues.is_empty(), "got: {issues:?}");
    }

    #[test]
    fn no_issues_for_a_complete_battery() {
        let issues = find_issues(&reference_battery());
        assert!(issues.is_empty(), "got: {issues:?}");
    }

    #[test]
    fn missing_product_name() {
        let rec = json!({ "productGroupData": { "productGroup": "textile" } });
        assert!(find_issues(&rec).iter().any(|i| i.contains("productName")));
    }

    #[test]
    fn missing_product_group_data() {
        let rec = json!({ "productName": "Widget" });
        assert!(
            find_issues(&rec)
                .iter()
                .any(|i| i.contains("productGroupData"))
        );
    }

    #[test]
    fn a_battery_missing_its_product_identifier_is_flagged_by_name() {
        let issues = find_issues(&without(reference_battery(), "productIdentifier"));
        assert!(
            issues.iter().any(|i| i.contains("productIdentifier")),
            "got: {issues:?}"
        );
    }

    #[test]
    fn a_textile_missing_its_product_identifier_is_flagged_by_name() {
        let issues = find_issues(&without(reference_textile(), "productIdentifier"));
        assert!(
            issues.iter().any(|i| i.contains("productIdentifier")),
            "got: {issues:?}"
        );
    }

    #[test]
    fn a_textile_missing_its_fibre_composition_is_flagged_by_name() {
        let issues = find_issues(&without(reference_textile(), "fibreComposition"));
        assert!(
            issues.iter().any(|i| i.contains("fibreComposition")),
            "got: {issues:?}"
        );
    }

    /// The node's battery rules treat `co2ePerUnitKg` as optional, and a draft
    /// without it publishes. The list this check kept of its own required a field
    /// the node does not, so `odal passport validate` exited 1 on a passport the
    /// same node would publish.
    #[test]
    fn a_battery_draft_without_co2e_per_unit_kg_is_not_flagged() {
        let issues = find_issues(&without(reference_battery(), "co2ePerUnitKg"));

        assert!(issues.is_empty(), "got: {issues:?}");
    }

    /// What the node requires is still reported, by name — from its rule.
    #[test]
    fn a_battery_draft_missing_a_required_field_is_flagged_by_name() {
        let issues = find_issues(&without(reference_battery(), "batteryChemistry"));

        assert!(
            issues.iter().any(|i| i.contains("batteryChemistry")),
            "got: {issues:?}"
        );
    }

    /// A value the node refuses is refused here too. A list of field names can
    /// say a field is present and cannot say it is wrong; the node's rule can.
    #[test]
    fn a_value_the_nodes_rule_refuses_is_flagged_though_the_field_is_present() {
        let mut rec = reference_textile();
        rec["productGroupData"]["fibreComposition"] =
            json!([{ "fibre": "organic cotton", "pct": 55.0 }]);

        let issues = find_issues(&rec);

        assert!(
            issues.iter().any(|i| i.contains("fibreComposition")),
            "got: {issues:?}"
        );
    }

    #[test]
    fn an_unknown_product_group_is_flagged() {
        let rec =
            json!({ "productName": "Widget", "productGroupData": { "productGroup": "alien" } });
        let issues = find_issues(&rec);
        assert!(!issues.is_empty(), "an unknown product group passed");
    }

    #[test]
    fn multiple_issues_combined() {
        let rec = json!({});
        assert!(find_issues(&rec).len() >= 2);
    }
}
