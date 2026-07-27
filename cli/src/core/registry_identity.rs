//! Facility (ESPR Annex III) and operator-identifier (ESPR Art. 13) management
//! via the node API. Pure HTTP — no direct DB access.

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// A facility row for display.
pub struct FacilityEntry {
    pub id: String,
    pub name: String,
    pub scheme: String,
    pub value: String,
    pub country: String,
    pub is_default: bool,
}

/// An operator-identifier row for display.
pub struct OperatorIdEntry {
    pub id: String,
    pub scheme: String,
    pub value: String,
    pub is_primary: bool,
}

/// Parameters for `odal facility add`.
pub struct FacilityCreateParams {
    pub name: String,
    pub scheme: String,
    pub value: String,
    pub country: String,
    pub address: Option<String>,
    pub default: bool,
}

/// Parameters for `odal operator-id add`.
pub struct OperatorIdCreateParams {
    pub scheme: String,
    pub value: String,
    pub label: Option<String>,
    pub primary: bool,
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("-")
        .to_owned()
}

fn array_body(body: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(body)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default()
}

// ── Facilities ───────────────────────────────────────────────────────────────

pub async fn action_facility_list(client: &OdalClient, cfg: &Config) -> Result<Vec<FacilityEntry>> {
    let url = format!("{}/api/v1/facilities", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        bail!(
            "failed to list facilities: {}",
            describe_error(status, &body)
        );
    }
    Ok(array_body(&body)
        .iter()
        .map(|f| FacilityEntry {
            id: str_field(f, "id"),
            name: str_field(f, "name"),
            scheme: str_field(f, "identifierScheme"),
            value: str_field(f, "identifierValue"),
            country: str_field(f, "country"),
            is_default: f
                .get("isDefault")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
        .collect())
}

pub async fn action_facility_add(
    params: &FacilityCreateParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<FacilityEntry> {
    let url = format!("{}/api/v1/facilities", cfg.vault_url);
    let mut payload = json!({
        "name": params.name,
        "identifierScheme": params.scheme,
        "identifierValue": params.value,
        "country": params.country,
        "isDefault": params.default,
    });
    if let Some(addr) = &params.address {
        payload["address"] = json!(addr);
    }
    let (status, body) = client.post_json(&url, &payload).await?;
    if !status.is_success() {
        bail!(
            "facility creation failed: {}",
            describe_error(status, &body)
        );
    }
    let f: serde_json::Value = serde_json::from_str(&body).context("could not parse response")?;
    Ok(FacilityEntry {
        id: str_field(&f, "id"),
        name: str_field(&f, "name"),
        scheme: str_field(&f, "identifierScheme"),
        value: str_field(&f, "identifierValue"),
        country: str_field(&f, "country"),
        is_default: f
            .get("isDefault")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

pub async fn action_facility_set_default(
    id: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let url = format!("{}/api/v1/facilities/{id}/default", cfg.vault_url);
    let (status, body) = client.post_json(&url, &json!({})).await?;
    if !status.is_success() {
        bail!("set-default failed: {}", describe_error(status, &body));
    }
    Ok(())
}

pub async fn action_facility_remove(id: &str, client: &OdalClient, cfg: &Config) -> Result<()> {
    let url = format!("{}/api/v1/facilities/{id}", cfg.vault_url);
    let (status, body) = client.delete(&url).await?;
    if !status.is_success() {
        bail!("remove failed: {}", describe_error(status, &body));
    }
    Ok(())
}

// ── Operator identifiers ─────────────────────────────────────────────────────

pub async fn action_operator_id_list(
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<OperatorIdEntry>> {
    let url = format!("{}/api/v1/operator-identifiers", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        bail!(
            "failed to list operator identifiers: {}",
            describe_error(status, &body)
        );
    }
    Ok(array_body(&body)
        .iter()
        .map(|o| OperatorIdEntry {
            id: str_field(o, "id"),
            scheme: str_field(o, "scheme"),
            value: str_field(o, "value"),
            is_primary: o
                .get("isPrimary")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
        .collect())
}

pub async fn action_operator_id_add(
    params: &OperatorIdCreateParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<OperatorIdEntry> {
    let url = format!("{}/api/v1/operator-identifiers", cfg.vault_url);
    let mut payload = json!({
        "scheme": params.scheme,
        "value": params.value,
        "isPrimary": params.primary,
    });
    if let Some(label) = &params.label {
        payload["label"] = json!(label);
    }
    let (status, body) = client.post_json(&url, &payload).await?;
    if !status.is_success() {
        bail!(
            "operator-identifier creation failed: {}",
            describe_error(status, &body)
        );
    }
    let o: serde_json::Value = serde_json::from_str(&body).context("could not parse response")?;
    Ok(OperatorIdEntry {
        id: str_field(&o, "id"),
        scheme: str_field(&o, "scheme"),
        value: str_field(&o, "value"),
        is_primary: o
            .get("isPrimary")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

pub async fn action_operator_id_set_primary(
    id: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let url = format!("{}/api/v1/operator-identifiers/{id}/primary", cfg.vault_url);
    let (status, body) = client.post_json(&url, &json!({})).await?;
    if !status.is_success() {
        bail!("set-primary failed: {}", describe_error(status, &body));
    }
    Ok(())
}

pub async fn action_operator_id_remove(id: &str, client: &OdalClient, cfg: &Config) -> Result<()> {
    let url = format!("{}/api/v1/operator-identifiers/{id}", cfg.vault_url);
    let (status, body) = client.delete(&url).await?;
    if !status.is_success() {
        bail!("remove failed: {}", describe_error(status, &body));
    }
    Ok(())
}
