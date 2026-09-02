//! EU registry sync status — the operator-wide rollup, or one passport's record.

use anyhow::Result;
use serde_json::Value;

use super::types::{ProvenanceEntry, RegistryStatusReport};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

pub async fn action_registry_status(
    id: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<RegistryStatusReport> {
    let url = match id {
        Some(id) => format!("{}/api/v1/dpp/{id}/registry", cfg.vault_url),
        None => format!("{}/api/v1/registry", cfg.vault_url),
    };
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to read registry status: {}",
            describe_error(status, &body)
        );
    }

    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);

    // Both views wrap the interesting part: one passport's state sits under
    // `registration`, and the rollup's counts under `registrations`. A node
    // with no registry queues omits them entirely rather than reporting zeros,
    // which would read as "everything is registered" — so absent stays absent
    // here too.
    let registration = v.get("registration");
    let text = |k: &str| {
        registration
            .and_then(|r| r.get(k))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    let totals = v
        .get("registrations")
        .and_then(Value::as_object)
        .map(|o| {
            let mut rows: Vec<(String, u64)> = o
                .iter()
                .filter_map(|(k, n)| n.as_u64().map(|n| (k.clone(), n)))
                .collect();
            rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            rows
        })
        .unwrap_or_default();

    Ok(RegistryStatusReport {
        passport_id: id.map(str::to_owned),
        status: text("status"),
        registry_id: text("registryId"),
        message: text("message"),
        configured: v.get("configured").and_then(Value::as_bool),
        stalled: registration
            .and_then(|r| r.get("stalled"))
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        attempts: registration
            .and_then(|r| r.get("attempts"))
            .and_then(Value::as_u64),
        totals,
    })
}

/// The append-only trail behind a facility or an operator identifier.
///
/// Both are retire-not-delete records, so "what happened to this identifier"
/// is answerable and worth a verb: the row itself only ever shows the current
/// state.
pub async fn action_provenance(
    collection: &str,
    id: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<ProvenanceEntry>> {
    let url = format!("{}/api/v1/{collection}/{id}/audit", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to read the provenance trail: {}",
            describe_error(status, &body)
        );
    }

    let rows: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
    Ok(rows
        .iter()
        .map(|e| {
            let s = |k: &str| {
                e.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            // Each row carries the whole record as it stood, which is the
            // point of an append-only trail — but a whole record per line is
            // unreadable. Show the identifier, which is what an operator is
            // actually tracking through the retire/restore history.
            let snapshot = e.get("snapshot");
            let from_snapshot = |k: &str| {
                snapshot
                    .and_then(|o| o.get(k))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            ProvenanceEntry {
                timestamp: s("ts"),
                action: s("action"),
                actor: s("actor"),
                detail: from_snapshot("identifierValue").or_else(|| from_snapshot("value")),
            }
        })
        .collect())
}
