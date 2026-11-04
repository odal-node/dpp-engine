//! EU registry sync status — the operator-wide rollup, or one passport's record.

use anyhow::{Context, Result, bail};
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

/// `POST /api/v1/dpp/{id}/registry/abandon` — give up on a registration the
/// registry never accepted.
///
/// Every non-success is an error, including the `409` that means the registry
/// holds a submission for the passport and the `422` that means it could not be
/// shown to hold none. The operator asked for a write and it did not happen, and
/// the node's `detail` says which: the registry's own answer is the part worth
/// reading.
///
/// The node decides, not the CLI: it reads the registry's task list at the moment
/// of the request, so there is nothing here to pre-check that would not be stale
/// by the time it was acted on.
///
/// Requires an admin credential.
pub async fn action_registry_abandon(
    id: &str,
    reason: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let (status, body) = client
        .post_json(
            &format!("{}/api/v1/dpp/{id}/registry/abandon", cfg.vault_url),
            &serde_json::json!({ "reason": reason }),
        )
        .await?;
    if !status.is_success() {
        bail!("Not abandoned: {}", describe_error(status, &body));
    }
    serde_json::from_str(&body).context("registry abandon response was not JSON")
}

/// `POST /api/v1/dpp/{id}/registry/handle` — record the registry's correlation
/// identifier for a submission the node lost the handle of.
///
/// Every non-success is an error, including the `422` that means the registry
/// did not show the handle to be this passport's. The operator asked for a
/// write and it did not happen, and the node's `detail` says which of the
/// several reasons it was: the submission reports other passports, it is still
/// being checked, nothing is listed under that identifier, or the node's
/// registry connection cannot read a submission's contents.
///
/// The node decides, not the CLI: it reads the submission back from the registry
/// at the moment of the request, so there is nothing here to pre-check that would
/// not be stale by the time it was acted on.
///
/// Requires an admin credential.
pub async fn action_registry_handle(
    id: &str,
    correlation_id: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let (status, body) = client
        .post_json(
            &format!("{}/api/v1/dpp/{id}/registry/handle", cfg.vault_url),
            &serde_json::json!({ "correlationId": correlation_id }),
        )
        .await?;
    if !status.is_success() {
        bail!("Handle not recorded: {}", describe_error(status, &body));
    }
    serde_json::from_str(&body).context("registry handle response was not JSON")
}
