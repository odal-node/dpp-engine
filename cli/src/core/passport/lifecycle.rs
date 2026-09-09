//! Lifecycle: suspend, archive, and audit history.

use anyhow::Result;
use serde_json::json;

use super::super::types::{ArchiveParams, HistoryParams, PassportAuditEntry, SuspendParams};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

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
        anyhow::bail!("{action} failed: {}", describe_error(status, &body));
    }
    Ok(())
}

/// The outcome of a supersession, whichever route produced it.
///
/// Both routes retire one passport in favour of another and the pair is what an
/// operator needs back; they differ in which of the two they return, so this
/// names both rather than "the passport".
pub struct Supersession {
    /// The passport now in the terminal `superseded` state.
    pub retired: String,
    /// The passport that takes over.
    pub successor: String,
}

/// Correct a published passport by issuing a successor.
///
/// Returns `201` with the **successor**, which is a different record from the
/// one addressed — the opposite of `supersede`, which returns the retired
/// predecessor. Both are reported here so the caller does not have to know
/// which way round a given route answers.
///
/// The patch is passed through as the caller supplied it. Only the patchable
/// content fields take effect and the node ignores the rest rather than
/// refusing them, so filtering here would add a second opinion about what is
/// amendable and could only ever disagree with the node's.
pub async fn action_amend(
    id: &str,
    patch: serde_json::Value,
    reason: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Supersession> {
    let url = format!("{}/api/v1/dpp/{id}/amend", cfg.vault_url);
    let mut body = json!({ "patch": patch });
    if let Some(r) = reason {
        body["reason"] = json!(r);
    }
    let (status, response) = client.post_json(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!("amend failed: {}", describe_error(status, &response));
    }
    let successor: serde_json::Value = serde_json::from_str(&response).unwrap_or_default();
    Ok(Supersession {
        retired: id.to_owned(),
        successor: successor
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(not reported)")
            .to_owned(),
    })
}

/// Retire a published passport in favour of one that already exists.
///
/// The link is **checked** here, not written: the successor must already carry
/// `supersedesId` back to the passport being retired, set when it was created.
/// A successor that does not is refused with `422`, and the message says so.
pub async fn action_supersede(
    id: &str,
    superseded_by: &str,
    reason: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Supersession> {
    let url = format!("{}/api/v1/dpp/{id}/supersede", cfg.vault_url);
    let mut body = json!({ "supersededBy": superseded_by });
    if let Some(r) = reason {
        body["reason"] = json!(r);
    }
    let (status, response) = client.post_json(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!("supersede failed: {}", describe_error(status, &response));
    }
    Ok(Supersession {
        retired: id.to_owned(),
        successor: superseded_by.to_owned(),
    })
}

pub async fn action_history(
    params: &HistoryParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<PassportAuditEntry>> {
    let url = format!("{}/api/v1/dpp/{}/history", cfg.vault_url, params.id);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!("failed to fetch history: {}", describe_error(status, &body));
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default();

    Ok(arr
        .iter()
        .map(|e| PassportAuditEntry {
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
