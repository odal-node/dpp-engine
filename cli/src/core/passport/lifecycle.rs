//! Lifecycle: suspend, archive, and audit history.

use anyhow::Result;
use serde_json::json;

use super::super::types::{ArchiveParams, AuditEntry, HistoryParams, SuspendParams};
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

pub async fn action_history(
    params: &HistoryParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<AuditEntry>> {
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
