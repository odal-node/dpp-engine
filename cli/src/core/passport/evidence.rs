//! Evidence: fetch a single passport's signed offline-verifiable dossier (N02).

use anyhow::{Context, Result};

use super::super::types::ExportResult;
use crate::http::OdalClient;

pub async fn action_evidence(
    id: &str,
    client: &OdalClient,
    cfg: &crate::config::Config,
) -> Result<ExportResult> {
    let url = format!("{}/api/v1/dpp/{id}/evidence", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!("Evidence export failed (HTTP {status}): {body}");
    }
    let dossier: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse vault response as JSON")?;
    Ok(ExportResult {
        data: serde_json::to_string_pretty(&dossier)?,
    })
}
