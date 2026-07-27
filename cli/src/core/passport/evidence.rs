//! Evidence: generate and store a signed dossier for a passport.

use anyhow::{Context, Result};

use super::super::types::ExportResult;
use crate::http::{OdalClient, describe_error};

pub async fn action_evidence(
    id: &str,
    client: &OdalClient,
    cfg: &crate::config::Config,
) -> Result<ExportResult> {
    let url = format!("{}/api/v1/dpp/{id}/evidence", cfg.vault_url);
    let (status, body) = client.post_empty(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "Evidence generation failed: {}",
            describe_error(status, &body)
        );
    }
    let record: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse vault response as JSON")?;
    Ok(ExportResult {
        data: serde_json::to_string_pretty(&record)?,
    })
}
