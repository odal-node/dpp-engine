//! Evidence: generate and store a signed dossier for a passport.

use anyhow::{Context, Result};

use super::super::types::ExportResult;
use crate::http::{OdalClient, describe_error};

pub async fn action_evidence(
    id: &str,
    client: &OdalClient,
    cfg: &crate::config::Config,
) -> Result<ExportResult> {
    // Keyed: this route is in the node's `KEYED` set and generating a dossier
    // stores one. `evidence_dossier` carries no DELETE grant (see the DELETE set
    // in ops/pg/README.md), so a dossier written twice is written twice for
    // good — the same permanence that put facilities and the Art. 24 disclosure
    // in that set. `post_empty` sent no key at all, so `--idempotency-key` was
    // accepted on the command line and then silently dropped here.
    let url = format!("{}/api/v1/dpp/{id}/evidence", cfg.vault_url);
    let (status, body) = client.post_empty_creating(&url).await?;
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
