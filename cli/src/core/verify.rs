//! Verify: check a stored dossier (by id) or an uploaded dossier file
//! against the node.

use anyhow::{Context, Result, bail};
use dpp_types::evidence::VerificationReport;

use crate::{config::Config, http::OdalClient};

/// `target` is either a path to a dossier JSON file on disk, or a stored
/// dossier's id — whichever resolves is used.
pub async fn action_verify(
    target: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<VerificationReport> {
    let (status, body) = if std::path::Path::new(target).is_file() {
        let bytes = std::fs::read(target).with_context(|| format!("Cannot read file: {target}"))?;
        client
            .post_bytes(&format!("{}/api/v1/evidence/verify", cfg.vault_url), bytes)
            .await?
    } else {
        client
            .post_empty(&format!(
                "{}/api/v1/evidence/{target}/verify",
                cfg.vault_url
            ))
            .await?
    };

    if !status.is_success() {
        bail!("Verification failed (HTTP {status}): {body}");
    }
    serde_json::from_str(&body).context("Failed to parse verification report as JSON")
}
