//! Scan telemetry: aggregate resolution counts, per passport and operator-wide.
//!
//! Privacy-safe by construction — the node stores only counts per passport per
//! day, nothing about who scanned. These actions just read the two endpoints and
//! return the parsed JSON for the renderer.

use anyhow::Result;
use serde_json::Value;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// `GET /api/v1/dpp/{id}/stats?days=N` — one passport's scan + QR-render counts.
pub async fn action_passport_stats(
    id: &str,
    days: u32,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let url = format!("{}/api/v1/dpp/{id}/stats?days={days}", cfg.vault_url);
    fetch_stats(&url, client).await
}

/// `GET /api/v1/stats?days=N` — the operator-wide rollup.
pub async fn action_operator_stats(days: u32, client: &OdalClient, cfg: &Config) -> Result<Value> {
    let url = format!("{}/api/v1/stats?days={days}", cfg.vault_url);
    fetch_stats(&url, client).await
}

async fn fetch_stats(url: &str, client: &OdalClient) -> Result<Value> {
    let (status, body) = client.get(url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to fetch scan telemetry: {}",
            describe_error(status, &body)
        );
    }
    Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
}
