//! Schema action: compares the local and node schema versions.

use anyhow::Result;

use super::types::SchemaCheckResult;
use crate::{config::Config, http::OdalClient};

pub async fn action_schema_check(client: &OdalClient, cfg: &Config) -> Result<SchemaCheckResult> {
    let local_version = match client
        .get_public(&format!("{}/health", cfg.vault_url))
        .await
    {
        Ok((_, body)) => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            v.get("schema_version")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_owned()
        }
        Err(_) => "unknown".to_owned(),
    };

    match client
        .get_public("https://updates.odal-node.io/api/v1/compliance/latest-version")
        .await
    {
        Ok((status, body)) if status.is_success() => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let latest = v
                .get("version")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_owned();
            let update_available =
                local_version != "unknown" && latest != "unknown" && local_version != latest;
            Ok(SchemaCheckResult {
                local_version,
                latest_version: Some(latest),
                update_available,
                offline: false,
                warning: None,
            })
        }
        Ok((status, _)) => Ok(SchemaCheckResult {
            local_version,
            latest_version: None,
            update_available: false,
            offline: false,
            warning: Some(format!("upstream returned HTTP {status}")),
        }),
        Err(_) => Ok(SchemaCheckResult {
            local_version,
            latest_version: None,
            update_available: false,
            offline: true,
            warning: None,
        }),
    }
}
