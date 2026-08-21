//! Schema action: report the versions that decide which rules a node applies.

use anyhow::Result;

use super::types::SchemaCheckResult;
use crate::{config::Config, http::OdalClient};

/// Report the node's build version, the `dpp-core` version it applies, and its
/// active ruleset.
///
/// This used to answer "is an update available" by reading a `schema_version`
/// field from `/health` and comparing it against an upstream release feed.
/// Neither half could work: the node stopped emitting that field, so the local
/// version was always `unknown`, and the upstream host does not resolve, so the
/// comparison always reported the caller as offline. Both lines were incapable
/// of being true on any node, on any network.
///
/// It now reports what the node actually serves. `coreVersion` is the value
/// that matters — it decides which regulatory schemas and rules the node
/// applies. The ruleset comes from the authenticated node state and is omitted
/// rather than guessed when the caller has no credential, the same way
/// `odal status` treats the trust posture.
pub async fn action_schema_check(client: &OdalClient, cfg: &Config) -> Result<SchemaCheckResult> {
    let (node_version, core_version) = match client
        .get_public(&format!("{}/health", cfg.vault_url))
        .await
    {
        Ok((status, body)) if status.is_success() => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let read = |key: &str| v.get(key).and_then(|s| s.as_str()).map(str::to_owned);
            (read("version"), read("coreVersion"))
        }
        _ => (None, None),
    };

    // Authenticated, so absent for a caller without a key. `status` makes the
    // same trade: report what was readable rather than fail over what was not.
    let ruleset_version = crate::core::onboarding::action_node_state(client, cfg)
        .await
        .ok()
        .and_then(|s| s.ruleset_version);

    Ok(SchemaCheckResult {
        node_version,
        core_version,
        ruleset_version,
    })
}
