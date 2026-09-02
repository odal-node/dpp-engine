//! Compliance-ruleset channel administration via the node API — tell the node
//! to re-read its signed channel now. Pure HTTP; the node owns fetching,
//! verification and the swap, so the CLI never handles the publisher key.

use anyhow::{Result, bail};

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// What the node reports after re-reading its channel.
pub struct RulesetReload {
    pub ruleset_version: String,
    pub changed: bool,
}

/// Ask the node to re-read its signed ruleset channel and hot-swap anything
/// that verifies and is current.
///
/// A channel that has not changed is a success with `changed: false`, not an
/// error — the caller decides how to word it.
pub async fn action_ruleset_reload(client: &OdalClient, cfg: &Config) -> Result<RulesetReload> {
    let url = format!("{}/api/v1/ruleset/reload", cfg.vault_url);
    let (status, body) = client.post_empty(&url).await?;
    if !status.is_success() {
        bail!("ruleset reload failed: {}", describe_error(status, &body));
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    Ok(RulesetReload {
        ruleset_version: v
            .get("rulesetVersion")
            .and_then(|s| s.as_str())
            .unwrap_or("?")
            .to_owned(),
        changed: v.get("changed").and_then(serde_json::Value::as_bool) == Some(true),
    })
}
