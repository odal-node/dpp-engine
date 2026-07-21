//! Operator onboarding actions: bootstrap, node state, and API-key/operator management.

use anyhow::{Context, Result, bail};
use serde_json::json;

use super::types::{
    BootstrapParams, BootstrapResult, KeyCreateParams, KeyCreateResult, KeyEntry, KeyRevokeParams,
    NodeState, OperatorUpdateParams,
};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Read the node's setup state — whether it has been claimed (≥1 API key) and
/// whether the operator identity is complete. Used to keep bootstrap idempotent.
/// Works with either an API-key client or a local-admin client.
pub async fn action_node_state(client: &OdalClient, cfg: &Config) -> Result<NodeState> {
    let url = format!("{}/api/v1/node/state", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        bail!(
            "failed to read node state: {}",
            describe_error(status, &body)
        );
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).context("could not parse node state response")?;
    Ok(NodeState {
        bootstrapped: v
            .get("bootstrapped")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        operator_complete: v
            .get("operatorComplete")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
    })
}

/// Optionally patch operator identity (only the fields provided) and mint the
/// first API key. The caller is responsible for resolving admin credentials,
/// gathering fields, and guarding against re-bootstrapping a claimed node.
/// Returns the plaintext API key — the caller persists it to config.
pub async fn action_bootstrap(
    params: &BootstrapParams,
    admin_client: &OdalClient,
    cfg: &Config,
) -> Result<BootstrapResult> {
    let mut patch = json!({});
    if let Some(v) = &params.legal_name {
        patch["legalName"] = json!(v);
    }
    if let Some(v) = &params.country {
        patch["country"] = json!(v);
    }
    if let Some(v) = &params.address {
        patch["address"] = json!(v);
    }
    if let Some(v) = &params.contact_email {
        patch["contactEmail"] = json!(v);
    }
    if let Some(d) = &params.did_web_url {
        patch["didWebUrl"] = json!(d);
    }

    // Only PATCH the operator if at least one identity field was supplied —
    // bootstrap's required job is just minting the first key.
    if patch.as_object().is_some_and(|o| !o.is_empty()) {
        let op_url = format!("{}/api/v1/operator", cfg.vault_url);
        let (status, body) = admin_client.patch_json(&op_url, &patch).await?;
        if !status.is_success() {
            bail!(
                "operator setup failed against {op_url}: {}",
                describe_error(status, &body)
            );
        }
    }

    let key_url = format!("{}/api/v1/api-keys", cfg.vault_url);
    let (status, body) = admin_client
        .post_json(&key_url, &json!({ "name": "cli-bootstrap" }))
        .await?;
    if !status.is_success() {
        bail!("API key creation failed: {}", describe_error(status, &body));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&body).context("could not parse api-key response")?;
    let secret = parsed
        .get("secret")
        .and_then(|s| s.as_str())
        .context("api-key response did not include a plaintext secret")?
        .to_owned();

    Ok(BootstrapResult { api_key: secret })
}

/// Fetch the current operator configuration from the vault.
pub async fn action_operator_show(client: &OdalClient, cfg: &Config) -> Result<serde_json::Value> {
    let url = format!("{}/api/v1/operator", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        bail!(
            "failed to fetch operator config: {}",
            describe_error(status, &body)
        );
    }
    Ok(serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body)))
}

/// Merge-patch operator fields. Returns `Ok(())` on success.
/// The caller validates that at least one field is set before calling.
pub async fn action_operator_set(
    params: &OperatorUpdateParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let mut patch = json!({});
    if let Some(v) = &params.legal_name {
        patch["legalName"] = json!(v);
    }
    if let Some(v) = &params.trade_name {
        patch["tradeName"] = json!(v);
    }
    if let Some(v) = &params.address {
        patch["address"] = json!(v);
    }
    if let Some(v) = &params.country {
        patch["country"] = json!(v);
    }
    if let Some(v) = &params.contact_email {
        patch["contactEmail"] = json!(v);
    }
    if let Some(v) = &params.did_web_url {
        patch["didWebUrl"] = json!(v);
    }
    if let Some(v) = params.retention_policy_days {
        patch["retentionPolicyDays"] = json!(v);
    }

    let url = format!("{}/api/v1/operator", cfg.vault_url);
    let (status, body) = client.patch_json(&url, &patch).await?;
    if !status.is_success() {
        bail!("operator update failed: {}", describe_error(status, &body));
    }
    Ok(())
}

/// Create a new API key and return the plaintext secret (shown once).
pub async fn action_key_create(
    params: &KeyCreateParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<KeyCreateResult> {
    let url = format!("{}/api/v1/api-keys", cfg.vault_url);
    let (status, body) = client
        .post_json(&url, &json!({ "name": params.name }))
        .await?;
    if !status.is_success() {
        bail!("key creation failed: {}", describe_error(status, &body));
    }
    let parsed: serde_json::Value =
        serde_json::from_str(&body).context("could not parse response")?;
    let secret = parsed
        .get("secret")
        .and_then(|s| s.as_str())
        .context("response did not include a plaintext secret")?
        .to_owned();
    Ok(KeyCreateResult {
        secret,
        name: params.name.clone(),
    })
}

/// List API keys (prefix only; secrets are never returned by the vault).
pub async fn action_key_list(client: &OdalClient, cfg: &Config) -> Result<Vec<KeyEntry>> {
    let url = format!("{}/api/v1/api-keys", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        bail!("failed to list keys: {}", describe_error(status, &body));
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default();

    Ok(arr
        .iter()
        .map(|k| KeyEntry {
            id: k
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            name: k
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            prefix: k
                .get("keyPrefix")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            is_active: k.get("isActive").and_then(|v| v.as_bool()).unwrap_or(false),
        })
        .collect())
}

/// Revoke an API key by id.
pub async fn action_key_revoke(
    params: &KeyRevokeParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let url = format!("{}/api/v1/api-keys/{}", cfg.vault_url, params.id);
    let (status, body) = client.delete(&url).await?;
    if !status.is_success() {
        bail!("revoke failed: {}", describe_error(status, &body));
    }
    Ok(())
}
