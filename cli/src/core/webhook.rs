//! Signed outbound webhook management via the node API. Pure HTTP — no direct
//! DB access.

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// A webhook subscription row for display (secret redacted).
pub struct WebhookEntry {
    pub id: String,
    pub url: String,
    /// Event filter, joined for display (`*` = all).
    pub events: String,
    pub active: bool,
}

/// A newly created subscription plus its one-time signing secret.
pub struct CreatedWebhook {
    pub entry: WebhookEntry,
    pub secret: String,
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("-")
        .to_owned()
}

fn array_body(body: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(body)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn entry_from(v: &serde_json::Value) -> WebhookEntry {
    let events = v
        .get("events")
        .and_then(|e| e.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    WebhookEntry {
        id: str_field(v, "id"),
        url: str_field(v, "url"),
        events,
        active: v.get("active").and_then(|b| b.as_bool()).unwrap_or(false),
    }
}

pub async fn action_webhook_list(client: &OdalClient, cfg: &Config) -> Result<Vec<WebhookEntry>> {
    let url = format!("{}/api/v1/webhooks", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        bail!("failed to list webhooks: {}", describe_error(status, &body));
    }
    Ok(array_body(&body).iter().map(entry_from).collect())
}

pub async fn action_webhook_add(
    target_url: &str,
    events: Vec<String>,
    description: Option<String>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<CreatedWebhook> {
    let url = format!("{}/api/v1/webhooks", cfg.vault_url);
    let events = if events.is_empty() {
        vec!["*".to_owned()]
    } else {
        events
    };
    let mut payload = json!({ "url": target_url, "events": events });
    if let Some(d) = &description {
        payload["description"] = json!(d);
    }
    let (status, body) = client.post_json(&url, &payload).await?;
    if !status.is_success() {
        bail!("webhook creation failed: {}", describe_error(status, &body));
    }
    let v: serde_json::Value = serde_json::from_str(&body).context("could not parse response")?;
    Ok(CreatedWebhook {
        entry: entry_from(&v),
        secret: str_field(&v, "secret"),
    })
}

pub async fn action_webhook_remove(id: &str, client: &OdalClient, cfg: &Config) -> Result<()> {
    let url = format!("{}/api/v1/webhooks/{id}", cfg.vault_url);
    let (status, body) = client.delete(&url).await?;
    if !status.is_success() {
        bail!("remove failed: {}", describe_error(status, &body));
    }
    Ok(())
}

pub async fn action_webhook_test(id: &str, client: &OdalClient, cfg: &Config) -> Result<()> {
    let url = format!("{}/api/v1/webhooks/{id}/test", cfg.vault_url);
    let (status, body) = client.post_empty(&url).await?;
    if !status.is_success() {
        bail!("test delivery failed: {}", describe_error(status, &body));
    }
    Ok(())
}
