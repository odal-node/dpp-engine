//! Publish: sign one draft, or every draft.

use anyhow::{Context, Result};
use serde_json::json;

use super::super::types::{PassportPublishResult, PublishParams, PublishSummary};
use crate::{config::Config, http::OdalClient};

pub async fn action_publish(
    params: &PublishParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<PublishSummary> {
    match &params.id {
        Some(id) => publish_one(client, &cfg.vault_url, id).await,
        None => publish_all(client, &cfg.vault_url).await,
    }
}

async fn publish_one(client: &OdalClient, vault_url: &str, id: &str) -> Result<PublishSummary> {
    let url = format!("{vault_url}/api/v1/dpp/{id}/publish");
    let (status, body) = client
        .post_json(&url, &json!({}))
        .await
        .with_context(|| format!("Failed to publish passport {id}"))?;

    if status.is_success() {
        let resp: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let name = resp
            .get("productName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_owned();
        let qr_url = resp
            .get("qrCodeUrl")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        Ok(PublishSummary {
            published: 1,
            failed: 0,
            errors: vec![],
            items: vec![PassportPublishResult {
                id: id.to_owned(),
                name,
                success: true,
                qr_url,
                error: None,
            }],
        })
    } else {
        let err = format!(
            "Failed to publish {id} (HTTP {status}): {}",
            &body[..body.len().min(300)]
        );
        Ok(PublishSummary {
            published: 0,
            failed: 1,
            errors: vec![err.clone()],
            items: vec![PassportPublishResult {
                id: id.to_owned(),
                name: "Unknown".to_owned(),
                success: false,
                qr_url: None,
                error: Some(err),
            }],
        })
    }
}

async fn publish_all(client: &OdalClient, vault_url: &str) -> Result<PublishSummary> {
    let list_url = format!("{vault_url}/api/v1/dpps?status=draft");
    let (http_status, body) = client
        .get(&list_url)
        .await
        .context("Failed to fetch draft passports")?;

    if !http_status.is_success() {
        anyhow::bail!("Failed to list drafts (HTTP {http_status}): {body}");
    }

    let envelope: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse draft list")?;
    let drafts: Vec<serde_json::Value> = envelope
        .get("dpps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut published = 0usize;
    let mut failed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut items: Vec<PassportPublishResult> = Vec::new();

    for dpp in &drafts {
        let id = dpp.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = dpp
            .get("productName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let url = format!("{vault_url}/api/v1/dpp/{id}/publish");

        match client.post_json(&url, &json!({})).await {
            Ok((status, resp_body)) if status.is_success() => {
                let resp: serde_json::Value = serde_json::from_str(&resp_body).unwrap_or_default();
                let qr_url = resp
                    .get("qrCodeUrl")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                items.push(PassportPublishResult {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    success: true,
                    qr_url,
                    error: None,
                });
                published += 1;
            }
            Ok((status, resp_body)) => {
                let err = format!(
                    "{name}: HTTP {status} — {}",
                    &resp_body[..resp_body.len().min(200)]
                );
                errors.push(err.clone());
                items.push(PassportPublishResult {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    success: false,
                    qr_url: None,
                    error: Some(err),
                });
                failed += 1;
            }
            Err(e) => {
                let err = format!("{name}: {e}");
                errors.push(err.clone());
                items.push(PassportPublishResult {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    success: false,
                    qr_url: None,
                    error: Some(err),
                });
                failed += 1;
            }
        }
    }

    Ok(PublishSummary {
        published,
        failed,
        errors,
        items,
    })
}
