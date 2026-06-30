//! `odal key create | list | revoke | use` — manage API keys via the node API.

use anyhow::{Context, Result, bail};

use crate::{
    config::Config,
    core::{
        onboarding::{action_key_create, action_key_list, action_key_revoke},
        types::{KeyCreateParams, KeyRevokeParams},
    },
    http::OdalClient,
    stateless::render::{render_key_create, render_key_list},
};

pub async fn run_key_create(name: &str, activate: bool) -> Result<()> {
    let mut cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let result = action_key_create(
        &KeyCreateParams {
            name: name.to_owned(),
        },
        &client,
        &cfg,
    )
    .await?;
    render_key_create(&result);
    // `--use`: adopt the freshly minted key as this profile's active credential.
    // Without it, `key create` only prints the secret — it does not switch the
    // CLI over, which is the footgun that makes self-lockout easy.
    if activate {
        cfg.api_key = result.secret.clone();
        cfg.save()?;
        println!("\nSaved as the active key for the '{}' profile.", cfg.name);
    }
    Ok(())
}

pub async fn run_key_list() -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let keys = action_key_list(&client, &cfg).await?;
    render_key_list(&keys);
    Ok(())
}

pub async fn run_key_revoke(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_key_revoke(&KeyRevokeParams { id: id.to_owned() }, &client, &cfg).await?;
    println!("API key {id} revoked.");
    Ok(())
}

/// `odal key use <secret>` — adopt an existing API key as this profile's active
/// credential (written to the 0600 credentials store). The key is verified
/// against the node before it is persisted, so a revoked or mistyped secret is
/// never saved over a working one. This is the non-destructive recovery path
/// when you already hold a valid key and just need to point the CLI at it.
pub async fn run_key_use(secret: &str) -> Result<()> {
    let secret = secret.trim();
    if !secret.starts_with("odal_sk_") {
        bail!("that doesn't look like an Odal API key (expected an 'odal_sk_…' secret)");
    }
    let mut cfg = Config::load()?;
    // Verify against an authenticated route before persisting. Any valid key —
    // even least-privilege — can list passports; only a bad key gets a 401.
    let client = OdalClient::new(secret);
    let url = format!("{}/api/v1/dpps?limit=1", cfg.vault_url);
    let (status, _) = client
        .get(&url)
        .await
        .context("could not reach the node to verify the key")?;
    if status.as_u16() == 401 {
        bail!("the node rejected that key (401) — it may be revoked, expired, or mistyped");
    }
    cfg.api_key = secret.to_owned();
    cfg.save()?;
    println!(
        "Saved API key to the '{}' profile. You're authenticated.",
        cfg.name
    );
    Ok(())
}
