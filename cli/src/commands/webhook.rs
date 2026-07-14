//! `odal webhook list | add | remove | test` — manage signed outbound webhook
//! subscriptions via the node API.

use anyhow::Result;

use crate::{
    config::Config,
    core::webhook::{
        action_webhook_add, action_webhook_list, action_webhook_remove, action_webhook_test,
    },
    http::OdalClient,
};

pub async fn run_webhook_list() -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let hooks = action_webhook_list(&client, &cfg).await?;
    if hooks.is_empty() {
        println!("No webhooks configured. Add one with `odal webhook add <url>`.");
        return Ok(());
    }
    println!("{:<38}  {:<6}  {:<28}  URL", "ID", "ACTIVE", "EVENTS");
    for h in &hooks {
        println!(
            "{:<38}  {:<6}  {:<28}  {}",
            h.id,
            if h.active { "yes" } else { "no" },
            h.events,
            h.url,
        );
    }
    Ok(())
}

pub async fn run_webhook_add(
    url: String,
    events: Vec<String>,
    description: Option<String>,
) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let created = action_webhook_add(&url, events, description, &client, &cfg).await?;
    println!("Added webhook {} → {}", created.entry.id, created.entry.url);
    println!();
    println!("Signing secret (shown once — store it now):");
    println!("  {}", created.secret);
    Ok(())
}

pub async fn run_webhook_remove(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_webhook_remove(id, &client, &cfg).await?;
    println!("Webhook {id} removed.");
    Ok(())
}

pub async fn run_webhook_test(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_webhook_test(id, &client, &cfg).await?;
    println!("Test delivery queued for webhook {id}.");
    Ok(())
}
