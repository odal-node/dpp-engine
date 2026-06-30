//! `odal suspend | archive | history <id>` — passport lifecycle operations.

use anyhow::Result;

use crate::{
    config::Config,
    core::{
        passport::{action_archive, action_history, action_suspend},
        types::{ArchiveParams, HistoryParams, SuspendParams},
    },
    http::OdalClient,
    stateless::render::render_history,
};

pub async fn run_suspend(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_suspend(&SuspendParams { id: id.to_owned() }, &client, &cfg).await?;
    println!("Passport {id} suspended.");
    Ok(())
}

pub async fn run_archive(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_archive(&ArchiveParams { id: id.to_owned() }, &client, &cfg).await?;
    println!("Passport {id} archived.");
    Ok(())
}

pub async fn run_history(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let entries = action_history(&HistoryParams { id: id.to_owned() }, &client, &cfg).await?;
    render_history(&entries, id);
    Ok(())
}
