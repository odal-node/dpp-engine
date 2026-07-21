//! `odal plugin install <file>` — upload a signed sector plugin for runtime
//! install (verified, persisted, and hot-swapped by the node).

use anyhow::Result;

use crate::{config::Config, core::plugin::action_plugin_install, http::OdalClient};

pub async fn run_plugin_install(file: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let installed = action_plugin_install(file, &client, &cfg).await?;
    println!(
        "Installed sector '{}' (ABI {}) — verified, persisted, and now serving.",
        installed.sector, installed.abi_version
    );
    Ok(())
}
