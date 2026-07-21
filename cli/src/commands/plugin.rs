//! `odal plugin install <file>` — upload a signed sector plugin for runtime
//! install (verified, persisted, and hot-swapped by the node).

use anyhow::Result;

use crate::core::plugin::action_plugin_install;

pub async fn run_plugin_install(file: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let installed = action_plugin_install(file, &client, &cfg).await?;
    println!(
        "Installed sector '{}' (ABI {}) — verified, persisted, and now serving.",
        installed.sector, installed.abi_version
    );
    Ok(())
}
