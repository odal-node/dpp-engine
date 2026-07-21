//! Sector-plugin administration via the node API — upload a signed artifact for
//! runtime install. Pure HTTP; the node owns verification and persistence.

use anyhow::{Context, Result, bail};
use std::path::Path;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// An installed plugin as reported by the node.
pub struct InstalledPlugin {
    pub sector: String,
    pub abi_version: String,
}

/// Read `<file>` and its sibling `<file>.sig`, upload both, and return what the
/// node installed. The node verifies the signature against its pinned publisher
/// key, so the CLI never handles the key itself.
pub async fn action_plugin_install(
    file: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<InstalledPlugin> {
    let wasm_path = Path::new(file);
    let wasm =
        std::fs::read(wasm_path).with_context(|| format!("could not read plugin file: {file}"))?;
    let sig_path = format!("{file}.sig");
    let sig = std::fs::read(&sig_path).with_context(|| {
        format!("could not read detached signature: {sig_path} (expected alongside the .wasm)")
    })?;
    let filename = wasm_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin.wasm");

    let url = format!("{}/api/v1/plugins", cfg.vault_url);
    let (status, body) = client.install_plugin(&url, filename, wasm, sig).await?;
    if !status.is_success() {
        bail!("plugin install failed: {}", describe_error(status, &body));
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    Ok(InstalledPlugin {
        sector: v
            .get("sector")
            .and_then(|s| s.as_str())
            .unwrap_or("?")
            .to_owned(),
        abi_version: v
            .get("abiVersion")
            .and_then(|s| s.as_str())
            .unwrap_or("?")
            .to_owned(),
    })
}
