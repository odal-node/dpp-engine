//! `odal init` — save connection config and scaffold the install files.
use crate::{
    config::{self, Config, EnvKind},
    core,
};
use anyhow::Result;

/// `odal init` — save connection config and scaffold the install files.
///
/// Intended for scripting and CI. Interactive operators should run `odal` instead.
/// The operator's `.env` is never created or modified here.
pub async fn run_init(
    node_url: Option<String>,
    vault_url: Option<String>,
    resolver_url: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let mut cfg = Config::load().unwrap_or_default();

    // The parser makes these two mutually exclusive, so at most one arm runs.
    if let Some(origin) = node_url.filter(|s| !s.trim().is_empty()) {
        cfg.vault_url = config::vault_url_from_node(&origin);
        cfg.kind = EnvKind::infer(&cfg.vault_url);
    }
    if let Some(url) = vault_url.filter(|s| !s.trim().is_empty()) {
        cfg.vault_url = url;
        cfg.kind = EnvKind::infer(&cfg.vault_url);
    }
    if let Some(url) = resolver_url.filter(|s| !s.trim().is_empty()) {
        cfg.resolver_url = url;
    }
    if let Some(key) = api_key {
        cfg.api_key = key;
    }
    cfg.save()?;
    println!(
        "Configuration saved to ~/.config/odal/config.toml (profile '{}' · {})",
        cfg.name, cfg.kind
    );
    if config::resolver_is_unstated_default(cfg.kind, &cfg.resolver_url) {
        super::profile::warn_unstated_resolver(&cfg.resolver_url);
    }

    // The compose file is not the whole install: it bind-mounts the database
    // role-provisioning hook out of `ops/bootstrap/`, and a missing mount
    // source becomes an empty directory rather than an error.
    let cwd = std::env::current_dir()?;
    match core::infra::scaffold_install(&cwd)? {
        created if created.is_empty() => {
            println!("Install files already present — nothing to scaffold");
        }
        created => {
            for path in created {
                println!("Created {}", path.display());
            }
        }
    }

    Ok(())
}
