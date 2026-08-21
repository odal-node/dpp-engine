//! `odal init` — save connection config and scaffold the Docker Compose file.

use std::fs;

use anyhow::Result;

use crate::{
    config::{self, Config, EnvKind},
    core::infra::COMPOSE_TEMPLATE,
};

/// `odal init` — save connection config and scaffold `docker/docker-compose.yml`.
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

    let cwd = std::env::current_dir()?;
    let docker_dir = cwd.join("docker");
    if !docker_dir.exists() {
        fs::create_dir_all(&docker_dir)?;
    }
    let compose_path = docker_dir.join("docker-compose.yml");
    if compose_path.exists() {
        println!("docker/docker-compose.yml already exists — skipping scaffold");
    } else {
        fs::write(&compose_path, COMPOSE_TEMPLATE)?;
        println!("Created {}", compose_path.display());
    }

    Ok(())
}
