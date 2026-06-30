//! `odal up` — start the Odal Node Docker services.

use anyhow::Result;

use crate::{
    config::{Config, EnvKind},
    core::infra::{action_up, compose_file, preflight_prod_env},
};

pub async fn run_up() -> Result<()> {
    let cfg = Config::load()?;
    let compose = compose_file()?;
    // Production must not boot on missing or dev-default secrets.
    if matches!(cfg.kind, EnvKind::Prod) {
        preflight_prod_env(&compose)?;
    }
    // Local self-host builds the node image from source; remote pulls it.
    let build = matches!(cfg.kind, EnvKind::Dev);
    println!(
        "Starting Odal Node services ({} · {} env)...",
        compose.display(),
        cfg.kind
    );
    action_up(&compose, build).await?;
    println!("Services started. Run `odal status` to check health.");
    Ok(())
}
