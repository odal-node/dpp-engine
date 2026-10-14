//! `odal up` — start the Odal Node Docker services.

use anyhow::Result;

use crate::{
    config::Config,
    core::infra::{action_up, compose_file, preflight_start, source_tree_present},
};

pub async fn run_up() -> Result<()> {
    let cfg = Config::load()?;
    let compose = compose_file()?;
    preflight_start(&compose, cfg.kind)?;

    // Build from source only when this install actually carries it; otherwise
    // use the published image. See `source_tree_present`.
    let build = source_tree_present(&compose);
    println!(
        "Starting Odal Node services ({} · {} env, {})...",
        compose.display(),
        cfg.kind,
        if build {
            "building from source"
        } else {
            "using the published image"
        }
    );
    action_up(&compose, build).await?;
    println!("Services started. Run `odal status` to check health.");
    Ok(())
}
