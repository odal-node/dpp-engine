//! `odal update` — bring the node up to the latest version.
//!
//! Decided the way `odal up` decides whether to build — by whether this install
//! carries the engine source (`source_tree_present`), never by profile kind:
//!   • source present — rebuild from it and recreate the containers. A pull
//!     there would fetch images the next `odal up` replaces with a build anyway.
//!   • no source — pull the published images for the pinned `ODAL_VERSION`
//!     (`latest` when unset), then `odal up` to recreate.

use anyhow::Result;

use crate::{
    config::{Config, EnvKind},
    core::infra::{
        action_up, action_update, compose_file, preflight_prod_env, source_tree_present,
    },
};

pub async fn run_update() -> Result<()> {
    let cfg = Config::load()?;
    let compose = compose_file()?;
    if source_tree_present(&compose) {
        // The rebuild recreates the containers, so it starts the node: hold a
        // production profile to the same preflight `odal up` does.
        if matches!(cfg.kind, EnvKind::Prod) {
            preflight_prod_env(&compose)?;
        }
        println!(
            "Rebuilding Odal Node from source ({})...",
            compose.display()
        );
        action_up(&compose, true).await?;
        println!("Rebuilt and restarted. Run `odal status` to check health.");
    } else {
        println!("Pulling Odal Node images ({})...", compose.display());
        action_update(&compose).await?;
        println!("Images updated. Run `odal up` to restart with the new images.");
    }
    Ok(())
}
