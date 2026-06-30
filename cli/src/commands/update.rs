//! `odal update` — bring the node up to the latest version.
//!
//! What "latest" means depends on how the node is deployed, mirroring `odal up`:
//!   • localhost / self-host (Dev) — node + resolver are built from source; there
//!     is no published image to pull (pre-publish, GHCR even returns "denied").
//!     Update = rebuild from the current source and recreate the containers.
//!   • remote / managed (Prod) — the node runs the published GHCR images.
//!     Update = pull the latest images, then `odal up` to recreate.

use anyhow::Result;

use crate::{
    config::{Config, EnvKind},
    core::infra::{action_up, action_update, compose_file},
};

pub async fn run_update() -> Result<()> {
    let cfg = Config::load()?;
    let compose = compose_file()?;
    match cfg.kind {
        EnvKind::Dev => {
            // Build-from-source install: `pull` would only ever hit "denied" for
            // the unpublished node/resolver images. Rebuild + recreate instead.
            println!(
                "Rebuilding Odal Node from source ({})...",
                compose.display()
            );
            action_up(&compose, true).await?;
            println!("Rebuilt and restarted. Run `odal status` to check health.");
        }
        EnvKind::Prod => {
            println!("Pulling latest Odal Node images ({})...", compose.display());
            action_update(&compose).await?;
            println!("Images updated. Run `odal up` to restart with the new images.");
        }
    }
    Ok(())
}
