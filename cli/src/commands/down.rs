//! `odal down` — stop the local Odal Node Docker services.

use anyhow::Result;

use crate::core::infra::{action_down, compose_file};

pub async fn run_down() -> Result<()> {
    let compose = compose_file()?;
    println!("Stopping Odal Node services ({})...", compose.display());
    action_down(&compose).await?;
    println!("Services stopped.");
    Ok(())
}
