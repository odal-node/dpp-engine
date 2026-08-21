//! `odal status` — health-check the node and its services.

use anyhow::Result;

use crate::{core::infra::action_status, stateless::render::render_status};

pub async fn run_status() -> Result<()> {
    let (client, cfg) = crate::http::load_client_unchecked()?;
    let report = action_status(&client, &cfg).await?;
    render_status(&report);
    if !report.all_ok() {
        anyhow::bail!("One or more services are unhealthy");
    }
    Ok(())
}
