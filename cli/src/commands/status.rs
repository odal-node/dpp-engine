//! `odal status` — health-check the node and its services.

use anyhow::Result;

use crate::{
    config::Config,
    core::{infra::action_status, types::ServiceStatus},
    http::OdalClient,
    stateless::render::render_status,
};

pub async fn run_status() -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let report = action_status(&client, &cfg).await?;
    render_status(&report);
    let all_ok = report
        .services
        .iter()
        .all(|s| matches!(s.status, ServiceStatus::Ok));
    if !all_ok {
        anyhow::bail!("One or more services are unhealthy");
    }
    Ok(())
}
