//! `odal evidence` — generate and store a passport's signed evidence dossier.

use anyhow::Result;

use crate::{
    config::Config, core::passport::action_evidence, http::OdalClient,
    stateless::render::render_export,
};

pub async fn run_evidence(id: &str, output: Option<&str>) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let result = action_evidence(id, &client, &cfg).await?;
    render_export(&result, output)?;
    Ok(())
}
