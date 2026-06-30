//! `odal export` — export passports in a given format, optionally filtered by status.

use anyhow::Result;

use crate::{
    config::Config,
    core::{passport::action_export, types::ExportParams},
    http::OdalClient,
    stateless::render::render_export,
};

pub async fn run_export(
    format: &str,
    status_filter: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let params = ExportParams {
        format: format.to_owned(),
        status_filter: status_filter.map(str::to_owned),
    };
    let result = action_export(&params, &client, &cfg).await?;
    render_export(&result, output)?;
    Ok(())
}
