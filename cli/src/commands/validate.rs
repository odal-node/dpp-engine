//! `odal validate` — validate stored passports against their schema.

use anyhow::Result;

use crate::{
    config::Config, core::passport::action_validate, http::OdalClient,
    stateless::render::render_validation_report,
};

pub async fn run_validate() -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let report = action_validate(&client, &cfg).await?;
    render_validation_report(&report);
    if report.records.iter().any(|r| !r.issues.is_empty()) {
        anyhow::bail!("Some DPPs have validation issues");
    }
    Ok(())
}
