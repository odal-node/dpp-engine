//! `odal schema` — report the node's schema version and compatibility.

use anyhow::Result;

use crate::{
    config::Config, core::schema::action_schema_check, http::OdalClient,
    stateless::render::render_schema_check,
};

pub async fn run_schema() -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let result = action_schema_check(&client, &cfg).await?;
    render_schema_check(&result);
    Ok(())
}
