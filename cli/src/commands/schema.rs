//! `odal schema` — report the node's schema version and compatibility.

use anyhow::Result;

use crate::{core::schema::action_schema_check, stateless::render::render_schema_check};

pub async fn run_schema() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let result = action_schema_check(&client, &cfg).await?;
    render_schema_check(&result);
    Ok(())
}
