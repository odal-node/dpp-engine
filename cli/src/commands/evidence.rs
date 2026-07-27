//! `odal evidence` — generate and store a passport's signed evidence dossier.

use anyhow::Result;

use crate::{core::passport::action_evidence, stateless::render::render_export};

pub async fn run_evidence(id: &str, output: Option<&str>) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let result = action_evidence(id, &client, &cfg).await?;
    render_export(&result, output)?;
    Ok(())
}
