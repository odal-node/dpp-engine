//! `odal stats` and `odal passport stats <id>` — aggregate scan telemetry.

use anyhow::Result;

use crate::{
    core::passport::{action_operator_stats, action_passport_stats},
    stateless::render::{render_operator_stats, render_passport_stats},
};

/// `odal passport stats <id>` — one passport's resolution + QR-render counts.
pub async fn run_passport_stats(id: &str, days: u32, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let stats = action_passport_stats(id, days, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        render_passport_stats(&stats, id);
    }
    Ok(())
}

/// `odal stats` — the operator-wide rollup across every passport.
pub async fn run_operator_stats(days: u32, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let stats = action_operator_stats(days, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        render_operator_stats(&stats);
    }
    Ok(())
}
