//! `odal seal status <id>` — what the node knows about a passport's qualified
//! seal.

use anyhow::Result;

use crate::{
    config::Config,
    core::seal::{SealStatus, action_seal_status},
    http::OdalClient,
    stateless::render::{render_seal_absent, render_seal_status},
};

pub async fn run_seal_status(id: &str, json: bool) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);

    match action_seal_status(id, &client, &cfg).await? {
        SealStatus::Present(seal) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&seal)?);
            } else {
                render_seal_status(&seal, id);
            }
        }
        SealStatus::Absent => {
            if json {
                println!("{}", serde_json::json!({ "seal": null }));
            } else {
                render_seal_absent(id);
            }
        }
    }
    Ok(())
}
