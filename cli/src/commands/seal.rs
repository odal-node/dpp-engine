//! `odal seal status [id]` — what the node knows about qualified sealing,
//! operator-wide or for one passport.

use anyhow::Result;

use crate::{
    config::Config,
    core::seal::{SealStatus, action_seal_status, action_seal_summary},
    http::OdalClient,
    stateless::render::{render_seal_absent, render_seal_status, render_seal_summary},
};

pub async fn run_seal_status(id: Option<&str>, json: bool) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);

    let Some(id) = id else {
        let summary = action_seal_summary(&client, &cfg).await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            render_seal_summary(&summary);
        }
        return Ok(());
    };

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
