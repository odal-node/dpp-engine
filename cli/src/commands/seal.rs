//! `odal seal status [id]` — what the node knows about qualified sealing,
//! operator-wide or for one passport — and `odal seal repair <id>`, the one
//! command here that spends.

use anyhow::Result;

use crate::{
    core::seal::{SealStatus, action_seal_repair, action_seal_status, action_seal_summary},
    stateless::render::{
        render_seal_absent, render_seal_repair, render_seal_status, render_seal_summary,
    },
};

pub async fn run_seal_status(id: Option<&str>, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;

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

/// `odal seal repair <id>` — queue a replacement for a seal that does not verify.
///
/// The node decides whether this is allowed, not the CLI: it opens the seal at
/// the moment of the request and refuses unless it is demonstrably broken. So
/// there is nothing to confirm here that the node does not already guard, and
/// nothing to pre-check that would not be stale by the time it was acted on.
///
/// A refusal is an error rather than a printed verdict, because the operator
/// asked for something and it did not happen — and the node's own detail says
/// which of the several "nothing to repair" states this is.
pub async fn run_seal_repair(id: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let repair = action_seal_repair(id, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&repair)?);
    } else {
        render_seal_repair(&repair, id);
    }
    Ok(())
}
