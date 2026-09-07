//! `odal ruleset reload` — tell the node to re-read its signed compliance
//! ruleset channel and hot-swap a verified bundle.

use anyhow::Result;

use crate::core::ruleset::action_ruleset_reload;

pub async fn run_ruleset_reload() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let reload = action_ruleset_reload(&client, &cfg).await?;
    // The two outcomes read differently on purpose: an operator who just dropped
    // a new bundle needs to see whether it was actually taken, and "reloaded"
    // alone would not tell them.
    if reload.changed {
        println!(
            "Ruleset '{}' verified and now in force — no restart needed.",
            reload.ruleset_version
        );
    } else {
        println!(
            "Channel re-read; ruleset '{}' was already in force (nothing new published).",
            reload.ruleset_version
        );
    }
    Ok(())
}
