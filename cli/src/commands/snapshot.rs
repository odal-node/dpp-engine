//! `odal snapshot verify <target>` — check a continuity snapshot's signed
//! freshness bound without reaching the node.
//!
//! Exit codes follow the convention `odal verify` already uses: 0 the bound is
//! proven and current, 1 it is not, 2 the check could not be made at all
//! (unreadable file, failed fetch, no usable key). The three ways a bound can
//! fail — expired, stripped, unproven — are one exit code and three different
//! sentences, because a script only needs to know whether to trust the copy and
//! a person needs to know which of the three happened.

use anyhow::Result;
use chrono::Utc;

use crate::{
    core::snapshot::{action_snapshot_verify, exit_code, verdict_json},
    stateless::render::render_snapshot_bound,
};

pub async fn run_snapshot_verify(
    target: &str,
    key: Option<&str>,
    did_url: Option<&str>,
    json: bool,
) -> Result<()> {
    match action_snapshot_verify(target, key, did_url, Utc::now()).await {
        Ok(bound) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&verdict_json(&bound))?);
            } else {
                render_snapshot_bound(&bound, target);
            }
            std::process::exit(exit_code(&bound));
        }
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(2);
        }
    }
}
