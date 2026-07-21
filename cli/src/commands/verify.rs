//! `odal verify` — verify a stored dossier (by id) or an uploaded dossier
//! file against the node.
//!
//! Exit codes match `VerificationReport::exit_code`'s documented convention:
//! 0 verified, 1 tamper detected. A target that couldn't be reached, read,
//! or parsed as a dossier is a third case, exit 2 — `action_verify` returns
//! `Err` for that, never a report.

use anyhow::Result;

use crate::{core::verify::action_verify, stateless::render::render_verification_report};

pub async fn run_verify(target: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    match action_verify(target, &client, &cfg).await {
        Ok(report) => {
            render_verification_report(&report, target);
            std::process::exit(report.exit_code());
        }
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(2);
        }
    }
}
