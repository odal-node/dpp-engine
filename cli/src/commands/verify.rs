//! `odal verify` — verify an evidence dossier fully offline, zero trust in
//! the issuing node.
//!
//! Exit codes match `dpp_evidence::VerificationReport::exit_code`'s
//! documented convention: 0 verified, 1 tamper detected. A file that
//! couldn't even be read or parsed as a dossier is a third case, exit 2 —
//! `action_verify` returns `Err` for that, never a report.

use anyhow::Result;

use crate::{core::verify::action_verify, stateless::render::render_verification_report};

pub fn run_verify(file: &str) -> Result<()> {
    match action_verify(file) {
        Ok(report) => {
            render_verification_report(&report, file);
            std::process::exit(report.exit_code());
        }
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(2);
        }
    }
}
