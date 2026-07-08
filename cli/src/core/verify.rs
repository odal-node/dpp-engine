//! Verify: offline verification of an exported evidence dossier, zero trust
//! in the issuing node.

use anyhow::{Context, Result};
use dpp_evidence::{VerificationReport, VerifyMode, verify_dossier_json};

pub fn action_verify(file: &str) -> Result<VerificationReport> {
    let bytes = std::fs::read(file).with_context(|| format!("Cannot read file: {file}"))?;
    verify_dossier_json(&bytes, VerifyMode::Embedded)
        .with_context(|| format!("{file} is not a valid evidence dossier"))
}
