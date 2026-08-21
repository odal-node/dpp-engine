//! `odal validate` — validate stored passports, or dry-run a body from a file.

use anyhow::Result;

use crate::{
    core::passport::{action_validate, action_validate_body},
    stateless::render::{render_dry_run, render_validation_report},
};

/// With no argument, validate the stored drafts. With a file, dry-run that body
/// against the node — the same gate `create` applies, persisting nothing.
pub async fn run_validate(file: Option<String>) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;

    let Some(path) = file else {
        let report = action_validate(&client, &cfg).await?;
        render_validation_report(&report);
        if report.records.iter().any(|r| !r.issues.is_empty()) {
            anyhow::bail!("Some DPPs have validation issues");
        }
        return Ok(());
    };

    let verdict = action_validate_body(&path, &client, &cfg).await?;
    render_dry_run(&verdict);
    // A body that would be refused is a failed check, not a successful report.
    if !verdict.create_valid {
        anyhow::bail!("{path} would be refused");
    }
    Ok(())
}
