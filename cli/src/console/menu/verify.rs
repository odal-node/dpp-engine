//! Verify menu: check a stored dossier or an uploaded dossier file against
//! the node.

use anyhow::Result;
use inquire::{Select, Text};

use crate::{core::verify::action_verify, stateless::render::render_verification_report};

use super::super::validators::valid_dossier_file;
use super::{ask, client, hint, print_err};

pub(super) async fn verify() -> Result<()> {
    let target = match prompt_target().await? {
        Some(t) => t,
        None => return Ok(()),
    };

    println!();
    let (odal_client, cfg) = client()?;
    match action_verify(&target, &odal_client, &cfg).await {
        Ok(report) => {
            render_verification_report(&report, &target);
            hint(&format!("odal verify {target}"));
            println!();
        }
        Err(e) => print_err(e),
    }
    Ok(())
}

/// Choose a stored dossier (by id) or a dossier file. Offers the native OS
/// file picker for the file path, falling back to a typed-path prompt if the
/// operator prefers it or no display is available (e.g. a headless/SSH
/// session) — same pattern as `Passports › Import`.
async fn prompt_target() -> Result<Option<String>> {
    match ask(Select::new(
        "Verify:",
        vec!["Stored dossier (enter id)", "Dossier file…"],
    )
    .with_help_message("↑↓ · ⏎ select · Esc to cancel")
    .prompt())?
    {
        Some("Stored dossier (enter id)") => prompt_dossier_id(),
        Some(_) => prompt_dossier_file_path().await,
        None => Ok(None),
    }
}

fn prompt_dossier_id() -> Result<Option<String>> {
    ask(Text::new("Stored dossier id:")
        .with_help_message("Esc to cancel")
        .prompt())
}

async fn prompt_dossier_file_path() -> Result<Option<String>> {
    match ask(
        Select::new("Choose the dossier file:", vec!["Browse…", "Type a path"])
            .with_help_message("↑↓ · ⏎ select · Esc to cancel")
            .prompt(),
    )? {
        Some("Browse…") => match super::super::file_picker::pick_dossier_file().await {
            Some(path) => {
                super::super::file_picker::remember_dossier_dir(&path);
                Ok(Some(path.to_string_lossy().into_owned()))
            }
            None => prompt_dossier_path_text(),
        },
        Some(_) => prompt_dossier_path_text(),
        None => Ok(None),
    }
}

fn prompt_dossier_path_text() -> Result<Option<String>> {
    ask(Text::new("Path to the evidence dossier JSON file:")
        .with_help_message("Esc to cancel")
        .with_validator(valid_dossier_file)
        .prompt())
}
