//! Verify menu: check an exported evidence dossier fully offline.

use anyhow::Result;
use inquire::{Select, Text};

use crate::{core::verify::action_verify, stateless::render::render_verification_report};

use super::super::validators::valid_dossier_file;
use super::{ask, hint, print_err};

pub(super) async fn verify() -> Result<()> {
    let file = match prompt_dossier_file().await? {
        Some(f) => f,
        None => return Ok(()),
    };

    println!();
    match action_verify(&file) {
        Ok(report) => {
            render_verification_report(&report, &file);
            hint(&format!("odal verify {file}"));
            println!();
        }
        Err(e) => print_err(e),
    }
    Ok(())
}

/// Choose a dossier file. Offers the native OS file picker first, falling
/// back to a typed-path prompt if the operator prefers it or no display is
/// available (e.g. a headless/SSH session) — same pattern as `Passports › Import`.
async fn prompt_dossier_file() -> Result<Option<String>> {
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
