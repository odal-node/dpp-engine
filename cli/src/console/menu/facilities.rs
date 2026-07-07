//! Facilities menu (ESPR Annex III): list, add, set default, remove.

use anyhow::Result;
use console::style;
use inquire::{Confirm, InquireError, Select, Text};

use crate::core::registry_identity::{
    FacilityCreateParams, action_facility_add, action_facility_list, action_facility_remove,
    action_facility_set_default,
};

use super::super::validators::{Required, valid_optional_country};
use super::{IdRow, MenuItem, ask, client, hint, print_err, skip_msg};

const FACILITIES: &[MenuItem] = &[
    MenuItem::new("List", "show configured facilities (default marked *)"),
    MenuItem::new("Add", "add a facility (e.g. a GLN)"),
    MenuItem::new("Set default", "choose which facility new passports use"),
    MenuItem::new("Remove", "delete a facility"),
    MenuItem::new("← Back", ""),
];

pub(super) async fn facilities_menu() -> Result<()> {
    loop {
        match Select::new(
            "Facilities — what would you like to do?",
            FACILITIES.to_vec(),
        )
        .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
        .prompt()
        {
            Ok(item) => match item.label {
                "List" => match client() {
                    Ok((client, cfg)) => match action_facility_list(&client, &cfg).await {
                        Ok(rows) if rows.is_empty() => {
                            println!("\n  {} No facilities configured.\n", style("ℹ").cyan());
                        }
                        Ok(rows) => {
                            println!();
                            for f in &rows {
                                let star = if f.is_default {
                                    style(" *").green().to_string()
                                } else {
                                    String::new()
                                };
                                println!(
                                    "  {} {} {}  {}{}",
                                    style(&f.id).dim(),
                                    f.scheme,
                                    f.value,
                                    f.name,
                                    star
                                );
                            }
                            hint("odal facility list");
                            println!();
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Add" => {
                    if let Some(params) = prompt_facility()? {
                        match client() {
                            Ok((client, cfg)) => {
                                match action_facility_add(&params, &client, &cfg).await {
                                    Ok(f) => {
                                        println!(
                                            "\n  {} Added facility {}.\n",
                                            style("✓").green(),
                                            f.id
                                        );
                                        hint("odal facility add --name … --value … --country …");
                                    }
                                    Err(e) => print_err(e),
                                }
                            }
                            Err(e) => print_err(e),
                        }
                    }
                }
                "Set default" => {
                    if let Some(id) = pick_facility("Make which facility the default?").await? {
                        match client() {
                            Ok((client, cfg)) => {
                                match action_facility_set_default(&id, &client, &cfg).await {
                                    Ok(()) => {
                                        println!(
                                            "\n  {} Default facility set.\n",
                                            style("✓").green()
                                        )
                                    }
                                    Err(e) => print_err(e),
                                }
                            }
                            Err(e) => print_err(e),
                        }
                    }
                }
                "Remove" => {
                    if let Some(id) = pick_facility("Remove which facility?").await? {
                        let ok = ask(Confirm::new("Remove this facility?")
                            .with_default(false)
                            .prompt())?
                        .unwrap_or(false);
                        if ok {
                            match client() {
                                Ok((client, cfg)) => {
                                    match action_facility_remove(&id, &client, &cfg).await {
                                        Ok(()) => println!(
                                            "\n  {} Facility removed.\n",
                                            style("✓").green()
                                        ),
                                        Err(e) => print_err(e),
                                    }
                                }
                                Err(e) => print_err(e),
                            }
                        }
                    }
                }
                "← Back" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Prompt for the fields of a new facility. `None` if the operator cancels.
fn prompt_facility() -> Result<Option<FacilityCreateParams>> {
    let name = match ask(Text::new("Facility name:")
        .with_validator(Required("Facility name"))
        .prompt())?
    {
        Some(s) => s.trim().to_owned(),
        None => return Ok(None),
    };
    let scheme = match ask(Text::new("Identifier scheme:").with_default("gln").prompt())? {
        Some(s) => s.trim().to_owned(),
        None => return Ok(None),
    };
    let value = match ask(Text::new("Identifier value (e.g. 13-digit GLN):")
        .with_validator(Required("Identifier value"))
        .prompt())?
    {
        Some(s) => s.trim().to_owned(),
        None => return Ok(None),
    };
    let country = match ask(Text::new("Country (ISO 3166-1 alpha-2, e.g. DE):")
        .with_validator(valid_optional_country)
        .prompt())?
    {
        Some(s) => s.trim().to_ascii_uppercase(),
        None => return Ok(None),
    };
    let address = match ask(Text::new("Address (optional):")
        .with_help_message(skip_msg())
        .prompt())?
    {
        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Some(_) => None,
        None => return Ok(None),
    };
    let default = ask(Confirm::new("Make this the default facility?")
        .with_default(false)
        .prompt())?
    .unwrap_or(false);
    Ok(Some(FacilityCreateParams {
        name,
        scheme,
        value,
        country,
        address,
        default,
    }))
}

/// List facilities and let the operator pick one — returns the chosen id.
async fn pick_facility(prompt: &str) -> Result<Option<String>> {
    let (client, cfg) = match client() {
        Ok(c) => c,
        Err(e) => {
            print_err(e);
            return Ok(None);
        }
    };
    let rows = match action_facility_list(&client, &cfg).await {
        Ok(r) => r,
        Err(e) => {
            print_err(e);
            return Ok(None);
        }
    };
    if rows.is_empty() {
        println!("\n  {} No facilities configured.\n", style("ℹ").cyan());
        return Ok(None);
    }
    let choices: Vec<IdRow> = rows
        .iter()
        .map(|f| IdRow {
            id: f.id.clone(),
            label: format!(
                "{} {}  {}{}",
                f.scheme,
                f.value,
                f.name,
                if f.is_default { " *" } else { "" }
            ),
        })
        .collect();
    Ok(ask(Select::new(prompt, choices).prompt())?.map(|r| r.id))
}
