//! Operator identifiers menu (ESPR Art. 13 — EORI/VAT/LEI/DUNS): list, add,
//! set primary, remove.

use anyhow::Result;
use console::style;
use inquire::{Confirm, InquireError, Select, Text};

use crate::core::registry_identity::{
    OperatorIdCreateParams, action_operator_id_add, action_operator_id_list,
    action_operator_id_remove, action_operator_id_set_primary,
};

use super::super::validators::Required;
use super::{IdRow, MenuItem, ask, client, hint, print_err, skip_msg};

const OPERATOR_IDS: &[MenuItem] = &[
    MenuItem::new("List", "show operator identifiers (primary marked *)"),
    MenuItem::new("Add", "add an identifier (EORI/VAT/LEI/DUNS)"),
    MenuItem::new("Set primary", "choose which identifier new passports use"),
    MenuItem::new("Remove", "delete an identifier"),
    MenuItem::new("← Back", ""),
];

pub(super) async fn operator_ids_menu() -> Result<()> {
    loop {
        match Select::new(
            "Operator identifiers — what would you like to do?",
            OPERATOR_IDS.to_vec(),
        )
        .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
        .prompt()
        {
            Ok(item) => match item.label {
                "List" => match client() {
                    Ok((client, cfg)) => match action_operator_id_list(&client, &cfg).await {
                        Ok(rows) if rows.is_empty() => {
                            println!(
                                "\n  {} No operator identifiers configured.\n",
                                style("ℹ").cyan()
                            );
                        }
                        Ok(rows) => {
                            println!();
                            for o in &rows {
                                let star = if o.is_primary {
                                    style(" *").green().to_string()
                                } else {
                                    String::new()
                                };
                                println!(
                                    "  {} {} {}{}",
                                    style(&o.id).dim(),
                                    o.scheme,
                                    o.value,
                                    star
                                );
                            }
                            hint("odal operator-id list");
                            println!();
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Add" => {
                    if let Some(params) = prompt_operator_id()? {
                        match client() {
                            Ok((client, cfg)) => {
                                match action_operator_id_add(&params, &client, &cfg).await {
                                    Ok(o) => {
                                        println!(
                                            "\n  {} Added operator identifier {}.\n",
                                            style("✓").green(),
                                            o.id
                                        );
                                        hint("odal operator-id add --scheme … --value …");
                                    }
                                    Err(e) => print_err(e),
                                }
                            }
                            Err(e) => print_err(e),
                        }
                    }
                }
                "Set primary" => {
                    if let Some(id) = pick_operator_id("Make which identifier the primary?").await?
                    {
                        match client() {
                            Ok((client, cfg)) => {
                                match action_operator_id_set_primary(&id, &client, &cfg).await {
                                    Ok(()) => println!(
                                        "\n  {} Primary identifier set.\n",
                                        style("✓").green()
                                    ),
                                    Err(e) => print_err(e),
                                }
                            }
                            Err(e) => print_err(e),
                        }
                    }
                }
                "Remove" => {
                    if let Some(id) = pick_operator_id("Remove which identifier?").await? {
                        let ok = ask(Confirm::new("Remove this operator identifier?")
                            .with_default(false)
                            .prompt())?
                        .unwrap_or(false);
                        if ok {
                            match client() {
                                Ok((client, cfg)) => {
                                    match action_operator_id_remove(&id, &client, &cfg).await {
                                        Ok(()) => println!(
                                            "\n  {} Operator identifier removed.\n",
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

/// Prompt for a new operator identifier. `None` if the operator cancels.
fn prompt_operator_id() -> Result<Option<OperatorIdCreateParams>> {
    let scheme = match ask(Select::new("Scheme:", vec!["vat", "lei", "eori", "duns"]).prompt())? {
        Some(s) => s.to_owned(),
        None => return Ok(None),
    };
    let value = match ask(Text::new("Identifier value:")
        .with_validator(Required("Identifier value"))
        .prompt())?
    {
        Some(s) => s.trim().to_owned(),
        None => return Ok(None),
    };
    let label = match ask(Text::new("Label (optional):")
        .with_help_message(skip_msg())
        .prompt())?
    {
        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Some(_) => None,
        None => return Ok(None),
    };
    let primary = ask(Confirm::new("Make this the primary identifier?")
        .with_default(false)
        .prompt())?
    .unwrap_or(false);
    Ok(Some(OperatorIdCreateParams {
        scheme,
        value,
        label,
        primary,
    }))
}

/// List operator identifiers and let the operator pick one — returns the chosen id.
async fn pick_operator_id(prompt: &str) -> Result<Option<String>> {
    let (client, cfg) = match client() {
        Ok(c) => c,
        Err(e) => {
            print_err(e);
            return Ok(None);
        }
    };
    let rows = match action_operator_id_list(&client, &cfg).await {
        Ok(r) => r,
        Err(e) => {
            print_err(e);
            return Ok(None);
        }
    };
    if rows.is_empty() {
        println!(
            "\n  {} No operator identifiers configured.\n",
            style("ℹ").cyan()
        );
        return Ok(None);
    }
    let choices: Vec<IdRow> = rows
        .iter()
        .map(|o| IdRow {
            id: o.id.clone(),
            label: format!(
                "{} {}{}",
                o.scheme,
                o.value,
                if o.is_primary { " *" } else { "" }
            ),
        })
        .collect();
    Ok(ask(Select::new(prompt, choices).prompt())?.map(|r| r.id))
}
