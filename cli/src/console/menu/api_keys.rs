//! API keys menu: list, create (and optionally adopt), and revoke.

use anyhow::Result;
use console::style;
use inquire::{Confirm, InquireError, Select, Text};

use crate::{
    config::Config,
    core::{
        onboarding::{action_key_create, action_key_list, action_key_revoke},
        types::{KeyCreateParams, KeyRevokeParams},
    },
    stateless::render::{render_key_create, render_key_list},
};

use super::super::validators::Required;
use super::{MenuItem, ask, client, hint, print_err};

const KEYS: &[MenuItem] = &[
    MenuItem::new("List keys", "show active keys (prefix only, no secrets)"),
    MenuItem::new("Create key", "mint a new API key (secret shown once)"),
    MenuItem::new("Revoke key", "permanently revoke a key by ID"),
    MenuItem::new("← Back", ""),
];

pub(super) async fn api_keys() -> Result<()> {
    loop {
        match Select::new("API keys — what would you like to do?", KEYS.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "List keys" => match client() {
                    Ok((client, cfg)) => match action_key_list(&client, &cfg).await {
                        Ok(keys) => {
                            println!();
                            render_key_list(&keys);
                            hint("odal key list");
                            println!();
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Create key" => {
                    let name = match ask(Text::new("Key name (label for your reference):")
                        .with_help_message("Esc to cancel")
                        .with_validator(Required("Key name"))
                        .prompt())?
                    {
                        Some(s) => s,
                        None => continue,
                    };
                    match client() {
                        Ok((client, cfg)) => {
                            match action_key_create(
                                &KeyCreateParams {
                                    name: name.trim().to_owned(),
                                },
                                &client,
                                &cfg,
                            )
                            .await
                            {
                                Ok(result) => {
                                    println!();
                                    render_key_create(&result);
                                    hint(&format!("odal key create {} --use", result.name));
                                    // Offer to adopt the new key. `create` alone
                                    // only prints the secret — it does not switch
                                    // the CLI over, so revoking the old key after
                                    // creating a new one would lock you out.
                                    let adopt = ask(Confirm::new(
                                        "Set this as your active key for this profile?",
                                    )
                                    .with_default(false)
                                    .prompt())?
                                    .unwrap_or(false);
                                    if adopt {
                                        match Config::load() {
                                            Ok(mut c) => {
                                                c.api_key = result.secret.clone();
                                                match c.save() {
                                                    Ok(()) => println!(
                                                        "\n  {} Active key updated.\n",
                                                        style("✓").green()
                                                    ),
                                                    Err(e) => print_err(e),
                                                }
                                            }
                                            Err(e) => print_err(e),
                                        }
                                    } else {
                                        println!();
                                    }
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
                    }
                }
                "Revoke key" => {
                    let id = match ask(Text::new("Key ID to revoke:")
                        .with_help_message("Esc to cancel")
                        .with_validator(Required("Key ID"))
                        .prompt())?
                    {
                        Some(s) => s.trim().to_owned(),
                        None => continue,
                    };
                    let confirmed =
                        match ask(Confirm::new(&format!("Revoke key {id}? Cannot be undone."))
                            .with_default(false)
                            .prompt())?
                        {
                            Some(b) => b,
                            None => continue,
                        };
                    if !confirmed {
                        continue;
                    }
                    match client() {
                        Ok((client, cfg)) => {
                            match action_key_revoke(
                                &KeyRevokeParams { id: id.clone() },
                                &client,
                                &cfg,
                            )
                            .await
                            {
                                Ok(_) => {
                                    println!("\n  {} Key {id} revoked.", style("✓").green());
                                    hint(&format!("odal key revoke {id}"));
                                    println!();
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
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
