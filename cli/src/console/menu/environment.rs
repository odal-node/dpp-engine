//! Environment/profile menu: list, switch, create, and show the active profile.

use anyhow::Result;
use console::style;
use inquire::{InquireError, Select, Text};

use crate::{
    config::{self, Config, EnvKind, Profile},
    stateless::render::render_profile_banner,
};

use super::{MenuItem, ask, hint, print_err};

const ENVIRONMENT: &[MenuItem] = &[
    MenuItem::new("List", "show all profiles"),
    MenuItem::new("Switch", "change the active profile"),
    MenuItem::new("Create", "add a new profile (dev/prod)"),
    MenuItem::new("Show", "view the active profile"),
    MenuItem::new("← Back", ""),
];

pub(super) async fn environment() -> Result<()> {
    loop {
        match Select::new(
            "Environment — what would you like to do?",
            ENVIRONMENT.to_vec(),
        )
        .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
        .prompt()
        {
            Ok(item) => match item.label {
                "List" => match config::list_profiles() {
                    Ok(entries) if !entries.is_empty() => {
                        println!();
                        for e in entries {
                            let marker = if e.is_active {
                                style("●").green()
                            } else {
                                style("○").dim()
                            };
                            println!(
                                "  {} {:<14} {:<5} {}",
                                marker,
                                e.name,
                                e.profile.kind.to_string(),
                                style(&e.profile.vault_url).dim()
                            );
                        }
                        hint("odal profile list");
                        println!();
                    }
                    Ok(_) => println!("\n  No profiles yet — choose Create.\n"),
                    Err(e) => print_err(e),
                },
                "Switch" => match config::list_profiles() {
                    Ok(entries) if !entries.is_empty() => {
                        let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
                        if let Some(name) = ask(Select::new("Switch to profile:", names).prompt())?
                        {
                            match config::use_profile(&name) {
                                Ok(()) => {
                                    println!(
                                        "\n  {} Active profile is now '{name}'.\n",
                                        style("✓").green()
                                    );
                                    hint(&format!("odal profile use {name}"));
                                }
                                Err(e) => print_err(e),
                            }
                        }
                    }
                    Ok(_) => println!("\n  No profiles yet — choose Create.\n"),
                    Err(e) => print_err(e),
                },
                "Create" => {
                    let name = match ask(Text::new("Profile name:").prompt())? {
                        Some(n) => n,
                        None => continue,
                    };
                    let url = match ask(Text::new("Vault URL:")
                        .with_default("http://localhost:8001/vault")
                        .prompt())?
                    {
                        Some(u) => u,
                        None => continue,
                    };
                    let kind = EnvKind::infer(&url);
                    let profile = Profile {
                        kind,
                        vault_url: url,
                        ..Profile::default()
                    };
                    match config::create_profile(&name, profile, false) {
                        Ok(()) => {
                            println!(
                                "\n  {} Created profile '{name}' ({kind}). Use Switch to activate it.\n",
                                style("✓").green()
                            );
                            hint(&format!("odal profile create {name} --vault-url …"));
                        }
                        Err(e) => print_err(e),
                    }
                }
                "Show" => match Config::load() {
                    Ok(cfg) => {
                        println!();
                        render_profile_banner(&cfg);
                        println!(
                            "    identity : {}\n    resolver : {}\n",
                            style(&cfg.identity_url).dim(),
                            style(&cfg.resolver_url).dim()
                        );
                        hint("odal profile show");
                    }
                    Err(e) => print_err(e),
                },
                "← Back" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
