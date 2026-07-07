//! Infrastructure menu: status, start/stop/update the local Docker stack.

use anyhow::Result;
use console::style;
use inquire::{InquireError, Select};

use crate::{
    config::{Config, EnvKind},
    core::{
        infra::{
            action_down, action_status, action_up, action_update, compose_file, preflight_prod_env,
        },
        types::ServiceStatus,
    },
    stateless::render::render_status,
};

use super::{MenuItem, client, hint, print_err};

pub(super) async fn infrastructure() -> Result<()> {
    // Docker commands are only relevant for self-hosted nodes (localhost).
    // Hide them — and say why — when the CLI points at a remote managed node.
    let self_hosted = Config::load().map(|c| c.is_localhost()).unwrap_or(true);

    if !self_hosted {
        println!(
            "\n  {} Connected to a remote node — infrastructure is managed externally.\n",
            style("ℹ").cyan()
        );
    }

    let items: Vec<MenuItem> = {
        let mut v = vec![MenuItem::new("Status", "check health of all services")];
        if self_hosted {
            v.push(MenuItem::new("Start", "docker compose up -d"));
            v.push(MenuItem::new("Stop", "docker compose down"));
            v.push(MenuItem::new(
                "Update images",
                "pull latest container images",
            ));
        }
        v.push(MenuItem::new("← Back", ""));
        v
    };

    loop {
        match Select::new("Infrastructure — what would you like to do?", items.clone())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "Status" => match client() {
                    Ok((client, cfg)) => match action_status(&client, &cfg).await {
                        Ok(report) => {
                            println!();
                            render_status(&report);
                            let all_ok = report
                                .services
                                .iter()
                                .all(|s| matches!(s.status, ServiceStatus::Ok));
                            if !all_ok {
                                println!(
                                    "\n  {} One or more services are unhealthy.",
                                    style("⚠").yellow()
                                );
                            }
                            hint("odal status");
                            println!();
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Start" => match Config::load() {
                    Ok(cfg) => match compose_file() {
                        Ok(compose) => {
                            let safe = !matches!(cfg.kind, EnvKind::Prod)
                                || match preflight_prod_env(&compose) {
                                    Ok(()) => true,
                                    Err(e) => {
                                        print_err(e);
                                        false
                                    }
                                };
                            if safe {
                                let build = matches!(cfg.kind, EnvKind::Dev);
                                println!(
                                    "\n  {} ({})\n",
                                    if build {
                                        "Building and starting Odal Node services (first run may take a few minutes)"
                                    } else {
                                        "Starting Odal Node services"
                                    },
                                    style(compose.display()).dim()
                                );
                                match action_up(&compose, build).await {
                                    Ok(_) => {
                                        println!(
                                            "\n  {} Services started. Run Status to verify.",
                                            style("✓").green()
                                        );
                                        hint("odal up");
                                        println!();
                                    }
                                    Err(e) => print_err(e),
                                }
                            }
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Stop" => match compose_file() {
                    Ok(compose) => {
                        println!(
                            "\n  Stopping Odal Node services ({})\n",
                            style(compose.display()).dim()
                        );
                        match action_down(&compose).await {
                            Ok(_) => {
                                println!("\n  {} Services stopped.", style("✓").green());
                                hint("odal down");
                                println!();
                            }
                            Err(e) => print_err(e),
                        }
                    }
                    Err(e) => print_err(e),
                },
                "Update images" => match compose_file() {
                    Ok(compose) => {
                        println!(
                            "\n  Pulling latest images ({})\n",
                            style(compose.display()).dim()
                        );
                        match action_update(&compose).await {
                            Ok(_) => {
                                println!(
                                    "\n  {} Images updated. Run Start to restart with new images.",
                                    style("✓").green()
                                );
                                hint("odal update");
                                println!();
                            }
                            Err(e) => print_err(e),
                        }
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
