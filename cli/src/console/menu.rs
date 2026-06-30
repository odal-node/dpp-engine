//! The interactive console's main menu and event loop.

use anyhow::Result;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Confirm, InquireError, Select, Text};

use super::setup::run_setup;
use super::validators::{
    Required, valid_import_file, valid_optional_country, valid_optional_days, valid_optional_email,
    valid_optional_url,
};

use crate::{
    config::{self, Config, EnvKind, Profile},
    core::{
        infra::{
            action_down, action_status, action_up, action_update, compose_file, preflight_prod_env,
        },
        onboarding::{
            action_key_create, action_key_list, action_key_revoke, action_operator_set,
            action_operator_show,
        },
        passport::{
            action_archive, action_export, action_get, action_history, action_import, action_list,
            action_publish, action_suspend, action_validate,
        },
        registry_identity::{
            FacilityCreateParams, OperatorIdCreateParams, action_facility_add,
            action_facility_list, action_facility_remove, action_facility_set_default,
            action_operator_id_add, action_operator_id_list, action_operator_id_remove,
            action_operator_id_set_primary,
        },
        schema::action_schema_check,
        types::{
            ArchiveParams, ExportParams, HistoryParams, ImportParams, KeyCreateParams,
            KeyRevokeParams, ListParams, OperatorUpdateParams, PassportSummary, ProgressEvent,
            PublishParams, ServiceStatus, SuspendParams,
        },
    },
    http::OdalClient,
    stateless::render::{
        render_export, render_history, render_import_result, render_key_create, render_key_list,
        render_operator, render_passport_details, render_profile_banner, render_publish_summary,
        render_schema_check, render_status, render_validation_report,
    },
};

// ── Menu item ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MenuItem {
    label: &'static str,
    hint: &'static str,
}

impl MenuItem {
    const fn new(label: &'static str, hint: &'static str) -> Self {
        Self { label, hint }
    }
}

impl std::fmt::Display for MenuItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.hint.is_empty() {
            write!(f, "{}", self.label)
        } else {
            write!(f, "{:<26}{}", self.label, self.hint)
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn print_header() {
    println!();
    println!(
        "  {} {}  {}",
        style("⬢").cyan().bold(),
        style("Odal Node — Management Console").bold(),
        style(env!("CARGO_PKG_VERSION")).dim()
    );
    if let Ok(cfg) = Config::load() {
        render_profile_banner(&cfg);
        if cfg.api_key.is_empty() {
            println!(
                "  {} Not configured — select {} to complete setup.",
                style("⚠").yellow(),
                style("Setup / Reconfigure").cyan()
            );
        }
    }
    println!();
}

/// Print an error with a plain-language remedy when the cause is recognisable.
fn print_err(e: impl std::fmt::Display) {
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    let remedy: Option<&str> = if lower.contains("connection refused")
        || lower.contains("actively refused")
    {
        Some("Vault isn't running — choose Infrastructure › Start, or run `odal up`.")
    } else if lower.contains("timed out") || lower.contains("timeout") {
        Some("Request timed out — check that the node is reachable at the configured vault URL.")
    } else if lower.contains("dns")
        || lower.contains("no such host")
        || lower.contains("failed to lookup")
    {
        Some("DNS lookup failed — check the vault URL in ~/.config/odal/config.toml.")
    } else if lower.contains("401") || lower.contains("unauthorized") {
        Some(
            "API key rejected — it may have been revoked or expired. Mint a fresh key with `odal bootstrap --force` (or Setup / Reconfigure), or run `odal key use <secret>` if you already hold a valid one.",
        )
    } else if lower.contains("403") || lower.contains("forbidden") {
        Some("Permission denied — your API key may lack the required scope.")
    } else if lower.contains("404") || lower.contains("not found") {
        Some("Not found — verify the ID is correct.")
    } else {
        None
    };
    println!("\n  {} {}", style("✗").red(), msg);
    if let Some(r) = remedy {
        println!("  {} {}", style("→").dim(), r);
    }
    println!();
}

fn client() -> Result<(OdalClient, Config)> {
    Config::load().map(|cfg| (OdalClient::new(&cfg.api_key), cfg))
}

fn hint(cmd: &str) {
    println!("  {}", style(format!("≡ {cmd}")).dim());
}

fn skip_msg() -> &'static str {
    "Press Enter to skip · Esc to cancel"
}

fn ask<T>(result: inquire::error::InquireResult<T>) -> anyhow::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// ── Top-level event loop ──────────────────────────────────────────────────────

const TOP: &[MenuItem] = &[
    MenuItem::new("Infrastructure", "start · stop · status · update images"),
    MenuItem::new("Passports", "import · validate · publish · export"),
    MenuItem::new("Operator", "view · edit configuration"),
    MenuItem::new("Registry identity", "facilities · operator identifiers"),
    MenuItem::new("API keys", "create · list · revoke"),
    MenuItem::new("Environment", "switch · create · view profiles (dev/prod)"),
    MenuItem::new("Schema", "check for updates"),
    MenuItem::new(
        "Setup / Reconfigure",
        "connect · start · onboard · first key",
    ),
    MenuItem::new("Quit", ""),
];

pub async fn event_loop() -> Result<()> {
    // First run: auto-enter setup when no API key is configured.
    if Config::load().map(|c| c.api_key.is_empty()).unwrap_or(true) {
        let _ = run_setup().await;
    }

    loop {
        print_header();
        match Select::new("What would you like to do?", TOP.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to quit")
            .prompt()
        {
            Ok(item) => match item.label {
                "Infrastructure" => infrastructure().await?,
                "Passports" => passports().await?,
                "Operator" => operator().await?,
                "Registry identity" => registry_identity().await?,
                "API keys" => api_keys().await?,
                "Environment" => environment().await?,
                "Schema" => schema().await?,
                "Setup / Reconfigure" => {
                    let _ = run_setup().await;
                }
                "Quit" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    println!("\n  {} Goodbye.\n", style("⬢").cyan().bold());
    Ok(())
}

// ── Infrastructure ────────────────────────────────────────────────────────────

async fn infrastructure() -> Result<()> {
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

// ── Environment / profiles ──────────────────────────────────────────────────────

const ENVIRONMENT: &[MenuItem] = &[
    MenuItem::new("List", "show all profiles"),
    MenuItem::new("Switch", "change the active profile"),
    MenuItem::new("Create", "add a new profile (dev/prod)"),
    MenuItem::new("Show", "view the active profile"),
    MenuItem::new("← Back", ""),
];

async fn environment() -> Result<()> {
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

// ── Passports ─────────────────────────────────────────────────────────────────

const PASSPORTS: &[MenuItem] = &[
    MenuItem::new("Browse / search", "list passports and act on one"),
    MenuItem::new("Import", "create draft passports from a file"),
    MenuItem::new("Validate", "check drafts for missing fields"),
    MenuItem::new("Publish all drafts", "sign and publish every draft"),
    // Per-passport lifecycle is now done via Browse → select → act (no UUID
    // typing). These standalone, ID-prompt items are kept (commented) in case we
    // want a future bulk multi-select flow; the stateless `odal passport
    // suspend|archive|history <id>` commands remain available for scripting.
    // MenuItem::new("Suspend", "serve 410 Gone for a passport"),
    // MenuItem::new("Archive", "permanently archive a passport"),
    // MenuItem::new("History", "show a passport's audit trail"),
    MenuItem::new("Export", "export passports to JSON or CSV"),
    MenuItem::new("← Back", ""),
];

async fn passports() -> Result<()> {
    loop {
        match Select::new("Passports — what would you like to do?", PASSPORTS.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "Browse / search" => browse_passports().await?,
                "Import" => {
                    let (client, cfg) = match client() {
                        Ok(c) => c,
                        Err(e) => {
                            print_err(e);
                            continue;
                        }
                    };
                    let file = match prompt_import_file(cfg.is_localhost()).await? {
                        Some(f) => f,
                        None => continue,
                    };
                    let params = ImportParams { file: file.clone() };
                    let pb = ProgressBar::new(0);
                    pb.set_style(
                        ProgressStyle::with_template(
                            "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len}",
                        )
                        .unwrap()
                        .progress_chars("=>-"),
                    );
                    let pb2 = pb.clone();
                    let progress = move |evt: ProgressEvent| match evt {
                        ProgressEvent::Started { total } => {
                            if let Some(t) = total {
                                pb2.set_length(t);
                            }
                        }
                        ProgressEvent::Tick { current } => pb2.set_position(current),
                        ProgressEvent::Done => pb2.finish_and_clear(),
                    };
                    println!();
                    match action_import(&params, &client, &cfg, Some(&progress)).await {
                        Ok(summary) => {
                            render_import_result(&summary, &file);
                            hint(&format!("odal passport import {file}"));
                            if summary.created > 0 {
                                println!();
                                let plural = if summary.created == 1 { "" } else { "s" };
                                let validate_now = ask(Confirm::new(&format!(
                                    "Validate your {} new draft{plural} now?",
                                    summary.created
                                ))
                                .with_default(true)
                                .prompt())?
                                .unwrap_or(false);
                                if validate_now {
                                    run_validate_inline(&client, &cfg).await?;
                                }
                            }
                            println!();
                        }
                        Err(e) => print_err(e),
                    }
                }
                "Validate" => match client() {
                    Ok((client, cfg)) => {
                        run_validate_inline(&client, &cfg).await?;
                        println!();
                    }
                    Err(e) => print_err(e),
                },
                "Publish all drafts" => {
                    println!(
                        "\n  {} This signs and publishes {} draft passports with your Ed25519 key,\n  making them publicly verifiable. Retention periods (e.g. 10 years for\n  batteries) are locked at publish time.\n  {} To publish just one, use Browse / search → select it → Publish.",
                        style("ℹ").cyan(),
                        style("all").bold(),
                        style("→").dim()
                    );
                    let confirmed = match ask(Confirm::new("Publish all draft passports?")
                        .with_default(true)
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
                            println!("\n  Publishing all draft passports...");
                            match action_publish(&PublishParams { id: None }, &client, &cfg).await {
                                Ok(summary) => {
                                    println!();
                                    render_publish_summary(&summary, false);
                                    hint("odal passport publish");
                                    println!();
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
                    }
                }
                /* Per-passport lifecycle is handled by Browse → select → act (no UUID
                   typing). Kept here, commented, in case we want a future bulk
                   multi-select flow; the stateless `odal passport suspend|archive|
                   history <id>` commands remain available for scripting.
                "Suspend" => {
                    let id = match ask(Text::new("Passport ID to suspend:")
                        .with_help_message("Esc to cancel")
                        .with_validator(Required("Passport ID"))
                        .prompt())?
                    {
                        Some(s) => s.trim().to_owned(),
                        None => continue,
                    };
                    println!(
                        "\n  {} Suspending causes public QR scans to return 410 Gone immediately.\n  The passport stays in your system and can be re-published.",
                        style("⚠").yellow()
                    );
                    let confirmed = match ask(Confirm::new(&format!("Suspend passport {id}?"))
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
                            match action_suspend(&SuspendParams { id: id.clone() }, &client, &cfg)
                                .await
                            {
                                Ok(_) => {
                                    println!("\n  {} Passport {id} suspended.", style("✓").green());
                                    hint(&format!("odal passport suspend {id}"));
                                    println!();
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
                    }
                }
                "Archive" => {
                    let id = match ask(Text::new("Passport ID to archive:")
                        .with_help_message("Esc to cancel")
                        .with_validator(Required("Passport ID"))
                        .prompt())?
                    {
                        Some(s) => s.trim().to_owned(),
                        None => continue,
                    };
                    println!(
                        "\n  {} Archiving is permanent and cannot be undone.\n  The passport will be permanently removed from public circulation.",
                        style("⚠").red()
                    );
                    let confirmed =
                        match ask(Confirm::new(&format!("Archive passport {id} permanently?"))
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
                            match action_archive(&ArchiveParams { id: id.clone() }, &client, &cfg)
                                .await
                            {
                                Ok(_) => {
                                    println!("\n  {} Passport {id} archived.", style("✓").green());
                                    hint(&format!("odal passport archive {id}"));
                                    println!();
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
                    }
                }
                "History" => {
                    let id = match ask(Text::new("Passport ID:")
                        .with_help_message("Esc to cancel")
                        .with_validator(Required("Passport ID"))
                        .prompt())?
                    {
                        Some(s) => s.trim().to_owned(),
                        None => continue,
                    };
                    match client() {
                        Ok((client, cfg)) => {
                            match action_history(&HistoryParams { id: id.clone() }, &client, &cfg)
                                .await
                            {
                                Ok(entries) => {
                                    println!();
                                    render_history(&entries, &id);
                                    hint(&format!("odal passport history {id}"));
                                    println!();
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
                    }
                }
                */
                "Export" => {
                    let fmt_choice = match ask(Select::new("Format?", vec!["JSON", "CSV"]).prompt())?
                    {
                        Some(f) => f.to_lowercase(),
                        None => continue,
                    };
                    let status_input = match ask(Text::new("Filter by status (blank = all):")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) => s,
                        None => continue,
                    };
                    let output_input = match ask(Text::new("Output file (blank = print here):")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) => s,
                        None => continue,
                    };
                    let status_filter = if status_input.trim().is_empty() {
                        None
                    } else {
                        Some(status_input.trim().to_owned())
                    };
                    let output_path = if output_input.trim().is_empty() {
                        None
                    } else {
                        Some(output_input.trim().to_owned())
                    };
                    match client() {
                        Ok((client, cfg)) => {
                            let params = ExportParams {
                                format: fmt_choice.clone(),
                                status_filter,
                            };
                            match action_export(&params, &client, &cfg).await {
                                Ok(result) => {
                                    println!();
                                    if let Err(e) = render_export(&result, output_path.as_deref()) {
                                        print_err(e);
                                    } else {
                                        let cmd = match &output_path {
                                            Some(p) => format!(
                                                "odal passport export --format {fmt_choice} -o {p}"
                                            ),
                                            None => format!(
                                                "odal passport export --format {fmt_choice}"
                                            ),
                                        };
                                        hint(&cmd);
                                        println!();
                                    }
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

/// Choose an import file. On a local node we open the native OS file picker so
/// the operator browses their whole machine — no `../../../` path typing. The
/// typed-path prompt stays as the fallback: it's the only sensible option for a
/// remote node, and the safety net if the dialog can't open (localhost reached
/// over SSH, no display, or the operator cancels the dialog).
async fn prompt_import_file(self_hosted: bool) -> Result<Option<String>> {
    if !self_hosted {
        return prompt_import_path_text();
    }
    match ask(
        Select::new("Choose your import file:", vec!["Browse…", "Type a path"])
            .with_help_message("↑↓ · ⏎ select · Esc to cancel")
            .prompt(),
    )? {
        Some("Browse…") => match super::file_picker::pick_import_file().await {
            Some(path) => {
                super::file_picker::remember_dir(&path);
                Ok(Some(path.to_string_lossy().into_owned()))
            }
            None => prompt_import_path_text(),
        },
        Some(_) => prompt_import_path_text(),
        None => Ok(None),
    }
}

/// The classic typed-path prompt, validated to an existing csv/tsv/json file.
fn prompt_import_path_text() -> Result<Option<String>> {
    ask(Text::new("Path to CSV, TSV, or JSON file:")
        .with_help_message("Esc to cancel")
        .with_validator(valid_import_file)
        .prompt())
}

// ── Browse / search ───────────────────────────────────────────────────────────

/// A selectable row in the browser: a passport to act on, or a control.
#[derive(Clone)]
enum BrowseChoice {
    Passport(PassportSummary),
    NextPage,
    Back,
}

impl std::fmt::Display for BrowseChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowseChoice::Passport(p) => write!(
                f,
                "{} {:<9} {:<30} {:<9} {}",
                status_dot(&p.status),
                p.status,
                truncate_label(&p.product_name, 30),
                p.sector,
                p.batch.as_deref().unwrap_or("—"),
            ),
            BrowseChoice::NextPage => write!(f, "{}", style("→ Next page").cyan()),
            BrowseChoice::Back => write!(f, "← Back"),
        }
    }
}

/// Colour-coded status dot (alignment-safe: always one visible glyph).
fn status_dot(status: &str) -> String {
    let dot = match status {
        "draft" => style("●").dim(),
        "active" => style("●").green(),
        "suspended" => style("●").yellow(),
        "archived" => style("●").red(),
        _ => style("●").white(),
    };
    dot.to_string()
}

fn truncate_label(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

/// Equivalent stateless command for the current filter/search, shown as a hint.
fn browse_hint(status: &Option<String>, q: &Option<String>) -> String {
    let mut cmd = String::from("odal passport list");
    if let Some(s) = status {
        cmd.push_str(&format!(" --status {s}"));
    }
    if let Some(query) = q {
        cmd.push_str(&format!(" --q \"{query}\""));
    }
    cmd
}

/// Browse / search passports, then act on a selected one — the operator never
/// types or copies a UUID.
async fn browse_passports() -> Result<()> {
    let (client, cfg) = match client() {
        Ok(c) => c,
        Err(e) => {
            print_err(e);
            return Ok(());
        }
    };

    let status = match ask(Select::new(
        "Filter by status:",
        vec!["All", "Draft", "Active", "Suspended", "Archived"],
    )
    .with_help_message("↑↓ · ⏎ select · Esc to go back")
    .prompt())?
    {
        Some("All") => None,
        Some(s) => Some(s.to_lowercase()),
        None => return Ok(()),
    };

    let q = match ask(Text::new("Search (product · batch · manufacturer):")
        .with_help_message(skip_msg())
        .prompt())?
    {
        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Some(_) => None,
        None => return Ok(()),
    };

    const PAGE: u32 = 50;
    let mut skip = 0u32;
    loop {
        let params = ListParams {
            status: status.clone(),
            q: q.clone(),
            facility_id: None,
            limit: PAGE,
            skip,
        };
        let page = match action_list(&params, &client, &cfg).await {
            Ok(p) => p,
            Err(e) => {
                print_err(e);
                return Ok(());
            }
        };

        if page.rows.is_empty() {
            println!("\n  {} No passports match.\n", style("ℹ").cyan());
            hint(&browse_hint(&status, &q));
            println!();
            return Ok(());
        }

        let shown = skip as u64 + page.rows.len() as u64;
        let mut choices: Vec<BrowseChoice> = page
            .rows
            .iter()
            .cloned()
            .map(BrowseChoice::Passport)
            .collect();
        if page.has_more {
            choices.push(BrowseChoice::NextPage);
        }
        choices.push(BrowseChoice::Back);

        // `total` is only meaningful without a text search (vault count ignores q).
        let counted = if q.is_some() {
            format!("{} match", page.rows.len())
        } else {
            format!("{}–{} of {}", skip + 1, shown, page.total)
        };
        let header = format!("Passports {counted}  (⏎ to act on one)");
        match ask(Select::new(&header, choices)
            .with_help_message("↑↓ · ⏎ select · Esc to go back")
            .prompt())?
        {
            Some(BrowseChoice::Passport(p)) => passport_actions(&client, &cfg, &p).await?,
            Some(BrowseChoice::NextPage) => skip += PAGE,
            Some(BrowseChoice::Back) | None => return Ok(()),
        }
    }
}

/// Per-passport action menu, gated by status. Reuses the core lifecycle actions
/// against the selected passport's id, so no id is ever typed.
async fn passport_actions(client: &OdalClient, cfg: &Config, p: &PassportSummary) -> Result<()> {
    loop {
        let mut items = vec!["View details", "History"];
        match p.status.as_str() {
            "draft" => items.push("Publish"),
            "active" => {
                items.push("Suspend");
                items.push("Archive");
            }
            "suspended" => items.push("Archive"),
            _ => {} // archived: terminal
        }
        items.push("← Back");

        let header = format!("{}  [{}]", p.product_name, p.status);
        let choice = match ask(Select::new(&header, items)
            .with_help_message("↑↓ · ⏎ select · Esc to go back")
            .prompt())?
        {
            Some(c) => c,
            None => return Ok(()),
        };

        match choice {
            "View details" => match action_get(&p.id, client, cfg).await {
                Ok(doc) => {
                    println!();
                    render_passport_details(&doc);
                    println!();
                }
                Err(e) => print_err(e),
            },
            "History" => {
                match action_history(&HistoryParams { id: p.id.clone() }, client, cfg).await {
                    Ok(entries) => {
                        println!();
                        render_history(&entries, &p.id);
                        hint(&format!("odal passport history {}", p.id));
                        println!();
                    }
                    Err(e) => print_err(e),
                }
            }
            "Publish" => {
                println!(
                    "\n  {} Publishing signs this draft with your Ed25519 key and makes it publicly verifiable.",
                    style("ℹ").cyan()
                );
                let ok = ask(Confirm::new(&format!("Publish \"{}\"?", p.product_name))
                    .with_default(true)
                    .prompt())?
                .unwrap_or(false);
                if ok {
                    match action_publish(
                        &PublishParams {
                            id: Some(p.id.clone()),
                        },
                        client,
                        cfg,
                    )
                    .await
                    {
                        Ok(summary) => {
                            println!();
                            render_publish_summary(&summary, true);
                            hint(&format!("odal passport publish {}", p.id));
                            println!();
                        }
                        Err(e) => print_err(e),
                    }
                    return Ok(()); // status changed — return to the refreshed list
                }
            }
            "Suspend" => {
                println!(
                    "\n  {} Suspending makes public QR scans return 410 Gone. It can be re-published later.",
                    style("⚠").yellow()
                );
                let ok = ask(Confirm::new(&format!("Suspend \"{}\"?", p.product_name))
                    .with_default(false)
                    .prompt())?
                .unwrap_or(false);
                if ok {
                    match action_suspend(&SuspendParams { id: p.id.clone() }, client, cfg).await {
                        Ok(_) => {
                            println!("\n  {} Suspended.", style("✓").green());
                            hint(&format!("odal passport suspend {}", p.id));
                            println!();
                        }
                        Err(e) => print_err(e),
                    }
                    return Ok(());
                }
            }
            "Archive" => {
                println!(
                    "\n  {} Archiving is permanent and removes the passport from public circulation.",
                    style("⚠").red()
                );
                let ok = ask(Confirm::new(&format!(
                    "Archive \"{}\" permanently?",
                    p.product_name
                ))
                .with_default(false)
                .prompt())?
                .unwrap_or(false);
                if ok {
                    match action_archive(&ArchiveParams { id: p.id.clone() }, client, cfg).await {
                        Ok(_) => {
                            println!("\n  {} Archived.", style("✓").green());
                            hint(&format!("odal passport archive {}", p.id));
                            println!();
                        }
                        Err(e) => print_err(e),
                    }
                    return Ok(());
                }
            }
            "← Back" => return Ok(()),
            _ => {}
        }
    }
}

/// Shared validate + "publish now?" suggestion, used by both the Validate menu item
/// and the post-Import suggestion.
async fn run_validate_inline(client: &OdalClient, cfg: &Config) -> Result<()> {
    match action_validate(client, cfg).await {
        Ok(report) => {
            println!();
            render_validation_report(&report);
            let has_issues = report.records.iter().any(|r| !r.issues.is_empty());
            if has_issues {
                println!(
                    "\n  {} Some DPPs have validation issues.",
                    style("⚠").yellow()
                );
            }
            hint("odal passport validate");
            if !has_issues && !report.records.is_empty() {
                println!();
                let publish_now = ask(Confirm::new("All drafts pass — publish them now?")
                    .with_default(false)
                    .prompt())?
                .unwrap_or(false);
                if publish_now {
                    println!(
                        "\n  {} Publishing signs your drafts with your Ed25519 key and locks retention periods.",
                        style("ℹ").cyan()
                    );
                    let params = PublishParams { id: None };
                    match action_publish(&params, client, cfg).await {
                        Ok(summary) => {
                            println!();
                            render_publish_summary(&summary, false);
                            hint("odal passport publish");
                        }
                        Err(e) => print_err(e),
                    }
                }
            }
        }
        Err(e) => print_err(e),
    }
    Ok(())
}

// ── Operator ──────────────────────────────────────────────────────────────────

const OPERATOR: &[MenuItem] = &[
    MenuItem::new("View configuration", "show current operator details"),
    MenuItem::new(
        "Edit configuration",
        "update legal name, country, contact, etc.",
    ),
    MenuItem::new("← Back", ""),
];

async fn operator() -> Result<()> {
    loop {
        match Select::new("Operator — what would you like to do?", OPERATOR.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "View configuration" => match client() {
                    Ok((client, cfg)) => match action_operator_show(&client, &cfg).await {
                        Ok(v) => {
                            println!();
                            if let Err(e) = render_operator(&v) {
                                print_err(e);
                            } else {
                                hint("odal operator show");
                                println!();
                            }
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Edit configuration" => {
                    println!(
                        "\n  {} Leave fields blank to keep the current value.\n",
                        style("ℹ").cyan()
                    );

                    let legal_name = match ask(Text::new("Legal name:")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let trade_name = match ask(Text::new("Trade name:")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let address = match ask(Text::new("Registered address:")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let country = match ask(Text::new("Country (ISO 3166-1 alpha-2, e.g. DE):")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_country)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_ascii_uppercase()),
                        Some(_) => None,
                        None => continue,
                    };
                    let contact_email = match ask(Text::new("Contact email:")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_email)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let did_web_url = match ask(Text::new("did:web URL:")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_url)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    // validator guarantees non-empty input parses successfully
                    let retention_policy_days = match ask(Text::new("Retention policy (days):")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_days)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().parse::<i64>().unwrap()),
                        Some(_) => None,
                        None => continue,
                    };

                    let params = OperatorUpdateParams {
                        legal_name,
                        trade_name,
                        address,
                        country,
                        contact_email,
                        did_web_url,
                        retention_policy_days,
                    };
                    if params.is_empty() {
                        println!(
                            "\n  {} Nothing to update — all fields were left blank.\n",
                            style("ℹ").cyan()
                        );
                        continue;
                    }
                    match client() {
                        Ok((client, cfg)) => {
                            match action_operator_set(&params, &client, &cfg).await {
                                Ok(_) => {
                                    println!("\n  {} Operator updated.", style("✓").green());
                                    hint("odal operator set ...");
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

// ── API keys ──────────────────────────────────────────────────────────────────

const KEYS: &[MenuItem] = &[
    MenuItem::new("List keys", "show active keys (prefix only, no secrets)"),
    MenuItem::new("Create key", "mint a new API key (secret shown once)"),
    MenuItem::new("Revoke key", "permanently revoke a key by ID"),
    MenuItem::new("← Back", ""),
];

async fn api_keys() -> Result<()> {
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

// ── Registry identity (facilities + operator identifiers) ──────────────────────

/// A selectable id row: shows a human label, carries the id to act on.
#[derive(Clone)]
struct IdRow {
    id: String,
    label: String,
}

impl std::fmt::Display for IdRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

const REGISTRY_IDENTITY: &[MenuItem] = &[
    MenuItem::new("Facilities", "ESPR Annex III — manufacturing sites"),
    MenuItem::new("Operator identifiers", "ESPR Art. 13 — EORI/VAT/LEI/DUNS"),
    MenuItem::new("← Back", ""),
];

async fn registry_identity() -> Result<()> {
    loop {
        match Select::new(
            "Registry identity — what would you like to do?",
            REGISTRY_IDENTITY.to_vec(),
        )
        .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
        .prompt()
        {
            Ok(item) => match item.label {
                "Facilities" => facilities_menu().await?,
                "Operator identifiers" => operator_ids_menu().await?,
                "← Back" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

const FACILITIES: &[MenuItem] = &[
    MenuItem::new("List", "show configured facilities (default marked *)"),
    MenuItem::new("Add", "add a facility (e.g. a GLN)"),
    MenuItem::new("Set default", "choose which facility new passports use"),
    MenuItem::new("Remove", "delete a facility"),
    MenuItem::new("← Back", ""),
];

async fn facilities_menu() -> Result<()> {
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

const OPERATOR_IDS: &[MenuItem] = &[
    MenuItem::new("List", "show operator identifiers (primary marked *)"),
    MenuItem::new("Add", "add an identifier (EORI/VAT/LEI/DUNS)"),
    MenuItem::new("Set primary", "choose which identifier new passports use"),
    MenuItem::new("Remove", "delete an identifier"),
    MenuItem::new("← Back", ""),
];

async fn operator_ids_menu() -> Result<()> {
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

// ── Schema ────────────────────────────────────────────────────────────────────

const SCHEMA: &[MenuItem] = &[
    MenuItem::new(
        "Check for updates",
        "compare local schema version with upstream",
    ),
    MenuItem::new("← Back", ""),
];

async fn schema() -> Result<()> {
    loop {
        match Select::new("Schema — what would you like to do?", SCHEMA.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "Check for updates" => match client() {
                    Ok((client, cfg)) => match action_schema_check(&client, &cfg).await {
                        Ok(result) => {
                            println!();
                            render_schema_check(&result);
                            hint("odal schema check");
                            println!();
                        }
                        Err(e) => print_err(e),
                    },
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
