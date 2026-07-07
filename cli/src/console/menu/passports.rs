//! Passports menu: browse/search, import, validate, publish, export, and the
//! per-passport action menu reached from Browse.

use anyhow::Result;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Confirm, InquireError, Select, Text};

use crate::{
    core::{
        passport::{
            action_archive, action_export, action_get, action_history, action_import, action_list,
            action_publish, action_suspend, action_validate,
        },
        types::{
            ArchiveParams, ExportParams, HistoryParams, ImportParams, ListParams, PassportSummary,
            ProgressEvent, PublishParams, SuspendParams,
        },
    },
    http::OdalClient,
    stateless::render::{
        render_export, render_history, render_import_result, render_passport_details,
        render_publish_summary, render_validation_report,
    },
};

use super::super::validators::valid_import_file;
use super::{MenuItem, ask, client, hint, print_err, skip_msg};

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

pub(super) async fn passports() -> Result<()> {
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
        Some("Browse…") => match super::super::file_picker::pick_import_file().await {
            Some(path) => {
                super::super::file_picker::remember_dir(&path);
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
async fn passport_actions(
    client: &OdalClient,
    cfg: &crate::config::Config,
    p: &PassportSummary,
) -> Result<()> {
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
async fn run_validate_inline(client: &OdalClient, cfg: &crate::config::Config) -> Result<()> {
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
