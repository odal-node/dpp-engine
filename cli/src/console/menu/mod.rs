//! The interactive console's main menu and event loop.

mod api_keys;
mod environment;
mod facilities;
mod infrastructure;
mod operator;
mod operator_ids;
mod passports;
mod registry_identity;
mod schema;

use anyhow::Result;
use console::style;
use inquire::{InquireError, Select};

use super::setup::run_setup;

use crate::config::Config;

// ── Menu item ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(super) struct MenuItem {
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

/// A selectable row shared by the facilities and operator-identifiers pickers.
pub(super) struct IdRow {
    pub(super) id: String,
    pub(super) label: String,
}

impl std::fmt::Display for IdRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
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
        crate::stateless::render::render_profile_banner(&cfg);
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
pub(super) fn print_err(e: impl std::fmt::Display) {
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

pub(super) fn client() -> Result<(crate::http::OdalClient, Config)> {
    Config::load().map(|cfg| (crate::http::OdalClient::new(&cfg.api_key), cfg))
}

pub(super) fn hint(cmd: &str) {
    println!("  {}", style(format!("≡ {cmd}")).dim());
}

pub(super) fn skip_msg() -> &'static str {
    "Press Enter to skip · Esc to cancel"
}

pub(super) fn ask<T>(result: inquire::error::InquireResult<T>) -> anyhow::Result<Option<T>> {
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
                "Infrastructure" => infrastructure::infrastructure().await?,
                "Passports" => passports::passports().await?,
                "Operator" => operator::operator().await?,
                "Registry identity" => registry_identity::registry_identity().await?,
                "API keys" => api_keys::api_keys().await?,
                "Environment" => environment::environment().await?,
                "Schema" => schema::schema().await?,
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
