//! Presentation-free outcome types are rendered here.  Every public function
//! in this module accepts a typed outcome from `core/` and writes to stdout
//! (or a file for export).  No business logic lives here — callers decide
//! whether to bail based on the same outcome value.

use std::io::Write as _;

use anyhow::Result;
use console::style;
use dpp_evidence::{CheckStatus, VerificationReport};

use crate::config::{Config, EnvKind};
use crate::core::types::{
    AuditEntry, BootstrapResult, ExportResult, ImportSummary, KeyCreateResult, KeyEntry,
    PassportPage, PublishSummary, SchemaCheckResult, ServiceStatus, StatusReport, ValidationReport,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

// ── Environment banner ─────────────────────────────────────────────────────────

/// Print the active profile + environment kind so the operator always knows
/// which node they are pointed at. Prod is rendered loudly (red); dev quietly.
pub fn render_profile_banner(cfg: &Config) {
    match cfg.kind {
        EnvKind::Prod => println!(
            "  {} {}  {}",
            style("●").red().bold(),
            style(format!("{} · prod", cfg.name)).red().bold(),
            style(&cfg.vault_url).dim(),
        ),
        EnvKind::Dev => println!(
            "  {} {}  {}",
            style("○").green(),
            style(format!("{} · dev", cfg.name)).green(),
            style(&cfg.vault_url).dim(),
        ),
    }
}

// ── Infrastructure ───────────────────────────────────────────────────────────

pub fn render_status(report: &StatusReport) {
    println!("{:<12} {:<38} {:<8} LATENCY", "SERVICE", "URL", "STATUS");
    println!("{}", "─".repeat(72));
    for svc in &report.services {
        let url = truncate(&svc.url, 38);
        // HTTP checks carry a round-trip latency; container checks don't.
        let latency = match svc.latency_ms {
            Some(ms) => format!("{ms}ms"),
            None => String::new(),
        };
        match &svc.status {
            ServiceStatus::Ok => {
                println!("{:<12} {:<38} {:<8} {}", svc.name, url, "OK", latency)
            }
            ServiceStatus::HttpError(code) => println!(
                "{:<12} {:<38} {:<8} {}",
                svc.name,
                url,
                format!("HTTP {code}"),
                latency
            ),
            ServiceStatus::Failed(reason) => {
                println!("{:<12} {:<38} {:<8} {}", svc.name, url, "FAIL", reason);
            }
        }
    }
}

// ── Passports ────────────────────────────────────────────────────────────────

pub fn render_passport_list(page: &PassportPage) {
    if page.rows.is_empty() {
        println!("No passports found.");
        return;
    }
    println!(
        "{:<10} {:<32} {:<9} {:<18} UPDATED",
        "STATUS", "PRODUCT", "SECTOR", "BATCH/REF"
    );
    println!("{}", "─".repeat(86));
    for r in &page.rows {
        println!(
            "{:<10} {:<32} {:<9} {:<18} {}",
            r.status,
            truncate(&r.product_name, 32),
            r.sector,
            r.batch.as_deref().unwrap_or("—"),
            r.updated
        );
    }
    print!("\n{} shown", page.rows.len());
    if page.has_more {
        print!(" — more available (raise --limit, or use the console's Browse to page)");
    }
    println!(".");
}

/// Formatted detail block for a single passport doc (used by the console
/// browser's "View details"). Shows the full ID and QR link.
pub fn render_passport_details(doc: &serde_json::Value) {
    let s = |k: &str| doc.get(k).and_then(|v| v.as_str());
    let line = |label: &str, val: &str| println!("  {:<14}{}", format!("{label}:"), val);

    line("Product", s("productName").unwrap_or("—"));
    line("Status", s("status").unwrap_or("—"));
    line("Sector", s("sector").unwrap_or("—"));
    line("Batch / ref", s("batchId").unwrap_or("—"));
    if let Some(name) = doc
        .get("manufacturer")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
    {
        line("Manufacturer", name);
    }
    // Registry identity stamped on create (ESPR Annex III facility / Art. 13 operator id).
    // The facility is a self-contained snapshot { scheme, value, name, country, address };
    // show "name (value)" when both are present, else whichever exists.
    if let Some(facility) = doc.get("facility").filter(|v| v.is_object()) {
        let fs = |k: &str| facility.get(k).and_then(|v| v.as_str());
        let display = match (fs("name"), fs("value")) {
            (Some(name), Some(value)) => format!("{name} ({value})"),
            (Some(name), None) => name.to_owned(),
            (None, Some(value)) => value.to_owned(),
            (None, None) => String::new(),
        };
        if !display.is_empty() {
            line("Facility", &display);
        }
    }
    if let Some(o) = s("operatorIdentifier") {
        line("Operator ID", o);
    }
    line("ID", s("id").unwrap_or("—"));
    if let Some(qr) = s("qrCodeUrl") {
        line("QR / link", qr);
    }
    if let Some(p) = s("publishedAt") {
        line("Published", p);
    }
    if let Some(r) = s("retentionUntil") {
        line("Retention to", r);
    }
}

pub fn render_import_result(summary: &ImportSummary, file: &str) {
    if summary.created == 0 && summary.failed == 0 {
        println!("No DPP records found in {file}");
        return;
    }
    println!(
        "Import complete: {} created, {} failed",
        summary.created, summary.failed
    );
    for err in &summary.errors {
        eprintln!("  ✗ {err}");
    }
}

pub fn render_validation_report(report: &ValidationReport) {
    if report.records.is_empty() {
        println!("No draft DPPs found.");
        return;
    }
    println!("{:<36} {:<30} ISSUES", "DPP ID", "PRODUCT NAME");
    println!("{}", "─".repeat(90));
    for rec in &report.records {
        let issues_str = if rec.issues.is_empty() {
            "OK".to_owned()
        } else {
            rec.issues.join(", ")
        };
        println!("{:<36} {:<30} {}", rec.id, rec.product_name, issues_str);
    }
    if report.records.iter().all(|r| r.issues.is_empty()) {
        println!("\nAll draft DPPs pass validation.");
    }
}

/// Render an evidence dossier verification report (`odal verify`).
pub fn render_verification_report(report: &VerificationReport, file: &str) {
    println!("Verifying: {file}");
    println!("Trust anchor: {}\n", report.trust_anchor_note);
    for check in &report.checks {
        match &check.status {
            CheckStatus::Pass => println!("  [PASS] {}", check.name),
            CheckStatus::Fail(reason) => println!("  [FAIL] {} — {reason}", check.name),
            CheckStatus::Absent(reason) => println!("  [N/A ] {} — {reason}", check.name),
        }
    }
    println!();
    if report.all_verified() {
        println!("VERIFIED — every check passed.");
    } else {
        println!("TAMPER DETECTED — one or more checks failed. See FAIL lines above.");
    }
}

/// Render the result of a publish run.
/// `single` is true when a specific passport ID was targeted (vs. publish-all).
pub fn render_publish_summary(summary: &PublishSummary, single: bool) {
    if summary.items.is_empty() && !single {
        println!("No draft passports found. Nothing to publish.");
        return;
    }
    for item in &summary.items {
        if item.success {
            if single {
                println!("Published: {}", item.name);
                if let Some(qr) = &item.qr_url {
                    println!("  QR URL: {qr}");
                }
                println!("  ID:     {}", item.id);
            } else {
                println!("  OK    {}", item.name);
                if let Some(qr) = &item.qr_url {
                    println!("        {qr}");
                }
            }
        } else if !single {
            println!(
                "  FAIL  {} ({})",
                item.name,
                item.error.as_deref().unwrap_or("-")
            );
        }
    }
    if !single && (summary.published > 0 || summary.failed > 0) {
        println!(
            "\nDone: {} published, {} failed.",
            summary.published, summary.failed
        );
    }
    if !summary.errors.is_empty() {
        println!("\nErrors:");
        for err in &summary.errors {
            eprintln!("  - {err}");
        }
    }
}

pub fn render_history(entries: &[AuditEntry], id: &str) {
    if entries.is_empty() {
        println!("No audit entries for {id}.");
        return;
    }
    println!("{:<26}  {:<12}  ACTOR", "TIMESTAMP", "ACTION");
    for e in entries {
        println!("{:<26}  {:<12}  {}", e.timestamp, e.action, e.actor);
    }
}

pub fn render_export(result: &ExportResult, output: Option<&str>) -> Result<()> {
    match output {
        Some(path) => {
            let target = crate::config::export_target(path)?;
            std::fs::write(&target, &result.data)
                .map_err(|e| anyhow::anyhow!("Failed to write to {}: {e}", target.display()))?;
            println!("Exported to {}", target.display());
        }
        None => {
            std::io::stdout().lock().write_all(result.data.as_bytes())?;
        }
    }
    Ok(())
}

// ── Onboarding ───────────────────────────────────────────────────────────────

pub fn render_operator(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

pub fn render_key_create(result: &KeyCreateResult) {
    println!("API key '{}' created (shown once):", result.name);
    println!("  {}", result.secret);
}

pub fn render_key_list(keys: &[KeyEntry]) {
    if keys.is_empty() {
        println!("No API keys.");
        return;
    }
    println!("{:<38}  {:<20}  {:<12}  ACTIVE", "ID", "NAME", "PREFIX");
    for k in keys {
        println!(
            "{:<38}  {:<20}  {:<12}  {}",
            k.id, k.name, k.prefix, k.is_active
        );
    }
}

pub fn render_bootstrap_result(
    result: &BootstrapResult,
    legal_name: Option<&str>,
    country: Option<&str>,
    operator_complete: bool,
) {
    match (legal_name, country) {
        (Some(name), Some(c)) => println!("\nOperator configured: {name} ({c})"),
        (Some(name), None) => println!("\nOperator configured: {name}"),
        _ => {}
    }
    println!("\nAPI key minted and saved to ~/.config/odal/credentials.toml:");
    println!("  {}", result.api_key);
    println!("  (shown once — store it somewhere safe)\n");
    if !operator_complete {
        println!(
            "{}",
            style(
                "⚠ Operator identity is incomplete — set it before publishing:\n  \
                 odal operator set --legal-name … --country … --address … --contact-email …"
            )
            .yellow()
        );
        println!();
    }
    println!("Next steps:");
    println!("  odal passport import <file>   — load products");
    println!("  odal passport validate        — check drafts");
    println!("  odal passport publish         — issue passports");
}

// ── Schema ───────────────────────────────────────────────────────────────────

pub fn render_schema_check(result: &SchemaCheckResult) {
    if result.offline {
        println!("Cannot check — no internet connection");
        println!("Local schema version: {}", result.local_version);
        return;
    }
    if let Some(w) = &result.warning {
        println!("Warning: {w}");
    }
    println!("Current version : {}", result.local_version);
    println!(
        "Latest version  : {}",
        result.latest_version.as_deref().unwrap_or("unknown")
    );
    println!(
        "Update available: {}",
        if result.update_available { "yes" } else { "no" }
    );
}
