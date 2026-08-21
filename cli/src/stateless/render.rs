//! Presentation-free outcome types are rendered here.  Every public function
//! in this module accepts a typed outcome from `core/` and writes to stdout
//! (or a file for export).  No business logic lives here — callers decide
//! whether to bail based on the same outcome value.

use std::io::Write as _;

use anyhow::Result;
use console::style;
use dpp_types::evidence::{CheckStatus, VerificationReport};

use crate::config::{Config, EnvKind};
use crate::core::types::{
    AuditEntry, BootstrapResult, DryRunVerdict, ExportResult, ImportSummary, KeyCreateResult,
    KeyEntry, NodeState, PassportPage, PublishSummary, SchemaCheckResult, ServiceStatus,
    StatusReport, ValidationReport, WhoAmI,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Truncate to at most `max` characters (not bytes), appending `…` when cut.
///
/// Counts and slices by `char` so a multi-byte UTF-8 sequence landing on the
/// cutoff can never panic the CLI (the byte-index `&s[..n]` form does).
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
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

/// Render what `odal status` found.
///
/// Three sections, because they answer three different questions: is the node
/// serving, are the local containers up, and what does the node's trust
/// actually rest on. The first two were one table, which gave a container an
/// empty latency cell and implied it had been probed over HTTP.
pub fn render_status(report: &StatusReport) {
    println!("{:<12} {:<38} {:<8} LATENCY", "SERVICE", "URL", "STATUS");
    println!("{}", "─".repeat(72));
    for svc in &report.probes {
        // The reason a probe failed goes after the latency, not into the status
        // column — it is free text and long enough to break every row below it.
        let (label, reason) = match &svc.status {
            ServiceStatus::Ok => ("OK".to_owned(), String::new()),
            ServiceStatus::HttpError(code) => (format!("HTTP {code}"), String::new()),
            ServiceStatus::Failed(reason) => ("FAIL".to_owned(), format!("  {reason}")),
        };
        println!(
            "{:<12} {:<38} {:<8} {}ms{}",
            svc.name,
            truncate(&svc.url, 38),
            label,
            svc.latency_ms,
            reason
        );
    }

    if !report.containers.is_empty() {
        println!();
        println!("{:<12} {:<38} STATE", "CONTAINER", "NAME");
        println!("{}", "─".repeat(72));
        for c in &report.containers {
            let state = match &c.status {
                ServiceStatus::Ok => "OK".to_owned(),
                ServiceStatus::HttpError(code) => format!("HTTP {code}"),
                ServiceStatus::Failed(reason) => reason.clone(),
            };
            println!(
                "{:<12} {:<38} {}",
                c.service,
                truncate(&c.container, 38),
                state
            );
        }
    }

    if let Some(node) = &report.node {
        render_trust_posture(node);
    }
}

/// The node's trust posture, when it reported one.
///
/// A node that resolves no trust ports says nothing here rather than reporting
/// an empty posture, because "not reported" and "nothing is a ghost" are
/// different claims and only one of them is safe to make.
fn render_trust_posture(node: &NodeState) {
    if !node.has_trust_posture() {
        return;
    }
    // Port names vary in length (`seal` to `credential_issuers`), so the label
    // column is measured rather than guessed.
    let width = node
        .trust_mode
        .keys()
        .map(String::len)
        .chain(["profile".len(), "ruleset".len()])
        .max()
        .unwrap_or(8);

    println!();
    println!("TRUST");
    println!("{}", "─".repeat(72));
    if let Some(profile) = &node.profile {
        println!("{:<width$}  {}", "profile", profile);
    }
    for (port, mode) in &node.trust_mode {
        let rendered = if mode == "ghost" {
            style(mode).yellow().to_string()
        } else {
            mode.clone()
        };
        println!("{port:<width$}  {rendered}");
    }
    if let Some(version) = &node.ruleset_version {
        println!("{:<width$}  {}", "ruleset", version);
    }

    let ghosts = node.ghost_ports();
    if !ghosts.is_empty() {
        // Deliberately not "carries no legal weight". That is exactly right for
        // `seal`, whose whole purpose is an eIDAS qualified seal, and wrong for
        // a port like `archive`, which underwrites a durability obligation
        // rather than producing anything that bears legal weight itself. One
        // sentence has to hold for every port, so it says what is true of all
        // of them: the service is simulated, so its output is not usable.
        println!(
            "\n{} Running on a stand-in: {}.",
            style("!").yellow().bold(),
            ghosts.join(", ")
        );
        println!("  Simulated, not the real service — nothing this node produces");
        println!("  is fit for compliance use.");
    }
}

/// `odal whoami` — what the presented credential actually is.
pub fn render_whoami(who: &WhoAmI) {
    println!("user  : {}", who.user_id);
    println!("scope : {}", who.scope);
    match &who.key_id {
        Some(id) => println!("key   : {id}"),
        // Local-admin Basic auth has no key row. Saying so beats printing a
        // blank that reads like a missing value.
        None => println!("key   : (local admin — no API key row)"),
    }
}

/// `odal validate <file>` — the dry-run verdict.
///
/// Both verdicts are always shown. Create is lenient about a sector with no
/// resolvable schema and publish fails closed on it, so a body can be
/// creatable and not yet publishable — collapsing the two into one line would
/// hide that gap until the operator tried to publish.
pub fn render_dry_run(verdict: &DryRunVerdict) {
    let mark = |ok: bool| {
        if ok {
            style("✓").green().to_string()
        } else {
            style("✗").red().to_string()
        }
    };
    println!(
        "{} create   {}",
        mark(verdict.create_valid),
        if verdict.create_valid {
            "would be accepted"
        } else {
            "would be refused"
        }
    );
    // Deliberately not "would be accepted". The node's publish verdict is its
    // sector-data schema gate alone; publish additionally requires registry
    // identity, and category-mandatory content for some product categories,
    // neither of which this preview runs. Reporting a pass here as acceptance
    // would promise more than the node checked.
    println!(
        "{} publish  {}",
        mark(verdict.publish_valid),
        if verdict.publish_valid {
            "passes the sector-data schema gate"
        } else {
            "would be refused"
        }
    );
    if let Some(detail) = &verdict.detail {
        println!("\n{detail}");
    }
    if verdict.create_valid && verdict.publish_valid {
        println!(
            "\n{}",
            style(
                "Publish applies further checks this preview does not run \
                 (registry identity, category-mandatory content)."
            )
            .dim()
        );
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
pub fn render_verification_report(report: &VerificationReport, target: &str) {
    println!("Verifying: {target}");
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

/// Read an integer field from a stats response, defaulting to 0.
fn stat_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(serde_json::Value::as_i64).unwrap_or(0)
}

pub fn render_passport_stats(stats: &serde_json::Value, id: &str) {
    let window = stat_i64(stats, "windowDays");
    println!("Scan telemetry for {id} — last {window} days");
    println!(
        "  Resolutions : {} total   ({} page, {} data)",
        stat_i64(stats, "totalScans"),
        stat_i64(stats, "scansHtml"),
        stat_i64(stats, "scansJson"),
    );
    println!(
        "  QR renders  : {}   (label production — never counted as a resolution)",
        stat_i64(stats, "qrRenders"),
    );
    if let Some(daily) = stats.get("daily").and_then(serde_json::Value::as_array) {
        let daily: Vec<&serde_json::Value> =
            daily.iter().filter(|d| stat_i64(d, "count") > 0).collect();
        if !daily.is_empty() {
            println!("  By day:");
            for d in daily {
                let day = d
                    .get("day")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("-");
                println!("    {day}   {}", stat_i64(d, "count"));
            }
        }
    }
}

pub fn render_operator_stats(stats: &serde_json::Value) {
    let window = stat_i64(stats, "windowDays");
    println!("Scan telemetry — all passports, last {window} days");
    println!("  Resolutions       : {}", stat_i64(stats, "totalScans"));
    println!(
        "  QR renders        : {}",
        stat_i64(stats, "totalQrRenders")
    );
    println!(
        "  Passports scanned : {}",
        stat_i64(stats, "distinctPassportsScanned")
    );
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

/// Render a passport's qualified-seal status.
///
/// Two things this deliberately does not do. It does not say "valid": the node
/// did not validate the CAdES and the route says so, so printing a verdict here
/// would invent one the API refused to give. And it does not collapse
/// `coverage` into a pass/fail — `superseded` is not a failure, it means the
/// passport was re-published after sealing and the seal still covers the
/// signature it was bought for.
pub fn render_seal_status(seal: &serde_json::Value, id: &str) {
    let s = |key: &str| {
        seal.get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-")
            .to_owned()
    };
    let placeholder = seal
        .get("placeholder")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    println!("Seal for {id}");

    if placeholder {
        println!(
            "  {}  no QTSP is configured, so this is a ghost placeholder with no legal weight",
            style("PLACEHOLDER").yellow().bold()
        );
    }

    println!("  Format        : {}", s("format"));
    println!("  Sealed at     : {}", s("sealedAt"));

    // The certificate the seal names as its signer — which certificate to ask
    // about, not whether it was qualified. Absent for seals made before the
    // extraction landed, or when the CAdES could not be parsed.
    match seal
        .get("signingCertRef")
        .and_then(serde_json::Value::as_str)
    {
        Some(cert) => println!("  Signing cert  : {cert}"),
        None => println!("  Signing cert  : not recorded (predates extraction, or unparseable)"),
    }

    let coverage = s("coverage");
    let note = match coverage.as_str() {
        "current" => "covers the passport's current signature".to_owned(),
        "superseded" => "the passport was re-published after sealing — the seal still covers the \
             signature it was bought for, and a seal over the new one has not landed yet"
            .to_owned(),
        "unknown" => "this node has no record of what was sealed — restored from a backup, \
                      or produced elsewhere"
            .to_owned(),
        other => format!("unrecognised coverage value `{other}`"),
    };
    println!("  Coverage      : {coverage} — {note}");

    println!("  Current hash  : {}", s("currentPayloadHash"));
    println!(
        "  Sealed hash   : {}",
        seal.get("sealedPayloadHash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(no record)")
    );

    println!("\n  Verification  : {}", s("verification"));
}

/// Render the "this passport has no seal" case.
///
/// Its own function rather than a branch inside [`render_seal_status`], because
/// there is no seal document to render and the useful content is entirely
/// different: why there might not be one yet.
pub fn render_seal_absent(id: &str) {
    println!("Seal for {id}");
    println!("  None. The passport may be unpublished, or its seal may still be queued.");
    println!("  Sealing runs off a drain after publish — it is not part of the publish call.");
}

/// Render the operator-wide sealing summary.
///
/// Leads with the passport count, not the row counts. An operator asking about
/// sealing is asking whether a published passport is missing its seal; the
/// outbox totals are how that came about, which is the second question.
pub fn render_seal_summary(summary: &serde_json::Value) {
    let n = |key: &str| {
        summary
            .get(key)
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0)
    };

    if !summary
        .get("sealingConfigured")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        println!("Sealing is not configured on this node.");
        println!("  No seal provider is selected, so nothing is queued and nothing is sealed.");
        println!("  Set SEAL_PROVIDER to enable it.");
        return;
    }

    let unsealed = n("unsealedPublished");
    println!("Sealing");
    if unsealed == 0 {
        println!(
            "  {}  every published passport carries a seal",
            style("OK").green().bold()
        );
    } else {
        println!(
            "  {}  {unsealed} published passport(s) carry no seal",
            style("UNSEALED").red().bold()
        );
    }
    println!(
        "  Outbox: {} pending, {} sealed, {} exhausted",
        n("pending"),
        n("sealed"),
        n("exhausted")
    );

    // Worth saying out loud: these two can disagree, and the direction of the
    // disagreement is the diagnosis.
    if unsealed > 0 && n("pending") == 0 && n("exhausted") == 0 {
        println!(
            "\n  Unsealed with an empty outbox — those passports have no row at all, so no\n  \
             drain will pick them up. The repair sweep queues them on its next pass."
        );
    }
}
