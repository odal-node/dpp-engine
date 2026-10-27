//! `odal unsold-goods` — record and read the ESPR Art. 24 disclosure.

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::core::unsold_goods::{
    action_unsold_goods_get, action_unsold_goods_list, action_unsold_goods_put,
};

fn text<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer).and_then(Value::as_str).unwrap_or("-")
}

/// `odal unsold-goods put --file <report.json>` — store a financial year's
/// disclosure, replacing one stored for the same year.
///
/// Prints the lint findings as well as the outcome: they refuse nothing, and a
/// disclosure is published, so the operator should see them before it is.
pub async fn run_unsold_goods_put(file: &str, json: bool) -> Result<()> {
    let raw = std::fs::read_to_string(file).with_context(|| format!("cannot read {file}"))?;
    let report: Value =
        serde_json::from_str(&raw).with_context(|| format!("{file} is not JSON"))?;
    let (client, cfg) = crate::http::load_client()?;
    let recorded = action_unsold_goods_put(&report, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&recorded)?);
        return Ok(());
    }
    let disclosure = &recorded["disclosure"];
    println!(
        "Recorded the disclosure of {} for the financial year {} to {}.",
        text(disclosure, "/report/entity/name"),
        text(disclosure, "/report/financialYear/start"),
        text(disclosure, "/report/financialYear/end"),
    );
    let findings = recorded["lintFindings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !findings.is_empty() {
        println!("\nFindings (advisory, nothing was refused):");
        for f in &findings {
            println!(
                "  [{}] {}: {}",
                text(f, "/severity"),
                text(f, "/field"),
                text(f, "/message")
            );
        }
    }
    Ok(())
}

/// `odal unsold-goods get <START>` — one financial year's disclosure.
pub async fn run_unsold_goods_get(start: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let disclosure = action_unsold_goods_get(start, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&disclosure)?);
        return Ok(());
    }
    let report = &disclosure["report"];
    println!(
        "{} ({}), financial year {} to {}",
        text(report, "/entity/name"),
        text(report, "/entity/identifier/value"),
        text(report, "/financialYear/start"),
        text(report, "/financialYear/end"),
    );
    let lines = report["lines"].as_array().cloned().unwrap_or_default();
    println!(
        "\n{:<12}  {:>10}  {:>10}  {:<34}",
        "CN", "UNITS", "KG", "REASON"
    );
    for l in &lines {
        let cn = l["cnCategories"]
            .as_array()
            .map(|c| {
                c.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        // Annex I marks an estimate with `±`.
        let quantity = |q: &Value| {
            let value = q["value"]
                .as_u64()
                .map_or_else(|| "-".to_owned(), |v| v.to_string());
            if q["estimated"].as_bool() == Some(true) {
                format!("±{value}")
            } else {
                value
            }
        };
        println!(
            "{cn:<12}  {:>10}  {:>10}  {:<34}",
            quantity(&l["unitsDiscarded"]),
            quantity(&l["weightKg"]),
            text(l, "/reason"),
        );
    }
    println!(
        "\n{} line(s). Recorded by {} at {}.",
        lines.len(),
        text(&disclosure, "/recordedBy"),
        text(&disclosure, "/updatedAt"),
    );
    Ok(())
}

/// `odal unsold-goods list` — every stored disclosure, latest year first.
pub async fn run_unsold_goods_list(json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let disclosures = action_unsold_goods_list(&client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&disclosures)?);
        return Ok(());
    }
    if disclosures.is_empty() {
        println!("No disclosures recorded.");
        return Ok(());
    }
    println!(
        "{:<10}  {:<10}  {:>5}  {:<30}",
        "START", "END", "LINES", "ENTITY"
    );
    for d in &disclosures {
        let lines = d["report"]["lines"].as_array().map_or(0, Vec::len);
        println!(
            "{:<10}  {:<10}  {lines:>5}  {:<30}",
            text(d, "/report/financialYear/start"),
            text(d, "/report/financialYear/end"),
            text(d, "/report/entity/name"),
        );
    }
    println!("\n{} disclosure(s).", disclosures.len());
    Ok(())
}
