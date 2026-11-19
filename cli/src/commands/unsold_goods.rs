//! `odal unsold-goods` — record and read the ESPR Art. 24 and Art. 25 discards.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::core::unsold_goods::{
    action_discard_attach, action_discard_list, action_discard_missing, action_discard_record,
    attached_sha256, missing_requirements, stored_record_id,
};

/// `odal unsold-goods record` — record one discard from a file.
///
/// Prints the retry advice on the write itself: the route serves no `DELETE`, so
/// a discard recorded twice stays counted twice.
pub async fn run_discard_record(file: &Path, passports: &[String]) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let record: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", file.display()))?;
    let (client, cfg) = crate::http::load_client()?;
    let stored = action_discard_record(&record, passports, &client, &cfg).await?;

    let id = stored_record_id(&stored)?;
    println!("Recorded discard {id}.");
    println!();
    println!("There is no delete — pass --idempotency-key if you retry this.");
    Ok(())
}

/// `odal unsold-goods list` — the discards of a financial year, earliest first.
pub async fn run_discard_list(start: &str, end: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let records = action_discard_list(start, end, &client, &cfg).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }
    if records.is_empty() {
        println!("No discard records between {start} and {end}.");
        return Ok(());
    }
    println!(
        "{:<36}  {:<10}  {:<18}  {:>10}",
        "ID", "DISCARDED", "TREATMENT", "GRAMS"
    );
    for r in &records {
        let record = r.get("record");
        let text = |key: &str| {
            record
                .and_then(|v| v.get(key))
                .and_then(Value::as_str)
                .unwrap_or("-")
                .to_owned()
        };
        let grams = record
            .and_then(|v| v.pointer("/weight/grams"))
            .and_then(Value::as_u64)
            .map_or_else(|| "-".to_owned(), |g| g.to_string());
        println!(
            "{:<36}  {:<10}  {:<18}  {grams:>10}",
            r.get("id").and_then(Value::as_str).unwrap_or("-"),
            text("discardedOn"),
            text("treatment"),
        );
    }
    println!("\n{} record(s).", records.len());
    Ok(())
}

/// `odal unsold-goods attach` — attach a document to a discard record.
pub async fn run_discard_attach(record_id: &str, kind: &str, file: &Path) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let attached = action_discard_attach(record_id, kind, file, &client, &cfg).await?;
    let sha = attached_sha256(&attached)?;
    println!("Attached {} as {kind} (sha256 {sha}).", file.display());
    Ok(())
}

/// `odal unsold-goods missing` — the evidence a discard record still lacks.
pub async fn run_discard_missing(record_id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let answer = action_discard_missing(record_id, &client, &cfg).await?;
    let missing = missing_requirements(&answer)?;
    if missing.is_empty() {
        println!("Nothing is missing for this record.");
        return Ok(());
    }
    println!("Missing evidence:");
    for (kinds, basis) in &missing {
        println!("  one of {} ({basis})", kinds.join(", "));
    }
    Ok(())
}
