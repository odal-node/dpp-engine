//! `odal unsold-goods` — record and read the ESPR Art. 24 disclosure.

use anyhow::Result;
use serde_json::Value;

use crate::core::unsold_goods::{
    DisclosureLine, action_unsold_goods_list, action_unsold_goods_record,
};

/// `odal unsold-goods record` — write one line of the Art. 24 disclosure.
///
/// Prints the retry advice on the write itself rather than leaving it in the
/// docs, because the route serves no `DELETE`: a line recorded twice is
/// permanent, and Art. 24 figures are published for a financial year, so the
/// duplicate becomes an overstatement of what the operator actually discarded.
pub async fn run_unsold_goods_record(line: DisclosureLine) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let id = action_unsold_goods_record(&line, &client, &cfg).await?;

    println!("Recorded disclosure line {id}.");
    println!(
        "  {} — {} units, {} kg, {} → {}",
        line.period, line.units, line.kg, line.category, line.destination
    );
    // Said on the write rather than only in the docs: this route serves no
    // DELETE, so a line recorded twice is a figure overstated for a financial
    // year that gets published.
    println!();
    println!("There is no delete — pass --idempotency-key if you retry this.");
    Ok(())
}

/// `odal unsold-goods list` — read the disclosure back, newest first.
///
/// The table flags lines carrying no unit count instead of printing a zero for
/// them. Art. 24(1)(a) asks for the number *and* the weight, and a row written
/// before the count had a column is incomplete rather than empty — an operator
/// assembling a return from these figures has to be able to tell the two apart.
pub async fn run_unsold_goods_list(period: Option<&str>, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let lines = action_unsold_goods_list(period, &client, &cfg).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&lines)?);
        return Ok(());
    }

    if lines.is_empty() {
        match period {
            Some(p) => println!("No disclosure lines recorded for {p}."),
            None => println!("No disclosure lines recorded."),
        }
        return Ok(());
    }

    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("-").to_owned();
    println!(
        "{:<6}  {:<14}  {:>8}  {:>10}  {:<18}  {:<8}",
        "YEAR", "CATEGORY", "UNITS", "KG", "DESTINATION", "COUNTRY"
    );
    for l in &lines {
        let units = l
            .get("unitCount")
            .and_then(Value::as_i64)
            .map_or_else(|| "-".to_owned(), |n| n.to_string());
        let kg = l
            .get("volumeKg")
            .and_then(Value::as_f64)
            .map_or_else(|| "-".to_owned(), |n| format!("{n:.1}"));
        println!(
            "{:<6}  {:<14}  {units:>8}  {kg:>10}  {:<18}  {:<8}",
            s(l, "reportingPeriod"),
            s(l, "productCategory"),
            s(l, "destination"),
            s(l, "countryOfDisposal"),
        );
    }
    println!("\n{} line(s).", lines.len());
    // Art. 24(1)(a) asks for the number and the weight. A row written before
    // the count had a column reports `-`, and an operator building a return
    // from these figures needs to see that rather than read it as zero.
    if lines
        .iter()
        .any(|l| l.get("unitCount").is_none_or(Value::is_null))
    {
        println!(
            "Some lines carry no unit count — they predate the column. Art. 24(1)(a)\n\
             asks for the number *and* the weight, so those lines are incomplete."
        );
    }
    Ok(())
}
