//! `odal product-group`, `odal schema list|show`, `odal template` — the
//! questions an operator asks before they have anything to import.

use anyhow::{Context, Result};

use crate::core::{
    catalog::{
        action_product_group_list, action_product_group_show, action_schema_list,
        action_schema_show, action_template,
    },
    types::ProductGroupObligation,
};

pub async fn run_product_group_list(required_only: bool, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client_unchecked()?;
    let mut rows = action_product_group_list(&client, &cfg).await?;
    if required_only {
        rows.retain(|r| r.required);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&as_json(&rows))?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No product groups reported.");
        return Ok(());
    }

    println!(
        "{:<16} {:<34} {:<10} {:<22} DETERMINABLE",
        "GROUP", "TITLE", "PASSPORT", "FROM"
    );
    for r in &rows {
        println!(
            "{:<16} {:<34} {:<10} {:<22} {}",
            r.product_group,
            // A null title is the case this endpoint exists for: an act
            // reaches the key and nothing else in the API names it.
            // Truncated because two catalog titles are long enough to push
            // every following column out of line.
            crate::stateless::render::truncate(r.title.as_deref().unwrap_or("(no descriptor)"), 34),
            if r.required { "required" } else { "—" },
            render_date(r),
            if r.determinable { "yes" } else { "no" },
        );
    }
    println!("\n{} product group(s).", rows.len());
    println!(
        "`required` is the duty; `determinable` is whether this build can decide it. \
         They differ where an act exists and its implementing rules do not."
    );
    Ok(())
}

pub async fn run_product_group_show(product_group: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client_unchecked()?;
    let r = action_product_group_show(product_group, &client, &cfg).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&as_json(&[r]))?);
        return Ok(());
    }

    println!("{}", r.title.as_deref().unwrap_or(&r.product_group));
    println!("  Key:           {}", r.product_group);
    println!(
        "  Passport:      {}",
        if r.required {
            "required"
        } else {
            "not required"
        }
    );
    println!("  From:          {}", render_date(&r));
    println!(
        "  Determinable:  {}",
        if r.determinable { "yes" } else { "no" }
    );
    println!(
        "  Granularity:   {}",
        r.granularity.as_deref().unwrap_or("not fixed by any act")
    );
    println!(
        "  Retention:     {}",
        match (r.retention_years, &r.retention_basis) {
            (Some(y), Some(b)) => format!("{y} years ({b})"),
            (Some(y), None) => format!("{y} years"),
            (None, _) => "no reaching act fixes one".to_owned(),
        }
    );

    if r.instruments.is_empty() {
        println!("\nNo act in this build's catalog reaches this product group.");
    } else {
        println!("\nActs reaching it:");
        for i in &r.instruments {
            println!(
                "  {:<26} act: {:<12} binds this group: {}",
                i.instrument,
                i.instrument_status.as_deref().unwrap_or("?"),
                i.binding_status.as_deref().unwrap_or("?"),
            );
        }
    }
    Ok(())
}

/// A date is never printed without its basis. Most of the catalog is undated,
/// and of the dates that exist some trace to an adopted text and some are a
/// reading — printing the bare date would present the second as the first.
fn render_date(r: &ProductGroupObligation) -> String {
    match (&r.from, &r.from_basis) {
        (Some(d), Some(b)) => format!("{d} ({b})"),
        (Some(d), None) => d.clone(),
        (None, _) => "—".to_owned(),
    }
}

fn as_json(rows: &[ProductGroupObligation]) -> serde_json::Value {
    serde_json::json!(
        rows.iter()
            .map(|r| serde_json::json!({
                "productGroup": r.product_group,
                "title": r.title,
                "passport": { "required": r.required,
                              "from": r.from, "fromBasis": r.from_basis },
                "determinable": r.determinable,
                "granularity": r.granularity,
                "retention": r.retention_years.map(|y| serde_json::json!({
                    "years": y, "basis": r.retention_basis,
                })),
                "instruments": r.instruments.iter().map(|i| serde_json::json!({
                    "instrument": i.instrument,
                    "instrumentStatus": i.instrument_status,
                    "bindingStatus": i.binding_status,
                })).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>()
    )
}

pub async fn run_schema_list(json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client_unchecked()?;
    let rows = action_schema_list(&client, &cfg).await?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!(
                rows.iter()
                    .map(|r| serde_json::json!({
                        "productGroup": r.product_group,
                        "current": r.current,
                        "versions": r.versions,
                    }))
                    .collect::<Vec<_>>()
            ))?
        );
        return Ok(());
    }

    println!("{:<16} {:<10} ALSO READABLE", "GROUP", "CURRENT");
    for r in &rows {
        // Everything except `current` — those are the versions the upcast lens
        // chain still covers, which is the fact worth showing beside it.
        let older: Vec<&str> = r
            .versions
            .iter()
            .map(String::as_str)
            .filter(|v| *v != r.current)
            .collect();
        println!(
            "{:<16} {:<10} {}",
            r.product_group,
            r.current,
            if older.is_empty() {
                "—".to_owned()
            } else {
                older.join(", ")
            }
        );
    }
    println!("\n{} schema(s).", rows.len());
    Ok(())
}

pub async fn run_schema_show(
    product_group: &str,
    version: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client_unchecked()?;
    let doc = action_schema_show(product_group, version, &client, &cfg).await?;
    write_out(&doc, output, &format!("{product_group} schema"))
}

pub async fn run_template(product_group: &str, output: Option<&str>) -> Result<()> {
    let (client, cfg) = crate::http::load_client_unchecked()?;
    let csv = action_template(product_group, &client, &cfg).await?;
    write_out(&csv, output, &format!("{product_group} CSV template"))
}

/// Straight to stdout unless a path is given, so the result can be piped.
fn write_out(body: &str, output: Option<&str>, what: &str) -> Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, body).with_context(|| format!("Cannot write {path}"))?;
            println!("Wrote the {what} to {path}.");
        }
        None => println!("{body}"),
    }
    Ok(())
}
