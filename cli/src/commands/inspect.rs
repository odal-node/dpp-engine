//! `odal passport lint | eol | tree | find` — the read-and-declare verbs the
//! CLI had no command for.

use anyhow::Result;

use crate::core::passport::{action_eol, action_find_by_identity, action_lint, action_verify_tree};

pub async fn run_lint(id: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let report = action_lint(id, &client, &cfg).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "packVersion": report.pack_version,
                "assessedAt": report.assessed_at,
                "findings": report.findings.iter().map(|f| serde_json::json!({
                    "severity": f.severity, "field": f.field, "message": f.message,
                })).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    println!("Lint: {id}");
    if let Some(v) = &report.pack_version {
        println!("  Pack:     {v}");
    }
    if let Some(t) = &report.assessed_at {
        println!("  Assessed: {t}");
    }

    if report.findings.is_empty() {
        println!("\nNo findings.");
    } else {
        println!("\n{} finding(s):", report.findings.len());
        for f in &report.findings {
            let where_ = if f.field.is_empty() { "-" } else { &f.field };
            println!("  [{}] {where_}  {}", f.severity, f.message);
        }
    }
    // Said every time, because a list of findings that gates nothing is
    // otherwise read as a list of findings that does.
    println!("\nFindings are advisory — they never block publish.");
    Ok(())
}

pub async fn run_eol(
    id: &str,
    reason: &str,
    derogation: Option<&str>,
    derogation_citation: Option<&str>,
    notes: Option<&str>,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    action_eol(
        id,
        reason,
        derogation,
        derogation_citation,
        notes,
        &client,
        &cfg,
    )
    .await?;
    println!("End of life declared for {id} ({reason}).");
    println!("The record is retained — a passport outlives its product.");
    Ok(())
}

pub async fn run_tree(id: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let report = action_verify_tree(id, &client, &cfg).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "verified": report.verified,
                "nodesChecked": report.nodes_checked,
                "failures": report.failures,
            })
        );
    } else {
        println!("Component tree: {id}");
        if let Some(n) = report.nodes_checked {
            println!("  Nodes checked: {n}");
        }
        if report.verified {
            println!("  Result:        every node matches the hash its parent pinned");
        } else {
            println!("  Result:        BROKEN");
            for f in &report.failures {
                println!("    {f}");
            }
        }
        // The route proves the pinned hash still matches. It does not check the
        // signature, and a summary that said "verified" without saying which
        // would be claiming the stronger of the two.
        println!("\nIntegrity only — this checks the pinned hash, not the signature.");
    }

    if report.verified {
        Ok(())
    } else {
        anyhow::bail!("component tree verification failed")
    }
}

pub async fn run_find(
    product_group: &str,
    gtin: &str,
    batch: Option<&str>,
    json: bool,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let found = action_find_by_identity(product_group, gtin, batch, &client, &cfg).await?;

    match found {
        None => {
            match batch {
                Some(b) => println!("No passport for {product_group} GTIN {gtin}, batch {b}."),
                // The batch is part of the identity, not a filter on it: a
                // passport that carries one is not found by a query without
                // one. Worth saying, because the bare "not found" reads as
                // "no such GTIN".
                None => println!(
                    "No passport for {product_group} GTIN {gtin} with no batch.\n\
                     The batch is part of the identity — pass --batch if the passport carries one."
                ),
            }
            Ok(())
        }
        Some(p) if json => {
            println!(
                "{}",
                serde_json::json!({
                    "id": p.id, "productName": p.product_name,
                    "productGroup": p.product_group, "status": p.status,
                    "batchId": p.batch, "updatedAt": p.updated,
                })
            );
            Ok(())
        }
        Some(p) => {
            println!("{}", p.product_name);
            println!("  ID:      {}", p.id);
            println!("  Group:   {}", p.product_group);
            println!("  Status:  {}", p.status);
            if let Some(b) = &p.batch {
                println!("  Batch:   {b}");
            }
            Ok(())
        }
    }
}
