//! `odal registry`, `odal facility audit`, `odal operator-id audit` — EU
//! registry sync state and the append-only trails behind retire-not-delete
//! records.

use anyhow::Result;

use crate::{
    core::registry::{
        action_provenance, action_registry_abandon, action_registry_handle, action_registry_status,
    },
    stateless::render::{render_registry_abandon, render_registry_handle},
};

pub async fn run_registry(id: Option<&str>, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let report = action_registry_status(id, &client, &cfg).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "passportId": report.passport_id,
                "configured": report.configured,
                "status": report.status,
                "registryId": report.registry_id,
                "message": report.message,
                "attempts": report.attempts,
                "stalled": report.stalled,
                "registrations": report.totals.iter()
                    .map(|(k, n)| (k.clone(), serde_json::json!(n)))
                    .collect::<serde_json::Map<String, serde_json::Value>>(),
            })
        );
        return Ok(());
    }

    match &report.passport_id {
        Some(id) => {
            println!("EU registry record: {id}");
            println!("  Status:      {}", report.status.as_deref().unwrap_or("—"));
            println!(
                "  Registry id: {}",
                report.registry_id.as_deref().unwrap_or("—")
            );
            if let Some(n) = report.attempts {
                println!(
                    "  Attempts:    {n}{}",
                    if report.stalled {
                        "  (STALLED — retries have stopped)"
                    } else {
                        ""
                    }
                );
            }
            if let Some(m) = &report.message {
                println!("  Registry:    {m}");
            }
        }
        None => {
            println!("EU registry sync");
            if report.totals.is_empty() {
                // Distinguishing these two matters: "no queues" is a
                // configuration fact, "nothing queued" is an activity fact.
                match report.configured {
                    Some(false) => println!("  No registry connection is configured on this node."),
                    _ => println!("  Nothing has been submitted yet."),
                }
            } else {
                for (status, count) in &report.totals {
                    println!("  {status:<14} {count}");
                }
            }
        }
    }
    Ok(())
}

/// `odal registry abandon <id> --reason "…"` — give up on a registration the
/// registry never accepted, once the node has found nothing for the passport in
/// the registry's task list.
pub async fn run_registry_abandon(id: &str, reason: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let abandoned = action_registry_abandon(id, reason, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&abandoned)?);
    } else {
        render_registry_abandon(&abandoned, id);
    }
    Ok(())
}

/// `odal registry handle <id> <correlation-id>` — record the registry's handle for a
/// submission this node lost it for, once the node has read the submission back
/// from the registry and found it to be this passport's.
pub async fn run_registry_handle(id: &str, correlation_id: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let recorded = action_registry_handle(id, correlation_id, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&recorded)?);
    } else {
        render_registry_handle(&recorded, id);
    }
    Ok(())
}

pub async fn run_facility_audit(id: &str) -> Result<()> {
    run_provenance("facilities", id, "Facility").await
}

pub async fn run_operator_id_audit(id: &str) -> Result<()> {
    run_provenance("operator-identifiers", id, "Operator identifier").await
}

async fn run_provenance(collection: &str, id: &str, label: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let entries = action_provenance(collection, id, &client, &cfg).await?;

    println!("{label} {id} — provenance");
    if entries.is_empty() {
        println!("  No entries.");
        return Ok(());
    }
    for e in &entries {
        println!("  {}  {:<18} {}", e.timestamp, e.action, e.actor);
        if let Some(d) = &e.detail {
            println!("      {d}");
        }
    }
    println!(
        "\n{} entry/entries. This trail is append-only.",
        entries.len()
    );
    Ok(())
}
