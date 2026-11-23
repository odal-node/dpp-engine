//! `odal passport lint | eol | tree | find` — the read-and-declare verbs the
//! CLI had no command for.

use anyhow::Result;
use dpp_types::passport_scope::{PassportScope, ScopeStatus};

use crate::core::passport::{
    action_eol, action_find_by_identity, action_lint, action_verify_tree, eol_payload,
};

/// `odal passport lint` — re-run the plausibility pack against a passport.
///
/// The route **persists** its `lintResult`, so this is a write dressed as a
/// read: running it replaces the stored assessment rather than reporting
/// alongside it. It also carries `publishReadiness`, which is the answer an
/// operator is usually actually after — whether the draft can be published,
/// and which fields block it if not.
pub async fn run_lint(id: &str, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let report = action_lint(id, &client, &cfg).await?;

    // The findings, as dpp-core serialises them: the same document the node
    // stored, with `code` and the severity spelt as the wire spells it.
    let findings = report
        .result
        .as_ref()
        .map_or(&[][..], |r| r.findings.as_slice());

    if json {
        let mut doc = report
            .result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| serde_json::json!({}));
        // Core leaves an empty list out; this output has always carried it.
        doc["findings"] = doc
            .get("findings")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        doc["publishReadiness"] = serde_json::json!(report.publish_readiness.as_ref().map(|r| {
            serde_json::json!({
                "ready": r.ready,
                "blockers": r.blockers.iter().map(|b| serde_json::json!({
                    "field": b.field, "message": b.message,
                })).collect::<Vec<_>>(),
                "passportScope": r.scope.as_ref().map(|s| serde_json::json!({
                    "status": s.status, "note": s.note,
                })),
            })
        }));
        println!("{doc}");
        return Ok(());
    }

    println!("Lint: {id}");
    if let Some(r) = &report.result {
        println!("  Pack:     {}", r.pack_version);
        println!("  Assessed: {}", r.assessed_at.to_rfc3339());
    }

    if findings.is_empty() {
        println!("\nNo findings.");
    } else {
        println!("\n{} finding(s):", findings.len());
        for f in findings {
            let where_ = if f.field.is_empty() { "-" } else { &f.field };
            let severity = serde_json::to_value(f.severity)?;
            println!(
                "  [{}] {where_}  {}",
                severity.as_str().unwrap_or_default(),
                f.message
            );
        }
    }
    // Said every time, because a list of findings that gates nothing is
    // otherwise read as a list of findings that does.
    println!("\nFindings are advisory — they never block publish.");

    // What *does* block publish, which is the question an operator running this
    // command is usually asking. Absent from a node that predates the field.
    if let Some(r) = &report.publish_readiness {
        println!();
        if r.ready {
            println!("Publish readiness: ready — no blocking field found.");
        } else {
            println!(
                "Publish readiness: NOT ready — {} blocker(s):",
                r.blockers.len()
            );
            for b in &r.blockers {
                let where_ = if b.field.is_empty() { "-" } else { &b.field };
                println!("  {where_}  {}", b.message);
            }
        }
        // Deliberately below the blockers rather than beside them: the gates
        // are what an operator acts on, and the scope is context for why they
        // are being asked at all.
        if let Some(s) = &r.scope {
            println!("\nPassport scope: {}", scope_label(&s.status));
            if let Some(note) = &s.note {
                println!("  {note}");
            }
        }
        println!(
            "\nThese are the gates answerable without attempting the publish. The registry\n\
             identity requirement and the binding-compliance determination are not among them."
        );
    }
    Ok(())
}

/// What the passport-scope status means to the person reading it.
///
/// Matched on dpp-core's own enum, so a status core words differently does not
/// quietly stop matching. The enum is `#[non_exhaustive]`, and the last arm is the
/// outcome this build has never heard of: it is printed as the node said it, which
/// is honest, and the test below fails for any outcome core lists that has no label
/// of its own here.
fn scope_label(status: &ScopeStatus) -> String {
    match status {
        ScopeStatus::Art77(PassportScope::Required) => "required by Art. 77(1)".to_owned(),
        ScopeStatus::Art77(PassportScope::NotCovered) => {
            "not covered — Art. 77(1) does not name this battery category".to_owned()
        }
        ScopeStatus::Art77(PassportScope::BelowThreshold) => {
            "below the threshold Art. 77(1) sets for industrial batteries".to_owned()
        }
        ScopeStatus::Art77(PassportScope::CapacityUnknown) => {
            "capacity not stated — treated as in scope".to_owned()
        }
        ScopeStatus::Art77(PassportScope::NotYetBinding) => {
            "not yet binding — placed on the market before Art. 77(1) applies".to_owned()
        }
        ScopeStatus::NotApplicable(_) => "not a battery — Art. 77(1) has nothing to say".to_owned(),
        other => serde_json::to_value(other)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
    }
}

pub async fn run_eol(
    id: &str,
    reason: &str,
    derogation: Option<&str>,
    unsold: Option<bool>,
    notes: Option<&str>,
    discard_record: Option<&str>,
) -> Result<()> {
    let payload = eol_payload(reason, derogation, unsold, notes, discard_record)?;
    let (client, cfg) = crate::http::load_client()?;
    action_eol(id, &payload, &client, &cfg).await?;
    println!("End of life declared for {id} ({reason}).");
    if let Some(record) = discard_record {
        println!("Documented by discard record {record}; the passport is joined to it.");
    }
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
    identifier: &str,
    batch: Option<&str>,
    json: bool,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let found = action_find_by_identity(product_group, identifier, batch, &client, &cfg).await?;

    match found {
        None => {
            match batch {
                Some(b) => {
                    println!("No passport for {product_group} {identifier}, batch {b}.");
                }
                // The batch is part of the identity, not a filter on it: a
                // passport that carries one is not found by a query without
                // one. Worth saying, because the bare "not found" reads as
                // "no such product".
                None => println!(
                    "No passport for {product_group} {identifier} with no batch.\n\
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

#[cfg(test)]
mod tests {
    use super::scope_label;
    use dpp_types::passport_scope::{PassportScope, ScopeStatus};

    /// Every outcome core lists has a sentence of its own, so one added to core is
    /// a failure here and not a raw word on an operator's screen. The word is what
    /// the last arm of `scope_label` falls back to, and it is core's, spelt
    /// camelCase, so a label that equals it is a label nobody wrote.
    #[test]
    fn every_outcome_core_lists_has_a_label_of_its_own() {
        for scope in PassportScope::ALL {
            let status = ScopeStatus::Art77(scope);
            let word = serde_json::to_value(&status).unwrap();
            let label = scope_label(&status);
            assert_ne!(
                word.as_str(),
                Some(label.as_str()),
                "{scope:?} prints as its raw word"
            );
        }
        assert!(scope_label(&ScopeStatus::from(None)).starts_with("not a battery"));
    }

    /// The stale table once labelled `voluntary`, a word the node had stopped
    /// sending, and printed the raw word for four it had started. A word nobody
    /// knows prints as it came.
    #[test]
    fn a_word_this_build_does_not_know_prints_as_it_came() {
        assert_eq!(
            scope_label(&ScopeStatus::Other("somethingNew".to_owned())),
            "somethingNew"
        );
    }
}
