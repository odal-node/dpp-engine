//! Read-side passport actions the CLI had no verb for: the plausibility lint,
//! the component-tree walk, the end-of-life declaration, and the lookup by
//! business identity rather than by ID.

use anyhow::Result;
use serde_json::{Value, json};

use super::super::types::{
    LintFinding, LintReport, PassportScope, PassportSummary, PublishReadiness, TreeReport,
};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Re-run the plausibility lint pack and store the refreshed findings.
///
/// Findings are advisory: they are arithmetic and physical-plausibility checks,
/// not binding compliance rules, and they gate no transition. The command says
/// so, because a list of red lines that blocks nothing is otherwise read as a
/// list of red lines that does.
pub async fn action_lint(id: &str, client: &OdalClient, cfg: &Config) -> Result<LintReport> {
    let url = format!("{}/api/v1/dpp/{id}/lint", cfg.vault_url);
    let (status, body) = client.post_json(&url, &json!({})).await?;
    if !status.is_success() {
        anyhow::bail!("lint failed: {}", describe_error(status, &body));
    }
    // The route returns the whole refreshed passport, not a lint document —
    // the findings it persisted live under `lintResult`.
    let passport: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let v = passport.get("lintResult").cloned().unwrap_or(Value::Null);
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);

    let findings = v
        .get("findings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|f| {
                    let s = |k: &str| {
                        f.get(k)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    LintFinding {
                        severity: s("severity"),
                        field: s("field"),
                        message: s("message"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let publish_readiness = parse_publish_readiness(&passport);

    Ok(LintReport {
        pack_version: text("packVersion"),
        assessed_at: text("assessedAt"),
        findings,
        publish_readiness,
    })
}

/// Read `publishReadiness` off a lint response.
///
/// It sits on the response **envelope**, not inside `lintResult` — it is
/// computed per request and never persisted, because it is a question about the
/// gates rather than a finding about the content. Reading it from the wrong
/// place is the kind of mistake that shows up as a silently empty section
/// rather than an error, so it is pulled out here and pinned by a test against
/// a real response shape.
///
/// `None` from a node that predates the field, which the caller renders as
/// "not reported" rather than as "not ready".
fn parse_publish_readiness(passport: &Value) -> Option<PublishReadiness> {
    let r = passport.get("publishReadiness")?;
    let blockers = r
        .get("blockers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|b| {
                    let s = |k: &str| {
                        b.get(k)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    LintFinding {
                        // Blockers carry no severity of their own: every one of
                        // them stops the publish, which is what makes them
                        // blockers rather than findings.
                        severity: "blocking".to_owned(),
                        field: s("field"),
                        message: s("message"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Some(PublishReadiness {
        ready: r.get("ready").and_then(Value::as_bool).unwrap_or(false),
        blockers,
        scope: r.get("passportScope").map(|s| PassportScope {
            status: s
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            note: s.get("note").and_then(Value::as_str).map(str::to_owned),
        }),
    })
}

/// Declare a passport end-of-life.
///
/// `derogation` is carried only for `destroyed`, which the ESPR Art. 25
/// destruction ban otherwise forbids. The node validates the category against
/// the applicable delegated act — this only refuses the shape the node would
/// certainly reject, so an operator is not charged a round-trip to learn that
/// `--reason destroyed` needs a `--derogation`.
pub async fn action_eol(
    id: &str,
    reason: &str,
    derogation: Option<&str>,
    derogation_citation: Option<&str>,
    notes: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let mut kind = json!({ "kind": reason });
    match (reason, derogation) {
        ("destroyed", None) => anyhow::bail!(
            "--reason destroyed requires --derogation <category>: destruction is barred by the \
             ESPR Art. 25 unsold-goods ban unless a recognised derogation applies"
        ),
        ("destroyed", Some(category)) => {
            let mut d = json!({ "category": category });
            if let Some(c) = derogation_citation {
                d["actCitation"] = json!(c);
            }
            kind["derogation"] = d;
        }
        (_, Some(_)) => anyhow::bail!(
            "--derogation applies only to --reason destroyed; {reason} needs no derogation"
        ),
        _ => {}
    }

    let mut payload = json!({ "reason": kind });
    if let Some(n) = notes {
        payload["notes"] = json!(n);
    }

    let url = format!("{}/api/v1/dpp/{id}/eol", cfg.vault_url);
    let (status, body) = client.post_json(&url, &payload).await?;
    if !status.is_success() {
        anyhow::bail!(
            "end-of-life declaration failed: {}",
            describe_error(status, &body)
        );
    }
    Ok(())
}

/// Walk and verify the component (BOM) tree.
///
/// Integrity only: this proves each node's signed public view is unchanged
/// against the hash its parent pinned. It is not a signature check, and the
/// rendering must not imply that it is.
pub async fn action_verify_tree(id: &str, client: &OdalClient, cfg: &Config) -> Result<TreeReport> {
    let url = format!("{}/api/v1/dpp/{id}/verify-tree", cfg.vault_url);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "tree verification failed: {}",
            describe_error(status, &body)
        );
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);

    // Absent means "the walk reported no verdict", which is not "verified".
    let verified = v
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or_default();

    // Every visited node is reported, verified or not. The count is how many
    // there were; the failures are the ones that did not verify, named by the
    // root-to-node path the report carries for exactly this purpose.
    let nodes = v.get("nodes").and_then(Value::as_array);
    let failures = nodes
        .map(|a| {
            a.iter()
                .filter(|n| {
                    !n.get("verified")
                        .and_then(Value::as_bool)
                        .unwrap_or_default()
                })
                .map(|n| {
                    let path = n.get("path").and_then(Value::as_str).unwrap_or("(root)");
                    match n.get("reason").and_then(Value::as_str) {
                        Some(r) => format!("{path}  {r}"),
                        None => path.to_owned(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(TreeReport {
        verified,
        nodes_checked: nodes.map(|a| a.len() as u64),
        failures,
    })
}

/// Find a passport by (product group, GTIN, batch) — the identity an operator
/// actually holds, rather than the node-assigned ID.
pub async fn action_find_by_identity(
    product_group: &str,
    gtin: &str,
    batch: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Option<PassportSummary>> {
    let mut url = format!(
        "{}/api/v1/dpp/by-identity?productGroup={product_group}&gtin={gtin}",
        cfg.vault_url
    );
    if let Some(b) = batch {
        url.push_str(&format!("&batchId={b}"));
    }

    let (status, body) = client.get(&url).await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        anyhow::bail!("lookup failed: {}", describe_error(status, &body));
    }

    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Ok(Some(PassportSummary {
        id: s("id"),
        product_name: s("productName"),
        product_group: s("productGroup"),
        status: s("status"),
        batch: v.get("batchId").and_then(Value::as_str).map(str::to_owned),
        updated: s("updatedAt"),
    }))
}

#[cfg(test)]
mod publish_readiness {
    use super::parse_publish_readiness;
    use serde_json::json;

    /// The shape a node actually returns, captured from a live `/lint` call
    /// against an imported battery rather than written from the schema.
    #[test]
    fn reads_the_envelope_field_not_the_lint_result() {
        let response = json!({
            "id": "01a08610-bce5-79e2-b85f-bdbe158446b2",
            "lintResult": { "packVersion": "1.2.0", "findings": [] },
            "publishReadiness": {
                "ready": true,
                "blockers": [],
                "passportScope": {
                    "status": "required",
                    "note": "Art. 77(1) requires a battery passport for an industrial \
                             battery with a capacity greater than 2 kWh."
                }
            }
        });
        let r = parse_publish_readiness(&response).expect("publishReadiness is on the envelope");
        assert!(r.ready);
        assert!(r.blockers.is_empty());
        let scope = r.scope.expect("passportScope is reported");
        assert_eq!(scope.status, "required");
        assert!(scope.note.is_some());
    }

    /// Blockers are addressed to a field, which is the whole reason they are a
    /// list rather than a sentence — a caller completing a draft attaches each
    /// message to the input it belongs to.
    #[test]
    fn a_blocker_keeps_the_field_it_is_addressed_to() {
        let response = json!({
            "publishReadiness": {
                "ready": false,
                "blockers": [
                    { "field": "/productGroupData/batteryModelId", "message": "is mandatory" }
                ]
            }
        });
        let r = parse_publish_readiness(&response).expect("present");
        assert!(!r.ready);
        assert_eq!(r.blockers.len(), 1);
        assert_eq!(r.blockers[0].field, "/productGroupData/batteryModelId");
        assert_eq!(r.blockers[0].severity, "blocking");
        assert!(r.scope.is_none(), "a node may omit the scope report");
    }

    /// A node that predates the field reports nothing, and that must not read
    /// as "not ready" — which would tell an operator their passport is blocked
    /// when nothing has been asked.
    #[test]
    fn an_older_node_reports_nothing_rather_than_not_ready() {
        let response = json!({ "id": "x", "lintResult": { "findings": [] } });
        assert!(parse_publish_readiness(&response).is_none());
    }
}
