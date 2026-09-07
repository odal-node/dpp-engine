//! Read-side passport actions the CLI had no verb for: the plausibility lint,
//! the component-tree walk, the end-of-life declaration, and the lookup by
//! business identity rather than by ID.

use anyhow::Result;
use serde_json::{Value, json};

use super::super::types::{LintFinding, LintReport, PassportSummary, TreeReport};
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

    Ok(LintReport {
        pack_version: text("packVersion"),
        assessed_at: text("assessedAt"),
        findings,
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
