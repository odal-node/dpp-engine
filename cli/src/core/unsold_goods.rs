//! The ESPR Art. 24 disclosure of unsold consumer products, via the node API.
//!
//! # Why this is not under `passport`
//!
//! Art. 24's subject is an **operator over a financial year**: the figures are
//! published on the operator's own website, and the trigger is discarding
//! unsold stock, none of which is a product placed on the market. There is no
//! digital product passport anywhere in Art. 24 or Art. 25, so these lines sit
//! beside the other operator-scoped actions and not under a passport id.

use anyhow::Result;
use serde_json::{Value, json};

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// One line of the disclosure, as the caller supplied it.
///
/// The operator is deliberately absent: the report is about this node's own
/// operator, taken from its config, and there is no second operator on a
/// single-tenant node for a caller to legitimately name.
pub struct DisclosureLine {
    pub period: String,
    pub units: i64,
    pub kg: f64,
    pub category: String,
    pub reason: String,
    pub destination: String,
    pub justification: Option<String>,
    pub country: String,
}

/// Record one disclosure line.
///
/// The justification rules are the node's and are not re-implemented here:
/// `exemptDestruction` requires one and every other destination refuses one,
/// and the node answers `422` naming which. A client-side copy of that rule
/// would be a second gate that can disagree with the first — and this one is
/// load-bearing, since Art. 25 prohibits the destruction outright from
/// 19 July 2026 and the justification is what records why it was permitted.
pub async fn action_unsold_goods_record(
    line: &DisclosureLine,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let url = format!("{}/api/v1/unsold-goods", cfg.vault_url);
    let mut body = json!({
        "reportingPeriod": line.period,
        "unitCount": line.units,
        "volumeKg": line.kg,
        "productCategory": line.category,
        "reason": line.reason,
        "destination": line.destination,
        "countryOfDisposal": line.country,
    });
    if let Some(j) = &line.justification {
        body["destructionJustification"] = json!(j);
    }
    let (status, response) = client.post_json(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!(
            "recording the disclosure line failed: {}",
            describe_error(status, &response)
        );
    }
    Ok(serde_json::from_str(&response).unwrap_or_default())
}

/// List recorded disclosure lines, newest first, optionally for one year.
pub async fn action_unsold_goods_list(
    period: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<Value>> {
    let url = match period {
        Some(p) => format!("{}/api/v1/unsold-goods?reportingPeriod={p}", cfg.vault_url),
        None => format!("{}/api/v1/unsold-goods", cfg.vault_url),
    };
    let (status, response) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "listing the disclosure failed: {}",
            describe_error(status, &response)
        );
    }
    let parsed: Value = serde_json::from_str(&response).unwrap_or_default();
    Ok(parsed.as_array().cloned().unwrap_or_default())
}
