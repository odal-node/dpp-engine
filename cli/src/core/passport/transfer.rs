//! Transfer of responsibility: the four ways a pending handover ends.
//!
//! A transfer is a two-step handover with three terminal outcomes, not a single
//! write, so each verb is its own route and its own command. `initiate` signs a
//! pending record onto the chain; `accept` countersigns and completes it;
//! `reject` and `cancel` both end it without a handover and differ only in who
//! walked away. All four are refused unless the passport is published.

use anyhow::Result;
use serde_json::{Value, json};

use super::super::types::{TransferInitiateParams, TransferOutcome};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// The three ways a pending transfer ends without a handover, plus the one way
/// it completes. Each is a distinct route; the verb is the last path segment.
pub async fn action_transfer_resolve(
    id: &str,
    verb: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<TransferOutcome> {
    let url = format!("{}/api/v1/dpp/{id}/transfer/{verb}", cfg.vault_url);
    let (status, body) = client.post_empty(&url).await?;
    if !status.is_success() {
        anyhow::bail!("transfer {verb} failed: {}", describe_error(status, &body));
    }
    Ok(read_outcome(&body))
}

pub async fn action_transfer_initiate(
    params: &TransferInitiateParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<TransferOutcome> {
    let mut payload = json!({
        "fromOperator": operator(
            &params.from_did, &params.from_name, &params.from_role, &params.from_country,
        ),
        "toOperator": operator(
            &params.to_did, &params.to_name, &params.to_role, &params.to_country,
        ),
        "reason": params.reason,
    });
    if let Some(notes) = &params.notes {
        payload["notes"] = json!(notes);
    }

    let url = format!(
        "{}/api/v1/dpp/{}/transfer/initiate",
        cfg.vault_url, params.id
    );
    let (status, body) = client.post_json(&url, &payload).await?;
    if !status.is_success() {
        anyhow::bail!(
            "transfer initiate failed: {}",
            describe_error(status, &body)
        );
    }
    Ok(read_outcome(&body))
}

fn operator(did: &str, name: &str, role: &str, country: &str) -> Value {
    json!({ "did": did, "name": name, "role": role, "country": country })
}

/// Read the fields a human wants back out of a `TransferRecord`, tolerating a
/// body that does not carry them: the transition already succeeded by the time
/// this runs, so a missing display field must not turn a completed transfer
/// into a reported failure.
fn read_outcome(body: &str) -> TransferOutcome {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let operator_name = |k: &str| {
        v.get(k)
            .and_then(|o| o.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    TransferOutcome {
        status: text("status"),
        from: operator_name("fromOperator"),
        to: operator_name("toOperator"),
        reason: text("reason"),
    }
}
