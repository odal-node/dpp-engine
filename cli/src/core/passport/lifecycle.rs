//! Lifecycle: suspend, archive, and audit history.

use anyhow::{Context as _, Result};
use serde_json::json;

use super::super::types::{ArchiveParams, HistoryParams, PassportAuditEntry, SuspendParams};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

pub async fn action_suspend(
    params: &SuspendParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    lifecycle_transition(&params.id, "suspend", client, cfg).await
}

pub async fn action_archive(
    params: &ArchiveParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    lifecycle_transition(&params.id, "archive", client, cfg).await
}

/// POST an empty body to one of the passport's state-transition routes.
///
/// Shared by `suspend` and `archive` because those two really are the same
/// request with a different path segment — they take no body and return
/// nothing. `amend` and `supersede` deliberately do not route through here:
/// both carry a payload and both answer with a pair of ids, so folding them in
/// would mean a parameter that only two of the four callers use.
async fn lifecycle_transition(
    id: &str,
    action: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<()> {
    let url = format!("{}/api/v1/dpp/{id}/{action}", cfg.vault_url);
    let (status, body) = client.post_json(&url, &json!({})).await?;
    if !status.is_success() {
        anyhow::bail!("{action} failed: {}", describe_error(status, &body));
    }
    Ok(())
}

/// The outcome of a supersession, whichever route produced it.
///
/// Both routes retire one passport in favour of another and the pair is what an
/// operator needs back; they differ in which of the two they return, so this
/// names both rather than "the passport".
pub struct Supersession {
    /// The passport now in the terminal `superseded` state.
    pub retired: String,
    /// The passport that takes over.
    pub successor: String,
}

/// Correct a published passport by issuing a successor.
///
/// Returns `201` with the **successor**, which is a different record from the
/// one addressed — the opposite of `supersede`, which returns the retired
/// predecessor. Both are reported here so the caller does not have to know
/// which way round a given route answers.
///
/// The patch is passed through as the caller supplied it. Only the patchable
/// content fields take effect and the node ignores the rest rather than
/// refusing them, so filtering here would add a second opinion about what is
/// amendable and could only ever disagree with the node's.
pub async fn action_amend(
    id: &str,
    patch: serde_json::Value,
    reason: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Supersession> {
    let url = format!("{}/api/v1/dpp/{id}/amend", cfg.vault_url);
    let mut body = json!({ "patch": patch });
    if let Some(r) = reason {
        body["reason"] = json!(r);
    }
    let (status, response) = client.post_json(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!("amend failed: {}", describe_error(status, &response));
    }
    Ok(Supersession {
        retired: id.to_owned(),
        successor: successor_id(&response)?,
    })
}

/// Read the successor's id out of a successful amend response.
///
/// A missing id is an error rather than a placeholder. Falling back to one made
/// a failure indistinguishable from a success: the caller was handed a
/// `Supersession` reporting that the passport had been retired in favour of
/// `(not reported)`, printed as if it were an id, and the operator was left
/// holding a retirement whose successor they could not name.
///
/// The status was `201` before this is reached, so the amend HAS been applied
/// and the successor does exist — which is why this cannot degrade quietly. The
/// message says so, because the natural response to a failed command is to run
/// it again, and this is the one case where that is the wrong move.
fn successor_id(response: &str) -> Result<String> {
    let body: serde_json::Value = serde_json::from_str(response)
        .context("the node accepted the amend but its response was not JSON")?;
    body.get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned)
        .context(
            "the node accepted the amend but did not name the successor in its response. \
             The amend HAS been applied and the successor exists — read the passport's \
             history to find it rather than amending again.",
        )
}

/// Retire a published passport in favour of one that already exists.
///
/// The link is **checked** here, not written: the successor must already carry
/// `supersedesId` back to the passport being retired, set when it was created.
/// A successor that does not is refused with `422`, and the message says so.
pub async fn action_supersede(
    id: &str,
    superseded_by: &str,
    reason: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Supersession> {
    let url = format!("{}/api/v1/dpp/{id}/supersede", cfg.vault_url);
    let mut body = json!({ "supersededBy": superseded_by });
    if let Some(r) = reason {
        body["reason"] = json!(r);
    }
    let (status, response) = client.post_json(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!("supersede failed: {}", describe_error(status, &response));
    }
    Ok(Supersession {
        retired: id.to_owned(),
        successor: superseded_by.to_owned(),
    })
}

pub async fn action_history(
    params: &HistoryParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<PassportAuditEntry>> {
    let url = format!("{}/api/v1/dpp/{}/history", cfg.vault_url, params.id);
    let (status, body) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!("failed to fetch history: {}", describe_error(status, &body));
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default();

    Ok(arr
        .iter()
        .map(|e| PassportAuditEntry {
            timestamp: e
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            action: e
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
            actor: e
                .get("actor")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_owned(),
        })
        .collect())
}

#[cfg(test)]
mod amend_response {
    use super::successor_id;

    /// The shape the route documents: `201` with the successor as the body.
    #[test]
    fn the_successor_id_is_read_from_the_body() {
        let body = r#"{"id":"01a08610-bce5-79e2-b85f-bdbe158446b2","status":"draft"}"#;
        assert_eq!(
            successor_id(body).expect("an id is present"),
            "01a08610-bce5-79e2-b85f-bdbe158446b2"
        );
    }

    /// A body that does not parse must not become a supersession. The amend has
    /// already been applied at this point, so reporting success with a
    /// placeholder successor would tell the operator the one thing that is not
    /// true: that they know which passport took over.
    #[test]
    fn an_unparseable_body_is_an_error_not_a_supersession() {
        assert!(successor_id("<html>502 Bad Gateway</html>").is_err());
    }

    /// Well-formed JSON that simply has no `id` is the same failure — this was
    /// the case the `(not reported)` fallback silently absorbed.
    #[test]
    fn a_body_without_an_id_is_an_error() {
        assert!(successor_id(r#"{"status":"draft"}"#).is_err());
    }

    /// An `id` of the wrong type is not an id. `as_str` alone returns `None`
    /// here, which the old fallback turned into a printed placeholder.
    #[test]
    fn a_non_string_id_is_an_error() {
        assert!(successor_id(r#"{"id":42}"#).is_err());
    }

    /// An empty or blank id would print as a supersession into nothing.
    #[test]
    fn a_blank_id_is_an_error() {
        assert!(successor_id(r#"{"id":""}"#).is_err());
        assert!(successor_id(r#"{"id":"   "}"#).is_err());
    }

    /// The failure has to say the amend already happened, or the operator does
    /// the natural thing and runs it again — which is the one action that makes
    /// this worse.
    #[test]
    fn the_error_says_the_amend_was_applied() {
        let err = successor_id(r#"{"status":"draft"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("HAS been applied"), "message was: {err}");
    }
}
