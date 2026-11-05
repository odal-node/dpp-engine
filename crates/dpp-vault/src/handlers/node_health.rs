use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use dpp_types::registry_sync::STALL_THRESHOLD;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::internal_error;

/// The registry-sync outbox's counts, as the node's gauges report them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryOutboxHealth {
    /// Rows awaiting a drain attempt.
    pub pending: i64,
    /// Rows accepted by the registry and awaiting its verdict.
    pub submitted: i64,
    /// Pending and submitted rows that have reached the stall threshold and need a
    /// person.
    pub stalled: i64,
    /// Rows the registry terminally rejected.
    pub rejected: i64,
}

/// The counters an operator pages on. Public so the OpenAPI contract test can
/// serialise it, as [`super::node_state::NodeState`] is.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeHealth {
    /// Publishes refused because a passport could not be signed, since the
    /// process started.
    pub signing_failures_total: u64,
    /// Ruleset bundles refused on load, since the process started.
    pub ruleset_load_failures_total: u64,
    /// Absent on a deployment with no registry-sync outbox wired, rather than
    /// reported as zeros a monitor would read as an empty queue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_outbox: Option<RegistryOutboxHealth>,
}

/// `GET /api/v1/node/health` — the operational counters a monitor needs, for a
/// deployment that cannot scrape `/metrics`. Authenticated, for the same reason
/// as `/node/state`: a failing signer or a stalled queue is a description of
/// where the node is weak. The unauthenticated `/health` answers liveness only.
///
/// The two process counters reset when the node restarts, so a restart hides
/// failures from before it. The outbox is read from the database and does not.
pub async fn node_health_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let registry_outbox = match &state.service.registry_outbox {
        Some(outbox) => match outbox.status_counts(STALL_THRESHOLD).await {
            Ok(c) => Some(RegistryOutboxHealth {
                pending: c.pending,
                submitted: c.submitted,
                stalled: c.stalled,
                rejected: c.rejected,
            }),
            Err(e) => return internal_error(e),
        },
        None => None,
    };

    (
        StatusCode::OK,
        Json(NodeHealth {
            signing_failures_total: dpp_common::metrics::signing_failures(),
            ruleset_load_failures_total: dpp_common::metrics::ruleset_load_failures(),
            registry_outbox,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no outbox wired the block is omitted entirely; the counters stay.
    #[test]
    fn an_unwired_outbox_is_omitted_rather_than_reported_as_empty() {
        let json = serde_json::to_value(NodeHealth {
            signing_failures_total: 0,
            ruleset_load_failures_total: 0,
            registry_outbox: None,
        })
        .expect("serialises");

        assert!(json.get("registryOutbox").is_none(), "{json}");
        assert_eq!(json["signingFailuresTotal"], 0);
        assert_eq!(json["rulesetLoadFailuresTotal"], 0);
    }
}
