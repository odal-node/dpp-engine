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
    /// Publishes refused because a passport could not be signed, since the node
    /// was first started. Absent on a deployment with no durable counter wired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_failures_total: Option<i64>,
    /// Ruleset bundles refused on load, since the node was first started. Absent
    /// on a deployment with no durable counter wired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_load_failures_total: Option<i64>,
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
/// The two refusal counts are kept in the database, so a restart does not clear
/// them. The Prometheus counters on `/metrics` still reset on restart.
pub async fn node_health_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let refusals = match &state.service.failure_counter {
        Some(counter) => match counter.counts().await {
            Ok(c) => Some(c),
            Err(e) => return internal_error(e),
        },
        None => None,
    };
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
            signing_failures_total: refusals.map(|c| c.signing),
            ruleset_load_failures_total: refusals.map(|c| c.ruleset_load),
            registry_outbox,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no counter or outbox wired, each block is omitted rather than reported
    /// as zeros a monitor would read as a healthy node.
    #[test]
    fn an_unwired_counter_and_outbox_are_omitted_rather_than_reported_as_zero() {
        let json = serde_json::to_value(NodeHealth {
            signing_failures_total: None,
            ruleset_load_failures_total: None,
            registry_outbox: None,
        })
        .expect("serialises");

        assert_eq!(json, serde_json::json!({}), "{json}");
    }
}
