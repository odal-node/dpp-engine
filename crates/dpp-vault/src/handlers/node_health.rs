use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use dpp_types::node_signal::{Signal, SignalState};
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

/// One signal, as the route serves it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSignal {
    /// Whether the latest recorded outcome is a failure: the field to alarm on.
    pub failing: bool,
    /// Failures since the node was first started. Never resets, so it says how
    /// often, not whether the node is failing now.
    pub failures: i64,
    /// When the latest failure was recorded. Absent until the first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failed_at: Option<DateTime<Utc>>,
    /// When the latest success was recorded. Absent until the first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_succeeded_at: Option<DateTime<Utc>>,
}

impl From<SignalState> for NodeSignal {
    fn from(state: SignalState) -> Self {
        Self {
            failing: state.is_failing(),
            failures: state.failures,
            last_failed_at: state.last_failed_at,
            last_succeeded_at: state.last_succeeded_at,
        }
    }
}

/// Every signal, keyed by its name. The one place the wire map is built, so the
/// OpenAPI contract test's fixture lists exactly the signals the route serves.
pub fn signals_view(states: Vec<(Signal, SignalState)>) -> BTreeMap<&'static str, NodeSignal> {
    states
        .into_iter()
        .map(|(signal, state)| (signal.name(), state.into()))
        .collect()
}

/// What an operator pages on. Public so the OpenAPI contract test can serialise
/// it, as [`super::node_state::NodeState`] is.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeHealth {
    /// Outcomes of the node's own work that leave no other trace, by signal name.
    /// Absent on a deployment with no signal store wired, rather than reported as
    /// a healthy node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signals: Option<BTreeMap<&'static str, NodeSignal>>,
    /// Absent on a deployment with no registry-sync outbox wired, rather than
    /// reported as zeros a monitor would read as an empty queue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_outbox: Option<RegistryOutboxHealth>,
}

/// `GET /api/v1/node/health` — what a monitor needs, for a deployment that
/// cannot scrape `/metrics`. Authenticated, for the same reason as
/// `/node/state`: a failing signer or a stalled queue is a description of where
/// the node is weak. The unauthenticated `/health` answers liveness only.
///
/// The signals are kept in the database, so a restart does not clear them. Each
/// says whether it is failing now, which is what tells a failing node from one
/// that failed once. The Prometheus counters on `/metrics` still reset on
/// restart.
pub async fn node_health_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let signals = match &state.service.signals {
        Some(store) => match store.states().await {
            Ok(states) => Some(signals_view(states)),
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
            signals,
            registry_outbox,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no signal store or outbox wired, each block is omitted rather than
    /// reported as a healthy node.
    #[test]
    fn an_unwired_store_and_outbox_are_omitted_rather_than_reported_as_healthy() {
        let json = serde_json::to_value(NodeHealth {
            signals: None,
            registry_outbox: None,
        })
        .expect("serialises");

        assert_eq!(json, serde_json::json!({}), "{json}");
    }

    /// A store that has recorded nothing still lists every signal, so a monitor
    /// reading `signals.signing.failing` finds the key.
    #[test]
    fn every_signal_is_listed_before_anything_is_recorded() {
        let states = Signal::ALL
            .into_iter()
            .map(|signal| (signal, SignalState::default()))
            .collect();
        let json = serde_json::to_value(signals_view(states)).expect("serialises");

        for signal in Signal::ALL {
            assert_eq!(
                json[signal.name()],
                serde_json::json!({ "failing": false, "failures": 0 }),
                "{json}"
            );
        }
    }
}
