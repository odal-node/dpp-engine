use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use dpp_types::STANDALONE_OPERATOR_ID;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::internal_error;

/// Setup/readiness state for a node, used by the CLI to keep `odal bootstrap`
/// idempotent.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeState {
    /// True once the node has been claimed — i.e. at least one active API key
    /// has been minted. Re-running bootstrap on a claimed node is refused.
    bootstrapped: bool,
    /// True once the operator's responsible-economic-operator identity is
    /// complete enough to publish passports.
    operator_complete: bool,
}

/// `GET /api/v1/node/state` — report whether the node is claimed and whether the
/// operator identity is complete. Authenticated (API key or local admin), so the
/// CLI can call it during bootstrap before any key exists.
pub async fn node_state_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let bootstrapped = match state.api_key_service.list().await {
        Ok(keys) => !keys.is_empty(),
        Err(e) => return internal_error(e),
    };
    let operator_complete = match state.operator_service.get(STANDALONE_OPERATOR_ID).await {
        Ok(cfg) => cfg.is_complete(),
        Err(e) => return internal_error(e),
    };

    (
        StatusCode::OK,
        Json(NodeState {
            bootstrapped,
            operator_complete,
        }),
    )
        .into_response()
}
