use axum::{extract::State, http::StatusCode, response::IntoResponse};

use dpp_types::{STANDALONE_OPERATOR_ID, operator::UpdateOperatorConfig};

use crate::state::AppState;

use super::error::{api_error, internal_error};
use crate::extract::Json;
use crate::middleware::scope::RequireAdmin;

/// `GET /api/v1/operator` — returns the node's operator config.
///
/// Single-tenant: one operator per node. If no row has ever been written,
/// returns an empty config rather than a 404 — keeps the dashboard
/// form-binding code simple. (Authenticated via `auth_middleware`.)
pub async fn operator_get_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.operator_service.get(STANDALONE_OPERATOR_ID).await {
        Ok(cfg) => (StatusCode::OK, Json(cfg)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `PATCH /api/v1/operator` — merge-patch the node's operator config.
///
/// Mutating operator identity/branding is an administrative action, so a
/// least-privilege key is rejected with 403. (`GET` stays available to any
/// authenticated caller.)
pub async fn operator_patch_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireAdmin(_auth): RequireAdmin,
    Json(patch): Json<UpdateOperatorConfig>,
) -> impl IntoResponse {
    if let Err(msg) = patch.validate() {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_CONFIG", &msg);
    }
    match state
        .operator_service
        .update(STANDALONE_OPERATOR_ID, patch)
        .await
    {
        Ok(cfg) => (StatusCode::OK, Json(cfg)).into_response(),
        Err(e) => internal_error(e),
    }
}
