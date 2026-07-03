use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};

use dpp_types::{STANDALONE_OPERATOR_ID, operator::UpdateOperatorConfig};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error};

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
    Extension(auth): Extension<AuthContext>,
    Json(patch): Json<UpdateOperatorConfig>,
) -> impl IntoResponse {
    if !auth.scope.is_admin() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Updating operator config requires an admin-scoped credential.",
        );
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
