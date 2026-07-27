//! `GET /api/v1/dpp/{dppId}/history` — append-only audit trail for a passport.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id};

/// `GET /api/v1/dpp/{dppId}/history` — return the append-only audit trail for a passport.
///
/// Returns `404` for an unknown id so the caller can distinguish "no history
/// recorded yet" from "passport doesn't exist".
pub async fn history_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.history(passport_id).await {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(e) => internal_error(e),
    }
}
