//! `PUT /api/v1/dpp/{dppId}` — patch a draft passport's fields.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id};

/// `PUT /api/v1/dpp/{dppId}` — partial-update a draft passport.
///
/// Returns `409 Conflict` if the passport is not in `Draft` status.
pub async fn update_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.update(passport_id, body, &auth).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::InvalidTransition { .. }) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "DPP is not in a state that allows updates.",
        ),
        Err(e) => internal_error(e),
    }
}
