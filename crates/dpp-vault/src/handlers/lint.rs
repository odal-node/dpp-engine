//! `POST /api/v1/dpp/{dppId}/lint` — on-demand plausibility-lint re-check (N10).

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id};

/// `POST /api/v1/dpp/{dppId}/lint` — recompute and persist the plausibility
/// lint pack's findings against the passport's current sector data.
///
/// Non-binding: findings never block publish and this endpoint never fails
/// on their account. Works regardless of passport status (Draft or
/// Published) — see [`crate::domain::service::PassportService::relint`].
pub async fn lint_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.relint(passport_id).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(e) => internal_error(e),
    }
}
