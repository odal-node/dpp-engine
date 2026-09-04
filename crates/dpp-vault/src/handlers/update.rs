//! `PUT /api/v1/dpp/{dppId}` — patch a draft passport's fields.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::state::AppState;

use super::error::{
    conflict_error, field_validation_error, internal_error, not_found_error, parse_passport_id,
};
use crate::extract::Json;
use crate::middleware::scope::RequireWrite;

/// `PUT /api/v1/dpp/{dppId}` — partial-update a draft passport.
///
/// Returns `409 Conflict` if the passport is not in `Draft` status.
pub async fn update_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireWrite(auth): RequireWrite,
    Path(dpp_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.update(passport_id, body, &auth).await {
        Ok(p) => (StatusCode::OK, Json(crate::api::PassportResponse::from(&p))).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => {
            conflict_error("DPP is not in a state that allows updates.")
        }
        Err(dpp_domain::DppError::Validation(errs)) => field_validation_error(&errs),
        Err(e) => internal_error(e),
    }
}
