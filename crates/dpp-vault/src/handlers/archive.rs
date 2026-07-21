//! `POST /api/v1/dpp/{dppId}/archive` — archive a passport after retention expiry.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id, require_write};

/// `POST /api/v1/dpp/{dppId}/archive` — permanently archive a published or suspended passport.
///
/// Blocked by the ESPR retention guard until the sector's minimum retention
/// period has elapsed from `published_at`. Returns `422` on a policy violation.
pub async fn archive_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Archiving a passport") {
        return resp;
    }
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.archive(passport_id, &auth).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::InvalidTransition { .. }) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "DPP cannot be archived from its current state.",
        ),
        // Business-rule rejection (e.g. the ESPR retention guard) — a client
        // error, not a server fault.
        Err(e @ dpp_domain::DppError::Validation(_)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &e.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}
