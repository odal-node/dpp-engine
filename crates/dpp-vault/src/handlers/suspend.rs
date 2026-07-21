//! `POST /api/v1/dpp/{dppId}/suspend` — suspend a published passport.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id, require_write};

/// Optional request body for the suspend endpoint.
#[derive(Debug, Deserialize)]
pub struct SuspendBody {
    /// Human-readable reason for suspension, stored in the audit trail.
    pub reason: Option<String>,
}

/// `POST /api/v1/dpp/{dppId}/suspend` — suspend a published passport.
///
/// Suspension is reversible (a suspended passport can be re-published). The
/// optional `reason` is appended to the audit entry. Returns `409` if the
/// passport is not in a suspendable state.
pub async fn suspend_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
    body: Option<Json<SuspendBody>>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Suspending a passport") {
        return resp;
    }
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let reason = body.and_then(|b| b.0.reason);

    match state.service.suspend(passport_id, &auth, reason).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::InvalidTransition { .. }) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "DPP cannot be suspended from its current state.",
        ),
        Err(e) => internal_error(e),
    }
}
