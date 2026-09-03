//! `POST /api/v1/dpp/{dppId}/suspend` — suspend a published passport.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

use super::error::{conflict_error, internal_error, not_found_error, parse_passport_id};
use crate::middleware::scope::RequireWrite;

/// Optional request body for the suspend endpoint.
///
/// `Serialize` is derived so the OpenAPI contract gate can read the wire shape
/// from serde rather than from the field list, the same ground truth every
/// other checked shape uses. Named for the `…Request` family the other request
/// bodies belong to (`EolRequest`, `TransferInitiateRequest`), so the schema and
/// the type behind it carry one name.
#[derive(Debug, Deserialize, Serialize)]
pub struct SuspendRequest {
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
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireWrite(auth): RequireWrite,
    Path(dpp_id): Path<String>,
    body: Option<Json<SuspendRequest>>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let reason = body.and_then(|b| b.0.reason);

    match state.service.suspend(passport_id, &auth, reason).await {
        Ok(p) => (StatusCode::OK, Json(crate::api::PassportResponse::from(&p))).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => {
            conflict_error("DPP cannot be suspended from its current state.")
        }
        Err(e) => internal_error(e),
    }
}
