//! `POST /api/v1/dpp/{dppId}/supersede` — retire a passport in favour of a newer one.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::extract::Json;
use crate::middleware::scope::RequireWrite;
use crate::state::AppState;

use super::error::{
    conflict_error, field_validation_error, internal_error, not_found_error, parse_passport_id,
};

/// Which passport replaces the one named in the path.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersedeRequest {
    /// The successor — an already-published passport that takes over from this
    /// one. It records `supersedesId` pointing back here.
    pub superseded_by: String,
}

/// `POST /api/v1/dpp/{dppId}/supersede` — mark this passport replaced.
///
/// The path names the passport being retired; the body names its replacement.
/// Both must already be published: a successor is an ordinary passport with its
/// own content and its own gates, so it is created and published through the
/// normal routes and only then linked here.
///
/// Terminal. A superseded passport accepts no further transitions, and the
/// successor is what a reader follows forward.
pub async fn supersede_handler(
    State(state): State<AppState>,
    RequireWrite(auth): RequireWrite,
    Path(dpp_id): Path<String>,
    Json(body): Json<SupersedeRequest>,
) -> impl IntoResponse {
    let predecessor_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let successor_id = match parse_passport_id(&body.superseded_by) {
        Ok(id) => id,
        Err(_) => {
            return super::error::api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "supersededBy is not a valid passport id",
            );
        }
    };

    match state
        .service
        .supersede(predecessor_id, successor_id, &auth)
        .await
    {
        Ok(p) => (StatusCode::OK, Json(crate::api::PassportResponse::from(&p))).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => {
            conflict_error("DPP cannot be superseded from its current state.")
        }
        Err(dpp_domain::DppError::Validation(errors)) => field_validation_error(&errors),
        Err(e) => internal_error(e),
    }
}
