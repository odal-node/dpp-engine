//! `POST /api/v1/dpp/{dppId}/supersede` — retire a passport in favour of a newer one.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::middleware::scope::RequireWrite;
use crate::state::AppState;

use super::error::{
    conflict_error, field_validation_error, internal_error, not_found_error, parse_passport_id,
    validation_error,
};

/// Which passport replaces the one named in the path.
///
/// `Serialize` is derived so the OpenAPI contract gate can read the wire shape
/// from serde rather than from the field list, the same ground truth every other
/// checked shape uses.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersedeRequest {
    /// The successor — an already-published passport that takes over from this
    /// one. It must already record `supersedesId` pointing back here.
    pub superseded_by: String,
    /// Why the passport is being retired. Stored on the predecessor's audit
    /// entry alongside the successor's id, which is where a reader asking "why
    /// did this change" will look — the same entry `amend` writes.
    pub reason: Option<String>,
}

/// `POST /api/v1/dpp/{dppId}/supersede` — mark this passport replaced.
///
/// The path names the passport being retired; the body names its replacement.
/// Both must already be published: a successor is an ordinary passport with its
/// own content and its own gates, so it is created and published through the
/// normal routes and only then linked here.
///
/// This is the link half of supersession. The issue half is
/// `POST /dpp/{dppId}/amend`, which builds the successor from a patch and
/// therefore cannot name one that already exists. Use this when the replacement
/// was created independently — a migration to a newer schema version, a record
/// imported from another node, a successor issued by a different operator.
///
/// Returns `200` with the **retired predecessor**, not the successor — the
/// opposite of `amend`, which returns `201` with the record it created.
///
/// Terminal. A superseded passport accepts no further transitions, and the
/// successor is what a reader follows forward.
pub async fn supersede_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireWrite(auth): RequireWrite,
    Path(dpp_id): Path<String>,
    Json(body): Json<SupersedeRequest>,
) -> impl IntoResponse {
    let predecessor_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // `422`, not the `400` that `parse_passport_id` produces for the path.
    // `BadRequest` documents one thing — "a path parameter is malformed" — and
    // this is a body field, so answering `400` here would make the published
    // response mean two different things on the same operation. Every other
    // body-field refusal in the service is a `422`, and a client that indexes on
    // the status to decide whether to re-read the URL or fix the payload is
    // told the wrong one.
    let successor_id = match parse_passport_id(&body.superseded_by) {
        Ok(id) => id,
        Err(_) => {
            return validation_error("supersededBy is not a valid passport id.");
        }
    };

    match state
        .service
        .supersede(predecessor_id, successor_id, body.reason, &auth)
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
