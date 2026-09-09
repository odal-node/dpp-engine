//! `POST /api/v1/dpp/{dppId}/amend` — issue a corrected successor.

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

/// Request body for the amend endpoint.
///
/// `Serialize` is derived so the OpenAPI contract gate can read the wire shape
/// from serde rather than from the field list, the same ground truth every other
/// checked shape uses.
#[derive(Debug, Deserialize, Serialize)]
pub struct AmendRequest {
    /// The correction, in the same shape the draft-update patch takes: the
    /// patchable content fields only. Anything else is ignored rather than
    /// refused, so a caller that PUTs a full create-shaped body still works and
    /// still cannot make a fixed field take effect.
    pub patch: serde_json::Value,
    /// Why the passport is being corrected. Stored on the predecessor's audit
    /// entry alongside the successor's id, which is where a reader asking "why
    /// did this change" will look.
    pub reason: Option<String>,
}

/// `POST /api/v1/dpp/{dppId}/amend` — issue a corrected successor.
///
/// A published passport cannot be edited: its signatures commit to its bytes and
/// the retention guard refuses the write. This publishes a **new** passport
/// carrying `supersedesId` back to `dppId`, then moves `dppId` to the terminal
/// `superseded` state. The superseded record keeps its signatures and stays
/// resolvable by its own id.
///
/// Returns `201` with the **successor** — the response body is a different
/// passport from the one in the path, which is the point of the operation.
/// `409` if the passport is not published, `422` if the correction is refused by
/// the same gates that govern a first publish.
pub async fn amend_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireWrite(auth): RequireWrite,
    Path(dpp_id): Path<String>,
    Json(body): Json<AmendRequest>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state
        .service
        .amend(passport_id, body.patch, body.reason, &auth)
        .await
    {
        Ok(p) => (
            StatusCode::CREATED,
            Json(crate::api::PassportResponse::from(&p)),
        )
            .into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => conflict_error(
            "Only a published DPP can be amended. A draft is edited in place; a suspended, \
             archived, superseded or deactivated DPP cannot be superseded.",
        ),
        Err(dpp_domain::DppError::Validation(errs)) => field_validation_error(&errs),
        Err(e) => internal_error(e),
    }
}
