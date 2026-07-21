//! Transfer of responsibility:
//! `POST /api/v1/dpp/{dppId}/transfer/initiate` and `.../transfer/accept`.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_domain::domain::transfer::{ResponsibleOperator, TransferReason};
use serde::Deserialize;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{
    conflict_error, internal_error, not_found_error, parse_passport_id, require_write,
    validation_error,
};

/// Body for initiating a transfer: the outgoing and incoming operators and the
/// reason. In the managed single-node model the caller supplies both parties.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferInitiateRequest {
    /// The current (outgoing) responsible operator — must match the chain head.
    pub from_operator: ResponsibleOperator,
    /// The incoming responsible operator taking over the DPP.
    pub to_operator: ResponsibleOperator,
    /// Why responsibility is transferring.
    pub reason: TransferReason,
    /// Optional notes (conditions, references).
    #[serde(default)]
    pub notes: Option<String>,
}

/// `POST /api/v1/dpp/{dppId}/transfer/initiate` — the outgoing operator signs a
/// pending handover onto the passport's transfer chain.
pub async fn transfer_initiate_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
    Json(body): Json<TransferInitiateRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Initiating a transfer") {
        return resp;
    }
    let id = match parse_passport_id(&dpp_id) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match state
        .service
        .initiate_transfer(
            id,
            body.from_operator,
            body.to_operator,
            body.reason,
            body.notes,
            &auth,
        )
        .await
    {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => {
            conflict_error("Only a published DPP can be transferred.")
        }
        Err(e @ dpp_domain::DppError::Validation(_)) => validation_error(&e.to_string()),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/dpp/{dppId}/transfer/accept` — the incoming operator verifies
/// the outgoing signature and countersigns, completing the handover.
pub async fn transfer_accept_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Accepting a transfer") {
        return resp;
    }
    let id = match parse_passport_id(&dpp_id) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match state.service.accept_transfer(id, &auth).await {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            not_found_error("No transfer to accept for this DPP.")
        }
        Err(e @ dpp_domain::DppError::Validation(_)) => validation_error(&e.to_string()),
        Err(e) => internal_error(e),
    }
}
