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

use super::error::{api_error, internal_error, parse_passport_id};

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
    if !auth.scope.can_write() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Initiating a transfer requires a write-scoped credential.",
        );
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
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::InvalidTransition { .. }) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Only a published DPP can be transferred.",
        ),
        Err(e @ dpp_domain::DppError::Validation(_)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &e.to_string(),
        ),
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
    if !auth.scope.can_write() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Accepting a transfer requires a write-scoped credential.",
        );
    }
    let id = match parse_passport_id(&dpp_id) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match state.service.accept_transfer(id, &auth).await {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "No transfer to accept for this DPP.",
        ),
        Err(e @ dpp_domain::DppError::Validation(_)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &e.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}
