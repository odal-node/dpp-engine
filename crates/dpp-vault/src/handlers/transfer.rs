//! Transfer of responsibility — the four lifecycle routes under
//! `POST /api/v1/dpp/{dppId}/transfer/`: `initiate`, `accept`, `reject` and
//! `cancel`.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_domain::transfer::{ResponsibleOperator, TransferReason};
use serde::{Deserialize, Serialize};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{
    conflict_error, internal_error, not_found_error, parse_passport_id, require_write,
    validation_error,
};

/// Body for initiating a transfer: the outgoing and incoming operators and the
/// reason. In the managed single-node model the caller supplies both parties.
#[derive(Debug, Deserialize, Serialize)]
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
    // Both DIDs are stored verbatim on the transfer chain and are later resolved
    // over the network to fetch each counterparty's document for the evidence
    // dossier. Refuse a shape that has no legitimate meaning in a handover
    // between two operators here, at the edge, rather than relying only on the
    // fetch-time guard: a DID naming a loopback or internal host is not a
    // counterparty, and a stored one is a request a later reader has to keep
    // refusing forever.
    for (label, operator) in [
        ("fromOperator", &body.from_operator),
        ("toOperator", &body.to_operator),
    ] {
        if let Err(e) = validate_counterparty_did(&operator.did) {
            return validation_error(&format!("{label}.did: {e}"));
        }
    }
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

/// `POST /api/v1/dpp/{dppId}/transfer/reject` — end the pending handover as
/// refused.
///
/// Terminal: the record can never complete afterwards, and the chain is free to
/// carry a new transfer. Paired with `transfer_cancel_handler`, this is the only
/// way out of a handover the counterparty never acted on — without it a pending
/// record blocks every later transfer on the passport for good.
///
/// The caller is this node's operator, not the incoming one, which holds no
/// credentials here. The name records the outcome; see
/// `PassportService::terminate_pending_transfer`.
pub async fn transfer_reject_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Rejecting a transfer") {
        return resp;
    }
    let id = match parse_passport_id(&dpp_id) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match state.service.reject_transfer(id, &auth).await {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            not_found_error("No transfer to reject for this DPP.")
        }
        Err(e @ dpp_domain::DppError::Validation(_)) => validation_error(&e.to_string()),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/dpp/{dppId}/transfer/cancel` — end the pending handover as
/// withdrawn, before it completes.
///
/// The same caller as reject, recording a different outcome. Core permits a
/// cancel from one state more (`Accepted`), which no stored record reaches
/// today — see `PassportService::cancel_transfer`.
pub async fn transfer_cancel_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Cancelling a transfer") {
        return resp;
    }
    let id = match parse_passport_id(&dpp_id) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match state.service.cancel_transfer(id, &auth).await {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            not_found_error("No transfer to cancel for this DPP.")
        }
        Err(e @ dpp_domain::DppError::Validation(_)) => validation_error(&e.to_string()),
        Err(e) => internal_error(e),
    }
}

/// A transfer counterparty's DID must be a `did:web` this node could actually
/// resolve to a public document.
///
/// Shape only — the resolving guard still runs at fetch time, and this does not
/// replace it. What this adds is refusing to *store* a target that will never be
/// fetchable, so the refusal happens once, at the request that introduced it,
/// with a message naming the field.
fn validate_counterparty_did(did: &str) -> Result<(), String> {
    let url = crate::domain::verify::did_web_url(did)?;
    dpp_common::url_guard::validate_public_https_url(&url)
        .map(|_| ())
        .map_err(|e| format!("{did} does not resolve to a public https document ({e})"))
}

#[cfg(test)]
mod counterparty_did {
    use super::validate_counterparty_did;

    #[test]
    fn a_public_did_web_is_accepted() {
        assert!(validate_counterparty_did("did:web:acme.example").is_ok());
        assert!(validate_counterparty_did("did:web:acme.example:operators:eu").is_ok());
    }

    /// The input half of the evidence-export fetch: a DID naming an internal
    /// host is not a counterparty, and storing one means a target that has to
    /// be refused on every later export instead of once, here.
    #[test]
    fn an_internal_or_loopback_did_is_refused() {
        for did in [
            "did:web:127.0.0.1",
            "did:web:169.254.169.254",
            "did:web:10.0.0.5",
        ] {
            assert!(
                validate_counterparty_did(did).is_err(),
                "{did} must not be storable as a counterparty"
            );
        }
    }

    /// Only `did:web` is resolvable by the exporter, so anything else would be
    /// stored as a permanently unfetchable counterparty.
    #[test]
    fn a_non_did_web_is_refused() {
        for did in ["did:key:z6Mk", "did:example:123", "not-a-did", ""] {
            assert!(
                validate_counterparty_did(did).is_err(),
                "{did} must be refused"
            );
        }
    }
}
