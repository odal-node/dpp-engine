//! `POST /internal/keys/rotate` — rotate the Ed25519 signing key for an operator.
//!
//! Accessible only behind the mTLS middleware (`CN=odal-vault`).

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use dpp_common::http_problem;
use serde::Deserialize;
use serde_json::json;

use dpp_crypto::identity::did_builder;

use crate::state::AppState;

/// Request body for the key rotation endpoint.
#[derive(Debug, Deserialize)]
pub struct RotateRequest {
    /// The operator whose active signing key is to be rotated.
    pub operator_id: String,
}

/// Rotate the Ed25519 signing key for an operator.
///
/// Workflow:
///   1. Archive the existing key under a timestamped entry (so old signatures
///      remain verifiable after the rotation).
///   2. Generate and persist a new key pair.
///   3. Rebuild the DID document: new key is `#key-1` (primary / `authentication`);
///      archived keys are appended as `#key-2`, `#key-3`, … under `assertionMethod`
///      so historical passport signatures remain verifiable.
///   4. Return the new fingerprint and the updated DID document.
pub async fn rotate_key_handler(
    State(state): State<AppState>,
    Json(body): Json<RotateRequest>,
) -> impl IntoResponse {
    if body.operator_id.is_empty() {
        return http_problem::unprocessable("operator_id is required").into_response();
    }

    // Archive first — best effort; log but don't abort on failure.
    if let Err(e) = state.store.archive_key(&body.operator_id) {
        tracing::warn!(operator_id = %body.operator_id, error = %e, "failed to archive old key before rotation");
    }

    let new_key = match state.store.generate_key(&body.operator_id) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(operator_id = %body.operator_id, error = %e, "key rotation failed");
            return http_problem::internal_error(e.to_string()).into_response();
        }
    };

    // Rebuild the DID document with the new primary key and all archived keys.
    let did_document = match did_builder::build_did_document(
        &state.store,
        &state.did_web_base_url,
        &body.operator_id,
    ) {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!(operator_id = %body.operator_id, error = %e, "failed to build DID document after rotation");
            return http_problem::internal_error(e.to_string()).into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "operator_id": body.operator_id,
            "new_key_id": format!("{}#key-1", did_document["id"].as_str().unwrap_or("")),
            "fingerprint": new_key.fingerprint,
            "rotated": true,
            "did_document": did_document
        })),
    )
        .into_response()
}
