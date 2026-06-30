//! `POST /internal/sign` — Ed25519 JWS signing for passport payloads.
//!
//! Accessible only behind the mTLS middleware (`CN=odal-vault`).

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::Engine;
use dpp_common::http_problem;
use serde::Deserialize;
use serde_json::json;

use dpp_crypto::jws::signer;

use crate::state::AppState;

/// Request body for the signing endpoint.
#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Operator id whose key is used for signing. Auto-provisioned on first use.
    pub operator_id: String,
    /// The passport id being signed (informational — recorded in the JWS payload).
    pub passport_id: String,
    /// Base64-encoded canonical JSON of the payload to sign.
    pub payload: String,
}

/// `POST /internal/sign` — sign a base64-encoded payload with the operator's Ed25519 key.
///
/// Auto-provisions a signing key for `operator_id` if one does not yet exist.
/// Returns `{ "jws_signature": "<compact JWS>" }` on success.
pub async fn sign_handler(
    State(state): State<AppState>,
    Json(body): Json<SignRequest>,
) -> impl IntoResponse {
    if body.operator_id.is_empty() || body.passport_id.is_empty() || body.payload.is_empty() {
        return http_problem::unprocessable("operator_id, passport_id, and payload are required")
            .into_response();
    }

    // Decode payload from base64
    let payload_bytes = match base64::engine::general_purpose::STANDARD.decode(&body.payload) {
        Ok(b) => b,
        Err(_) => {
            return http_problem::bad_request("payload must be valid base64").into_response();
        }
    };

    let payload_value: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => {
            return http_problem::bad_request("decoded payload is not valid JSON").into_response();
        }
    };

    // Auto-provision key for new operators
    if !state.store.has_key(&body.operator_id)
        && let Err(e) = state.store.generate_key(&body.operator_id)
    {
        tracing::error!(operator_id = %body.operator_id, error = %e, "failed to generate operator key");
        return http_problem::internal_error("failed to provision signing key").into_response();
    }

    match signer::sign(&state.store, &body.operator_id, &payload_value) {
        Ok(jws) => (StatusCode::OK, Json(json!({"jws_signature": jws}))).into_response(),
        Err(e) => {
            tracing::error!(operator_id = %body.operator_id, error = %e, "signing failed");
            http_problem::internal_error(e.to_string()).into_response()
        }
    }
}
