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

/// Whether `operator_id` is a well-formed identifier safe to key the on-disk
/// key store by: 1–64 characters from `[A-Za-z0-9._:-]`.
///
/// Rejecting anything else bounds key auto-provisioning — a typo, retry, or
/// garbage/oversized value can no longer silently grow the (never-pruned) key
/// store with a brand-new key.
pub(crate) fn is_valid_operator_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

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
    if !is_valid_operator_id(&body.operator_id) {
        return http_problem::unprocessable(
            "operator_id must be 1-64 characters of [A-Za-z0-9._:-]",
        )
        .into_response();
    }
    if body.passport_id.is_empty() || body.payload.is_empty() {
        return http_problem::unprocessable("passport_id and payload are required").into_response();
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

#[cfg(test)]
mod tests {
    use super::is_valid_operator_id;

    #[test]
    fn operator_id_validation_bounds_provisioning() {
        assert!(is_valid_operator_id("self_hosted"));
        assert!(is_valid_operator_id("did:web:acme.example"));
        // Rejected: empty, too long, or unsafe characters.
        assert!(!is_valid_operator_id(""));
        assert!(!is_valid_operator_id(&"x".repeat(65)));
        for bad in ["../etc", "a b", "a/b", "a\nb", "a;b"] {
            assert!(!is_valid_operator_id(bad), "should reject: {bad}");
        }
    }
}
