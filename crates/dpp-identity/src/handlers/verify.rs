//! `POST /internal/verify` — Ed25519 JWS verification for signatures this
//! service issued.
//!
//! Accessible only behind the mTLS middleware (`CN=odal-vault`).

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::Engine;
use dpp_common::http_problem;
use serde::Deserialize;
use serde_json::json;

use dpp_crypto::jws::signer;

use super::sign::is_valid_operator_id;
use crate::state::AppState;

/// Request body for the verification endpoint.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// Operator id whose key the signature is checked against.
    pub operator_id: String,
    /// The compact JWS to verify.
    pub jws: String,
    /// The payload the caller expects the JWS to have been signed over.
    pub payload: serde_json::Value,
}

/// `POST /internal/verify` — check a JWS against the operator's key *and*
/// confirm it was signed over `payload`.
///
/// A validly-signed JWS for different content must not pass: the caller is
/// asking "does this proof cover this exact payload", not merely "is this
/// signature well-formed". Returns `{ "valid": bool }`; never errors on a
/// signature that simply fails to verify — that is a `false`, not a fault.
pub async fn verify_handler(
    State(state): State<AppState>,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse {
    if !is_valid_operator_id(&body.operator_id) {
        return http_problem::unprocessable(
            "operator_id must be 1-64 characters of [A-Za-z0-9._:-]",
        )
        .into_response();
    }

    // No key on file for this operator: cannot be a signature we issued.
    if !state.store.has_key(&body.operator_id) {
        return (StatusCode::OK, Json(json!({"valid": false}))).into_response();
    }

    // A structurally malformed signature segment (bad base64, wrong decoded
    // length) is the caller presenting an invalid proof, not a server fault —
    // fail closed the same as every other invalid-input path above, rather
    // than a 500 that reads as "the service is broken."
    let sig_valid = match signer::verify(&state.store, &body.operator_id, &body.jws) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(operator_id = %body.operator_id, error = %e, "malformed signature");
            false
        }
    };

    let payload_matches = decode_jws_payload(&body.jws).as_ref() == Some(&body.payload);

    (
        StatusCode::OK,
        Json(json!({"valid": sig_valid && payload_matches})),
    )
        .into_response()
}

/// Decode the payload segment of a compact JWS into JSON, without verifying
/// the signature — the caller checks content match; [`signer::verify`]
/// checks the cryptographic proof. Neither alone is sufficient.
fn decode_jws_payload(jws: &str) -> Option<serde_json::Value> {
    let payload_b64 = jws.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{Router, body::Body, http::Request, routing::post};
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;

    fn temp_store() -> dpp_crypto::keystore::KeyStore {
        let path = std::env::temp_dir().join(format!("verify-test-{}.json", uuid::Uuid::now_v7()));
        dpp_crypto::keystore::KeyStore::open(path, "test").expect("open store")
    }

    fn app(store: dpp_crypto::keystore::KeyStore) -> Router {
        let state = AppState {
            store: Arc::new(store),
            did_web_base_url: "http://localhost".into(),
        };
        Router::new()
            .route("/internal/verify", post(verify_handler))
            .with_state(state)
    }

    async fn post_json(app: &Router, body: serde_json::Value) -> serde_json::Value {
        let req = Request::builder()
            .method("POST")
            .uri("/internal/verify")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 10_000)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_signature_this_service_issued_verifies_true() {
        let store = temp_store();
        store.generate_key("root").expect("provision key");
        let payload = json!({"passportId": "abc", "productName": "Widget"});
        let jws = signer::sign(&store, "root", &payload).expect("sign");

        let app = app(store);
        let resp = post_json(
            &app,
            json!({"operator_id": "root", "jws": jws, "payload": payload}),
        )
        .await;
        assert_eq!(resp["valid"], true);
    }

    #[tokio::test]
    async fn a_signature_over_different_content_is_rejected() {
        let store = temp_store();
        store.generate_key("root").expect("provision key");
        let signed_payload = json!({"passportId": "abc"});
        let jws = signer::sign(&store, "root", &signed_payload).expect("sign");

        let app = app(store);
        // Caller expects a different payload than what was actually signed.
        let resp = post_json(
            &app,
            json!({"operator_id": "root", "jws": jws, "payload": {"passportId": "other"}}),
        )
        .await;
        assert_eq!(resp["valid"], false);
    }

    #[tokio::test]
    async fn an_unknown_operator_is_rejected_without_provisioning_a_key() {
        let store = temp_store();
        let payload = json!({"passportId": "abc"});

        let app = app(store);
        let resp = post_json(
            &app,
            json!({"operator_id": "never-signed", "jws": "a.b.c", "payload": payload}),
        )
        .await;
        assert_eq!(resp["valid"], false);
    }

    #[tokio::test]
    async fn a_malformed_jws_is_rejected_not_a_500() {
        let store = temp_store();
        store.generate_key("root").expect("provision key");
        let payload = json!({"passportId": "abc"});

        let app = app(store);
        let resp = post_json(
            &app,
            json!({"operator_id": "root", "jws": "not-a-jws", "payload": payload}),
        )
        .await;
        assert_eq!(resp["valid"], false);
    }

    /// A JWS with the right shape (three dot-separated parts) but a signature
    /// segment that isn't decodable base64 must still fail closed as `false`,
    /// not 500 — `signer::verify` returns `Err` for this input, and a known
    /// operator with a real key means we reach that call, unlike the
    /// no-such-operator case above which never gets that far.
    #[tokio::test]
    async fn a_structurally_malformed_signature_segment_is_rejected_not_a_500() {
        let store = temp_store();
        store.generate_key("root").expect("provision key");
        let payload = json!({"passportId": "abc"});

        let app = app(store);
        let resp = post_json(
            &app,
            json!({
                "operator_id": "root",
                "jws": "aGVhZGVy.cGF5bG9hZA.!!!not-valid-base64!!!",
                "payload": payload
            }),
        )
        .await;
        assert_eq!(resp["valid"], false);
    }
}
