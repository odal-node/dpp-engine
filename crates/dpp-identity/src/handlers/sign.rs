//! `POST /internal/sign` — Ed25519 JWS signing for passport payloads.
//!
//! Accessible only behind the mTLS middleware (`CN=odal-vault`).

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::Engine;
use dpp_common::http_problem;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Deserialize, Serialize)]
pub struct InternalSignRequest {
    /// Operator id whose key is used for signing. Auto-provisioned on first use.
    pub operator_id: String,
    /// The passport id being signed (informational — recorded in the JWS payload).
    pub passport_id: String,
    /// Base64-encoded canonical JSON of the payload to sign.
    pub payload: String,
}

/// Response body for the signing endpoint.
///
/// A named type rather than a `json!` literal so the OpenAPI contract test can
/// check `components/schemas/identity/InternalSignResponse` against it.
///
/// Note the field is `jws_signature`, not `jwsSignature`: this internal
/// service-to-service surface is snake_case, unlike the public `/api/v1` one.
/// That is the shape already on the wire and the shape the spec records; it is
/// not changed here, because renaming it would break the vault client for a
/// consistency the internal surface never claimed.
#[derive(Debug, Serialize)]
pub struct InternalSignResponse {
    /// Compact JWS (EdDSA over RFC 8785 canonical bytes).
    pub jws_signature: String,
}

/// `POST /internal/sign` — sign a base64-encoded payload with the operator's Ed25519 key.
///
/// Auto-provisions a signing key for `operator_id` if one does not yet exist.
/// Returns `{ "jws_signature": "<compact JWS>" }` on success.
pub async fn sign_handler(
    State(state): State<AppState>,
    Json(body): Json<InternalSignRequest>,
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

    // The `kid` is the absolute DID URL of the key's verification method, which
    // is the identifier the DID document this service serves gives that key.
    // `AppState::sign` names the key and signs with it as one step, and refuses a
    // token whose key was rotated while it was being made.
    match state.sign(&body.operator_id, &payload_value) {
        Ok(jws) => (
            StatusCode::OK,
            Json(InternalSignResponse { jws_signature: jws }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(operator_id = %body.operator_id, error = %e, "signing failed");
            http_problem::internal_error(e.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{Router, body::Body, http::Request, routing::post};
    use base64::Engine as _;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::{StatusCode, is_valid_operator_id, sign_handler};
    use crate::state::AppState;

    /// A router with only the signing route, over a throwaway keystore.
    ///
    /// The store comes back too, so a test can ask whether a refused request
    /// provisioned a key: the keystore is never pruned, so one that did would be
    /// permanent. The `TempDir` owns the directory the store writes into.
    fn sign_app() -> (
        Router,
        Arc<dpp_crypto::keystore::KeyStore>,
        tempfile::TempDir,
    ) {
        // The passphrase is the directory's own random name: a fresh one per
        // fixture, and not a literal in the source.
        let dir = tempfile::Builder::new()
            .prefix("odal-keystore-")
            .rand_bytes(24)
            .tempdir()
            .expect("temp dir");
        let passphrase = dir
            .path()
            .file_name()
            .expect("a named directory")
            .to_string_lossy()
            .into_owned();
        let store = Arc::new(
            dpp_crypto::keystore::KeyStore::open(dir.path().join("keystore.json"), &passphrase)
                .expect("open store"),
        );
        let state = AppState {
            store: Arc::clone(&store),
            did_web_base_url: "http://localhost".into(),
        };
        let app = Router::new()
            .route("/internal/sign", post(sign_handler))
            .with_state(state);
        (app, store, dir)
    }

    /// Post `body` to the signing route; the status and the RFC 9457 body.
    async fn sign_problem(app: &Router, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/internal/sign")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
            "a refusal is an RFC 9457 problem"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 10_000)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn payload_b64(value: &Value) -> String {
        base64::engine::general_purpose::STANDARD.encode(value.to_string())
    }

    #[tokio::test]
    async fn an_operator_id_outside_the_key_name_alphabet_is_refused_without_provisioning_a_key() {
        let (app, store, _dir) = sign_app();

        let (status, problem) = sign_problem(
            &app,
            json!({
                "operator_id": "a/b",
                "passport_id": "dpp:1",
                "payload": payload_b64(&json!({"id": "dpp:1"}))
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            problem["detail"]
                .as_str()
                .is_some_and(|d| d.contains("operator_id")),
            "the problem names the field: {problem}"
        );
        assert!(
            !store.has_key("a/b"),
            "a refused operator id must not grow the key store"
        );
    }

    #[tokio::test]
    async fn an_empty_passport_id_or_payload_is_refused_as_unprocessable() {
        let (app, store, _dir) = sign_app();
        let payload = payload_b64(&json!({"id": "dpp:1"}));

        for body in [
            json!({"operator_id": "op", "passport_id": "", "payload": payload}),
            json!({"operator_id": "op", "passport_id": "dpp:1", "payload": ""}),
        ] {
            let (status, problem) = sign_problem(&app, body.clone()).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert!(
                problem["detail"]
                    .as_str()
                    .is_some_and(|d| d.contains("required")),
                "the problem says what is missing: {problem}"
            );
        }
        assert!(
            !store.has_key("op"),
            "no key for a request that was refused"
        );
    }

    #[tokio::test]
    async fn a_payload_that_is_not_base64_is_a_bad_request_not_a_provisioned_key() {
        let (app, store, _dir) = sign_app();

        let (status, problem) = sign_problem(
            &app,
            json!({"operator_id": "op", "passport_id": "dpp:1", "payload": "!!!not base64!!!"}),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            problem["detail"]
                .as_str()
                .is_some_and(|d| d.contains("base64")),
            "the problem names the encoding: {problem}"
        );
        assert!(
            !store.has_key("op"),
            "no key for a request that was refused"
        );
    }

    #[tokio::test]
    async fn a_base64_payload_that_is_not_json_is_a_bad_request_not_a_provisioned_key() {
        let (app, store, _dir) = sign_app();
        let not_json = base64::engine::general_purpose::STANDARD.encode("this is not json");

        let (status, problem) = sign_problem(
            &app,
            json!({"operator_id": "op", "passport_id": "dpp:1", "payload": not_json}),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            problem["detail"]
                .as_str()
                .is_some_and(|d| d.contains("JSON")),
            "the problem names the format: {problem}"
        );
        assert!(
            !store.has_key("op"),
            "no key for a request that was refused"
        );
    }

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
