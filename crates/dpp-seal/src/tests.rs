//! End-to-end tests for [`crate::adapter::QtspSealAdapter`] against a local mock
//! of the eID Easy e-seal endpoint.
//!
//! The mock is not a stub that always says yes: it **re-derives the HMAC from the
//! bytes it actually received** and rejects a mismatch with a 401, exactly as eID
//! Easy would. That is what makes these a real check of the sign-the-exact-bytes
//! rule, rather than a check that we call `.send()`.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use dpp_domain::domain::error::DppError;
use dpp_domain::ports::seal::{
    SealCredentialRef, SealFormat, SealMode, SealPort, SealRequest, SealedEnvelope,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::adapter::QtspSealAdapter;
use crate::eideasy::client::{ESEAL_PATH, hmac_message};

/// Base64 standing in for a real detached CAdES `.p7s`.
const MOCK_P7S: &str = "TU9DSy1DQWRFUy1QN1M=";

const MOCK_KEY: &str = "mock-eseal-hmac-key";

/// A digest of the right shape: 32 bytes, hex.
fn fixture_digest() -> String {
    hex::encode(Sha256::digest(b"a passport jws"))
}

fn seal_request(payload_hash: String) -> SealRequest {
    SealRequest {
        payload_hash,
        mode: SealMode::ProviderSeal,
        key_ref: SealCredentialRef {
            // CSC-shaped and unused by eID Easy, whose credential is adapter
            // config rather than a per-request reference. Carried as provenance
            // only.
            qtsp_id: "eideasy".into(),
            credential_id: "test-client".into(),
        },
        sig_format: SealFormat::Cades,
    }
}

mod mock_server {
    use super::*;
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(super) struct MockState {
        /// The raw body of the last request, exactly as received.
        pub received_body: Mutex<Option<String>>,
        /// Overrides the success response when set.
        pub force_response: Mutex<Option<(StatusCode, String)>>,
    }

    /// Rejects unless the presented HMAC matches one recomputed over the bytes
    /// that actually arrived — the same check eID Easy performs.
    async fn eseal(
        State(state): State<Arc<MockState>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let raw = String::from_utf8(body.to_vec()).expect("body is utf-8");
        *state.received_body.lock().unwrap() = Some(raw.clone());

        if let Some((status, body)) = state.force_response.lock().unwrap().clone() {
            return (status, body).into_response();
        }

        let ts: u64 = headers
            .get("X-Timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or_default();
        let presented = headers
            .get("X-HMAC-Signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();

        let mut mac = Hmac::<Sha256>::new_from_slice(MOCK_KEY.as_bytes()).unwrap();
        mac.update(hmac_message("POST", ESEAL_PATH, ts, &raw).as_bytes());
        let expected = BASE64.encode(mac.finalize().into_bytes());

        if presented != expected {
            return (StatusCode::UNAUTHORIZED, "HMAC mismatch").into_response();
        }

        let file_name: String = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v["files"][0]["fileName"].as_str().map(ToOwned::to_owned))
            .unwrap_or_default();

        axum::Json(serde_json::json!({
            "status": "OK",
            "signatures": [{
                "fileName": format!("{file_name}.p7s"),
                "mimeType": "application/pkcs7-signature",
                "fileContent": MOCK_P7S,
            }],
        }))
        .into_response()
    }

    pub(super) async fn spawn(state: Arc<MockState>) -> String {
        let app = Router::new()
            .route(ESEAL_PATH, post(eseal))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }
}

use mock_server::MockState;

fn adapter_for(base_url: &str, hmac_key: &str) -> QtspSealAdapter {
    let mut cfg = crate::config::test_config(base_url);
    cfg.hmac_key = zeroize::Zeroizing::new(hmac_key.to_owned());
    QtspSealAdapter::eideasy(cfg).unwrap()
}

#[tokio::test]
async fn unconfigured_adapter_delegates_to_ghost() {
    let env = QtspSealAdapter::ghost()
        .seal(seal_request(fixture_digest()))
        .await
        .unwrap();
    assert!(env.placeholder);
    assert!(env.seal_value.starts_with("GHOST-SEAL-"));
}

#[tokio::test]
async fn a_real_seal_round_trips_into_a_non_placeholder_envelope() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;

    let env = adapter_for(&base_url, MOCK_KEY)
        .seal(seal_request(fixture_digest()))
        .await
        .expect("the mock accepted the HMAC and returned a signature");

    assert_eq!(env.seal_value, MOCK_P7S);
    assert_eq!(env.format, SealFormat::Cades);
    assert!(
        !env.placeholder,
        "a real provider seal must never be marked placeholder"
    );
    assert!(env.signing_cert_ref.is_none());
}

/// The rule the client is built around, checked over a real socket: the bytes the
/// server receives are byte-identical to the bytes the HMAC was computed over. A
/// `.json()` call, a re-serialize, or any whitespace change breaks this.
#[tokio::test]
async fn the_hmac_covers_the_exact_bytes_that_arrive() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;

    adapter_for(&base_url, MOCK_KEY)
        .seal(seal_request(fixture_digest()))
        .await
        .expect("mock recomputed the HMAC over the received body and it matched");

    let received = state.received_body.lock().unwrap().clone().unwrap();
    // Sanity: what arrived is the compact form we serialized, carrying our values.
    assert!(received.starts_with('{') && received.ends_with('}'));
    assert!(!received.contains('\n'), "body was pretty-printed");
    assert!(received.contains("\"mimeType\":\"application/pdf\""));
    assert!(received.contains("\"signature_form\":\"CAdES\""));
}

#[tokio::test]
async fn a_wrong_hmac_key_is_a_clean_error_not_a_panic() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;

    let err = adapter_for(&base_url, "the-wrong-key")
        .seal(seal_request(fixture_digest()))
        .await
        .expect_err("a rotated or wrong key must not seal");

    assert!(matches!(err, DppError::Internal(_)));
    assert!(
        err.to_string().contains("credentials"),
        "the error should name the credential failure, got: {err}"
    );
}

#[tokio::test]
async fn a_non_ok_status_body_does_not_become_a_seal() {
    let state = Arc::new(MockState::default());
    *state.force_response.lock().unwrap() = Some((
        axum::http::StatusCode::OK,
        r#"{"status":"ERROR","signatures":[]}"#.to_owned(),
    ));
    let base_url = mock_server::spawn(state.clone()).await;

    assert!(
        adapter_for(&base_url, MOCK_KEY)
            .seal(seal_request(fixture_digest()))
            .await
            .is_err(),
        "an ERROR status was accepted as a seal"
    );
}

#[tokio::test]
async fn a_malformed_digest_never_reaches_the_network() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;

    let result = adapter_for(&base_url, MOCK_KEY)
        .seal(seal_request("not-a-sha256".into()))
        .await;

    assert!(result.is_err());
    assert!(
        state.received_body.lock().unwrap().is_none(),
        "a bad digest was sent anyway — every call to this endpoint is billed"
    );
}

#[tokio::test]
async fn verify_refuses_rather_than_guessing() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;

    let env = SealedEnvelope {
        format: SealFormat::Cades,
        seal_value: MOCK_P7S.into(),
        signing_cert_ref: None,
        sealed_at: chrono::Utc::now(),
        placeholder: false,
    };

    let err = adapter_for(&base_url, MOCK_KEY)
        .verify(&env)
        .await
        .expect_err("verify must not claim a CAdES check it cannot perform");
    assert!(err.to_string().contains("not implemented"));
}
