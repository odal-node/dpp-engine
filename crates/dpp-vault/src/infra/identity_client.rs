//! HTTP client that calls the co-located dpp-identity service for JWS signing.

use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;
use sha2::{Digest, Sha256};

use dpp_domain::{
    domain::{
        error::DppError,
        identity::{PassportCredential, PassportCredentialSubject, SignedCredential},
        passport::PassportId,
    },
    ports::identity_port::IdentityPort,
};

/// The issuer key id whose key the node's did:web document publishes at
/// `/.well-known/did.json`. Single-tenant deployments sign with this key.
const ROOT_ISSUER: &str = "root";

/// HTTP adapter for the `IdentityPort` that delegates signing to the
/// co-located dpp-identity microservice.
///
/// In single-tenant deployments the client always signs with the `"root"` key
/// — the same key published at the node's `did:web` document. Using any other
/// key would break JWS verification by external consumers.
pub struct IdentityHttpClient {
    base_url: String,
    operator_id: String,
    client: Client,
}

impl IdentityHttpClient {
    /// Construct a client that signs using the node's `"root"` issuer key.
    ///
    /// The signing key and the did:web document MUST reference the same key.
    /// This constructor enforces that invariant by always using `ROOT_ISSUER`.
    pub fn new(base_url: String) -> Self {
        Self::with_operator(base_url, ROOT_ISSUER.to_owned())
    }

    /// Construct a client that signs using an explicit issuer key id.
    ///
    /// Prefer [`Self::new`] for standard single-tenant use. This entry point
    /// exists for test overrides and future multi-key scenarios.
    pub fn with_operator(base_url: String, operator_id: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url,
            operator_id,
            client,
        }
    }
}

#[async_trait]
impl IdentityPort for IdentityHttpClient {
    /// POST `/internal/sign` — base64-encode the payload and request a JWS from
    /// the identity service.
    ///
    /// # Errors
    ///
    /// Returns `DppError::Internal` if the identity service is unreachable,
    /// or `DppError::Signing` if it returns a non-2xx status or an unexpected
    /// response shape.
    async fn sign_passport(
        &self,
        passport_id: PassportId,
        payload: &serde_json::Value,
    ) -> Result<SignedCredential, DppError> {
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(payload).map_err(|e| DppError::Serialisation(e.to_string()))?,
        );

        let body = serde_json::json!({
            "operator_id": self.operator_id,
            "passport_id": passport_id.to_string(),
            "payload": payload_b64,
        });

        let resp = self
            .client
            .post(format!("{}/internal/sign", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("identity service unreachable: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(DppError::Signing(format!(
                "identity service returned {status}: {text}"
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| DppError::Serialisation(e.to_string()))?;

        let jws = json
            .get("jws_signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DppError::Signing("missing jws_signature in response".into()))?
            .to_owned();

        // Build the W3C VC wrapper ourselves: the identity service signs the
        // payload, it does not echo back a credential shape, and `payload`
        // itself is whatever the caller is signing (a public view, an
        // evidence manifest, a transfer record, ...) — never a
        // `PassportCredential` in its own right, so it cannot be reparsed as
        // one. Mirrors `dpp_crypto::identity::local_service`'s in-process path.
        let canonical = dpp_crypto::jws::canonicalize(payload)
            .map_err(|e| DppError::Signing(format!("canonicalising payload: {e}")))?;
        let payload_hash = hex::encode(Sha256::digest(&canonical));
        let issuer_did = format!(
            "did:web:identity.odal-node.io:operators:{}",
            self.operator_id
        );
        let credential = PassportCredential::new(
            issuer_did.clone(),
            PassportCredentialSubject {
                id: format!("urn:uuid:{passport_id}"),
                payload_hash,
            },
        );

        Ok(SignedCredential {
            credential,
            jws,
            issuer_did,
        })
    }

    /// POST `/internal/verify` — delegate signature verification to the identity service.
    ///
    /// Returns `false` on any non-2xx response rather than propagating an error,
    /// so a transient identity-service hiccup does not break reads.
    async fn verify_signature(
        &self,
        jws: &str,
        payload: &serde_json::Value,
    ) -> Result<bool, DppError> {
        let body = serde_json::json!({
            "operator_id": self.operator_id,
            "jws": jws,
            "payload": payload,
        });

        let resp = self
            .client
            .post(format!("{}/internal/verify", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("identity service unreachable: {e}")))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| DppError::Serialisation(e.to_string()))?;

        Ok(json.get("valid").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// GET `/.well-known/did.json` — the same public, unauthenticated route
    /// external verifiers resolve. Single-tenant: there is one document, for
    /// the root operator; `self.operator_id` is not path-encoded into the
    /// request (`did_builder::build_did_document` publishes a pathless
    /// `did:web:{hostname}` DID, resolving only at the well-known path).
    async fn own_did_document(&self) -> Result<serde_json::Value, DppError> {
        let resp = self
            .client
            .get(format!("{}/.well-known/did.json", self.base_url))
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("identity service unreachable: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            return Err(DppError::Internal(format!(
                "identity service returned {status} for did.json"
            )));
        }

        resp.json()
            .await
            .map_err(|e| DppError::Serialisation(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::post,
    };

    use super::*;

    struct MockIdentity {
        store: dpp_crypto::keystore::KeyStore,
    }

    async fn sign(
        State(mock): State<Arc<MockIdentity>>,
        body: axum::Json<serde_json::Value>,
    ) -> Response {
        let payload_b64 = body["payload"].as_str().unwrap();
        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let jws = dpp_crypto::jws::sign(&mock.store, "root", &payload).unwrap();
        (
            StatusCode::OK,
            Json(serde_json::json!({"jws_signature": jws})),
        )
            .into_response()
    }

    /// Mirrors `dpp-identity`'s real `/internal/verify` contract: valid only
    /// when the signature checks out *and* the JWS's own payload matches what
    /// the caller expects.
    async fn verify(
        State(mock): State<Arc<MockIdentity>>,
        body: axum::Json<serde_json::Value>,
    ) -> Response {
        let jws = body["jws"].as_str().unwrap();
        let sig_ok = dpp_crypto::jws::verify(&mock.store, "root", jws).unwrap_or(false);
        let payload_b64 = jws.split('.').nth(1).unwrap();
        let decoded_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&decoded_bytes).unwrap();
        let valid = sig_ok && decoded == body["payload"];
        (StatusCode::OK, Json(serde_json::json!({"valid": valid}))).into_response()
    }

    async fn spawn_identity_mock() -> String {
        let path = std::env::temp_dir().join(format!(
            "identity-client-test-{}.json",
            uuid::Uuid::now_v7()
        ));
        let store = dpp_crypto::keystore::KeyStore::open(path, "test").expect("open store");
        store.generate_key("root").expect("provision key");
        let mock = Arc::new(MockIdentity { store });
        let app = Router::new()
            .route("/internal/sign", post(sign))
            .route("/internal/verify", post(verify))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Regression: `payload` is whatever the caller is signing (a public view,
    /// an evidence manifest, a transfer record, ...) — never a
    /// `PassportCredential` in its own right. `sign_passport` must not fail
    /// just because the payload doesn't happen to have that shape.
    #[tokio::test]
    async fn sign_passport_succeeds_for_a_non_credential_shaped_payload() {
        let base_url = spawn_identity_mock().await;
        let client = IdentityHttpClient::new(base_url);
        let passport_id = PassportId::new();

        // Shaped like a TransferRecord::signing_payload(), not a PassportCredential.
        let payload = serde_json::json!({
            "transferId": "abc-123",
            "fromOperator": "did:web:a.example",
            "toOperator": "did:web:b.example",
        });

        let signed = client
            .sign_passport(passport_id, &payload)
            .await
            .expect("signing a non-credential-shaped payload must succeed");

        assert!(!signed.jws.is_empty());
        assert_eq!(
            signed.credential.credential_subject.id,
            format!("urn:uuid:{passport_id}")
        );
        let expected_hash = {
            use sha2::{Digest, Sha256};
            let canonical = dpp_crypto::jws::canonicalize(&payload).unwrap();
            hex::encode(Sha256::digest(&canonical))
        };
        assert_eq!(
            signed.credential.credential_subject.payload_hash,
            expected_hash
        );
    }

    /// Regression for the `accept_transfer` flow: `verify_signature` must
    /// reach a real `/internal/verify` route (not 404) and correctly confirm
    /// a signature this same client produced moments earlier.
    #[tokio::test]
    async fn a_freshly_signed_payload_verifies_true() {
        let base_url = spawn_identity_mock().await;
        let client = IdentityHttpClient::new(base_url);
        let payload = serde_json::json!({"transferId": "abc-123"});

        let signed = client
            .sign_passport(PassportId::new(), &payload)
            .await
            .expect("sign");

        assert!(
            client
                .verify_signature(&signed.jws, &payload)
                .await
                .expect("verify_signature must not error"),
            "a signature this client just produced must verify"
        );
    }

    #[tokio::test]
    async fn a_signature_over_different_content_fails_verification() {
        let base_url = spawn_identity_mock().await;
        let client = IdentityHttpClient::new(base_url);

        let signed = client
            .sign_passport(
                PassportId::new(),
                &serde_json::json!({"transferId": "abc-123"}),
            )
            .await
            .expect("sign");

        let different_payload = serde_json::json!({"transferId": "different"});
        assert!(
            !client
                .verify_signature(&signed.jws, &different_payload)
                .await
                .expect("verify_signature must not error"),
            "a signature over different content must not verify"
        );
    }
}
