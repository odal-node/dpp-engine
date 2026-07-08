//! HTTP client that calls the co-located dpp-identity service for JWS signing.

use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;

use dpp_domain::{
    domain::{
        error::DppError,
        identity::{PassportCredential, SignedCredential},
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

        let credential: PassportCredential =
            serde_json::from_value(payload.clone()).map_err(|e| {
                DppError::Signing(format!(
                    "invalid credential payload from identity service: {e}"
                ))
            })?;

        Ok(SignedCredential {
            credential,
            jws,
            issuer_did: format!(
                "did:web:identity.odal-node.io:operators:{}",
                self.operator_id
            ),
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
