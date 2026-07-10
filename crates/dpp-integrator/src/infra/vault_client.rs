//! HTTP client for `dpp-vault` — passport creation and token verification.

use std::fmt;

use dpp_domain::domain::product_identity::ProductIdentity;

use crate::domain::request::CreatePassportRequest;

/// HTTP client for `dpp-vault`.
///
/// Cheap to clone — uses a shared `reqwest::Client` internally.
#[derive(Clone)]
pub struct VaultHttpClient {
    client: reqwest::Client,
    base_url: String,
}

impl VaultHttpClient {
    /// Construct a client that calls the vault at `base_url`.
    ///
    /// Sets a 30-second per-request timeout. Trailing slashes in `base_url` are
    /// stripped so path concatenation is consistent.
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build reqwest client"),
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// Validate a caller's bearer token by making an authenticated, side-effect
    /// free call to the vault. Returns `true` only on a 2xx response. Used to
    /// gate read endpoints (e.g. import-job status) behind the same auth as the
    /// rest of the API, since the integrator has no auth provider of its own.
    pub async fn verify_token(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let url = format!("{}/api/v1/dpps?limit=1", self.base_url);
        match self.client.get(&url).bearer_auth(token).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// POST a single passport creation request to vault.
    ///
    /// The caller's JWT is forwarded as `Authorization: Bearer {auth_token}`.
    pub async fn create_passport(
        &self,
        req: &CreatePassportRequest,
        auth_token: &str,
    ) -> Result<serde_json::Value, VaultClientError> {
        let url = format!("{}/api/v1/dpp", self.base_url);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .json(req)
            .send()
            .await
            .map_err(|e| VaultClientError::Network(e.to_string()))?;

        let status = resp.status();

        match status {
            s if s.is_success() => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|e| VaultClientError::Parse(e.to_string()))?;
                Ok(body)
            }
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(VaultClientError::Unauthorised),
            s if s == reqwest::StatusCode::FORBIDDEN => Err(VaultClientError::Unauthorised),
            s if s == reqwest::StatusCode::UNPROCESSABLE_ENTITY => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or(serde_json::json!({"detail": "validation failed"}));
                // RFC 7807 Problem: prefer `detail`, fall back to `title` for older shapes.
                let msg = body
                    .get("detail")
                    .or_else(|| body.get("title"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("validation failed")
                    .to_owned();
                Err(VaultClientError::Validation(msg))
            }
            s if s == reqwest::StatusCode::TOO_MANY_REQUESTS => Err(VaultClientError::RateLimit),
            s if s.is_server_error() => Err(VaultClientError::ServerError(s.as_u16())),
            s => Err(VaultClientError::Unexpected(s.as_u16())),
        }
    }

    /// PUT a merge-patch to an existing (draft) passport — the delta
    /// matcher's `update_draft` action. Same status-code mapping as
    /// `create_passport`; the vault's `PUT` returns `200`, not `201`, but
    /// both are covered by `is_success()`.
    pub async fn update_passport(
        &self,
        id: &str,
        req: &CreatePassportRequest,
        auth_token: &str,
    ) -> Result<serde_json::Value, VaultClientError> {
        let url = format!("{}/api/v1/dpp/{id}", self.base_url);

        let resp = self
            .client
            .put(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .json(req)
            .send()
            .await
            .map_err(|e| VaultClientError::Network(e.to_string()))?;

        let status = resp.status();

        match status {
            s if s.is_success() => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|e| VaultClientError::Parse(e.to_string()))?;
                Ok(body)
            }
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(VaultClientError::Unauthorised),
            s if s == reqwest::StatusCode::FORBIDDEN => Err(VaultClientError::Unauthorised),
            s if s == reqwest::StatusCode::UNPROCESSABLE_ENTITY => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or(serde_json::json!({"detail": "validation failed"}));
                let msg = body
                    .get("detail")
                    .or_else(|| body.get("title"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("validation failed")
                    .to_owned();
                Err(VaultClientError::Validation(msg))
            }
            s if s == reqwest::StatusCode::TOO_MANY_REQUESTS => Err(VaultClientError::RateLimit),
            s if s.is_server_error() => Err(VaultClientError::ServerError(s.as_u16())),
            s => Err(VaultClientError::Unexpected(s.as_u16())),
        }
    }

    /// Look up a passport by exact compound identity (sector, GTIN, batch).
    /// `Ok(None)` means no passport matches — not an error.
    pub async fn find_by_identity(
        &self,
        identity: &ProductIdentity,
        auth_token: &str,
    ) -> Result<Option<serde_json::Value>, VaultClientError> {
        let sector = serde_json::to_value(&identity.sector)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let mut params = vec![("sector", sector), ("gtin", identity.gtin.clone())];
        if let Some(ref batch_id) = identity.batch_id {
            params.push(("batchId", batch_id.clone()));
        }

        let url = format!("{}/api/v1/dpp/by-identity", self.base_url);
        let resp = self
            .client
            .get(&url)
            .query(&params)
            .bearer_auth(auth_token)
            .send()
            .await
            .map_err(|e| VaultClientError::Network(e.to_string()))?;

        match resp.status() {
            s if s.is_success() => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|e| VaultClientError::Parse(e.to_string()))?;
                Ok(Some(body))
            }
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            s if s == reqwest::StatusCode::UNAUTHORIZED || s == reqwest::StatusCode::FORBIDDEN => {
                Err(VaultClientError::Unauthorised)
            }
            s if s.is_server_error() => Err(VaultClientError::ServerError(s.as_u16())),
            s => Err(VaultClientError::Unexpected(s.as_u16())),
        }
    }
}

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors returned by `VaultHttpClient` calls.
#[derive(Debug)]
pub enum VaultClientError {
    Network(String),
    Parse(String),
    Validation(String),
    Unauthorised,
    RateLimit,
    ServerError(u16),
    Unexpected(u16),
}

impl fmt::Display for VaultClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network error: {e}"),
            Self::Parse(e) => write!(f, "response parse error: {e}"),
            Self::Validation(e) => write!(f, "vault validation error: {e}"),
            Self::Unauthorised => write!(f, "vault returned 401/403 — check auth token"),
            Self::RateLimit => write!(f, "vault rate limit (429) — all retries exhausted"),
            Self::ServerError(c) => write!(f, "vault server error: HTTP {c}"),
            Self::Unexpected(c) => write!(f, "unexpected vault response: HTTP {c}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use dpp_domain::domain::passport::ManufacturerInfo;
    use std::sync::Arc;

    struct MockResponse {
        status: StatusCode,
        body: serde_json::Value,
    }

    async fn respond(State(mock): State<Arc<MockResponse>>) -> Response {
        (mock.status, Json(mock.body.clone())).into_response()
    }

    /// Spawns a mock vault server that answers `GET /api/v1/dpps` and
    /// `POST /api/v1/dpp` with the same canned `(status, body)` — neither
    /// `verify_token` nor `create_passport` retries, so one canned response
    /// per test is enough.
    async fn spawn_mock(status: StatusCode, body: serde_json::Value) -> String {
        let mock = Arc::new(MockResponse { status, body });
        let app = Router::new()
            .route("/api/v1/dpps", get(respond))
            .route("/api/v1/dpp", post(respond))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn sample_request() -> CreatePassportRequest {
        CreatePassportRequest {
            product_name: "Test Widget".into(),
            sector: None,
            manufacturer: ManufacturerInfo {
                name: "Acme".into(),
                address: "1 Main St".into(),
                did_web_url: None,
            },
            materials: None,
            co2e_per_unit: None,
            repairability_score: None,
            sector_data: None,
            batch_id: None,
            schema_version: None,
        }
    }

    #[tokio::test]
    async fn verify_token_empty_token_is_false_without_a_network_call() {
        // base_url is never contacted — the empty-token check short-circuits first.
        let client = VaultHttpClient::new("http://127.0.0.1:1");
        assert!(!client.verify_token("").await);
    }

    #[tokio::test]
    async fn verify_token_true_on_2xx() {
        let base_url = spawn_mock(StatusCode::OK, serde_json::json!({"items": []})).await;
        let client = VaultHttpClient::new(&base_url);
        assert!(client.verify_token("some-token").await);
    }

    #[tokio::test]
    async fn verify_token_false_on_401() {
        let base_url = spawn_mock(StatusCode::UNAUTHORIZED, serde_json::json!({})).await;
        let client = VaultHttpClient::new(&base_url);
        assert!(!client.verify_token("bad-token").await);
    }

    #[tokio::test]
    async fn verify_token_false_when_vault_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // nothing listens now
        let client = VaultHttpClient::new(&format!("http://{addr}"));
        assert!(!client.verify_token("some-token").await);
    }

    #[tokio::test]
    async fn create_passport_success_returns_body() {
        let base_url = spawn_mock(StatusCode::CREATED, serde_json::json!({"id": "pp-123"})).await;
        let client = VaultHttpClient::new(&base_url);
        let body = client
            .create_passport(&sample_request(), "tok")
            .await
            .expect("should succeed");
        assert_eq!(body["id"], "pp-123");
    }

    #[tokio::test]
    async fn create_passport_401_is_unauthorised() {
        let base_url = spawn_mock(StatusCode::UNAUTHORIZED, serde_json::json!({})).await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultClientError::Unauthorised));
    }

    #[tokio::test]
    async fn create_passport_403_is_unauthorised() {
        let base_url = spawn_mock(StatusCode::FORBIDDEN, serde_json::json!({})).await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultClientError::Unauthorised));
    }

    #[tokio::test]
    async fn create_passport_422_extracts_detail() {
        let base_url = spawn_mock(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({"detail": "bad gtin"}),
        )
        .await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        match err {
            VaultClientError::Validation(msg) => assert_eq!(msg, "bad gtin"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_passport_422_falls_back_to_title_when_no_detail() {
        let base_url = spawn_mock(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({"title": "Unprocessable Entity"}),
        )
        .await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        match err {
            VaultClientError::Validation(msg) => assert_eq!(msg, "Unprocessable Entity"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_passport_429_is_rate_limit() {
        let base_url = spawn_mock(StatusCode::TOO_MANY_REQUESTS, serde_json::json!({})).await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultClientError::RateLimit));
    }

    #[tokio::test]
    async fn create_passport_5xx_is_server_error() {
        let base_url = spawn_mock(StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({})).await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultClientError::ServerError(500)));
    }

    #[tokio::test]
    async fn create_passport_unrecognised_status_is_unexpected() {
        let base_url = spawn_mock(StatusCode::IM_A_TEAPOT, serde_json::json!({})).await;
        let client = VaultHttpClient::new(&base_url);
        let err = client
            .create_passport(&sample_request(), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultClientError::Unexpected(418)));
    }
}
