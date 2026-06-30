//! HTTP client for `dpp-vault` — passport creation and token verification.

use std::fmt;

use crate::domain::validator::CreatePassportRequest;

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
