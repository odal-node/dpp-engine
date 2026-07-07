//! HTTP adapter implementing `RegistrySyncPort` for the EU Central DPP Registry.
//!
//! # Authentication
//!
//! The EU registry requires OAuth2 client-credentials tokens. The adapter
//! acquires and caches tokens automatically, refreshing when they expire.
//!
//! # Retry policy
//!
//! Transient failures (5xx, timeouts, connection errors) are retried with
//! exponential backoff (3 attempts, 1s → 2s → 4s). Non-retryable errors
//! (4xx except 429) fail immediately.
//!
//! # Unreachable registry
//!
//! If the registry is unreachable (connection refused, DNS failure) the adapter
//! returns an error. It does **not** fabricate a synthetic success: the
//! transactional outbox (`dpp-types::RegistrySyncOutbox`) already
//! guarantees no registration is lost — an unreachable registry simply leaves
//! the outbox row `pending`, visibly, to be retried with backoff. Faking a
//! `Pending` here would let the drain mark an unregistered passport
//! "registered", which is exactly the ghost-as-real dishonesty the honesty
//! invariant forbids.

use std::sync::Arc;

use dpp_common::event_codes;
use dpp_domain::domain::error::DppError;
use reqwest::Client;
use tokio::sync::RwLock;

use super::config::EuRegistrySyncConfig;
use super::token::CachedToken;

/// HTTP adapter for the EU Central DPP Registry.
///
/// Implements `RegistrySyncPort` (see [`super::mapping`]) by making REST calls
/// to the EU registry API, mapping between domain port types and bridge wire
/// types.
pub struct EuRegistrySync {
    pub(super) client: Client,
    pub(super) config: EuRegistrySyncConfig,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
}

impl EuRegistrySync {
    /// Create a new adapter with the given configuration.
    pub fn new(config: EuRegistrySyncConfig) -> Result<Self, DppError> {
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| DppError::Internal(format!("HTTP client build failed: {e}")))?;

        Ok(Self {
            client,
            config,
            token_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Acquire an OAuth2 access token, using the cache when possible.
    pub(super) async fn get_token(&self) -> Result<String, DppError> {
        use super::token::TokenResponse;

        // Fast path: check cache with read lock.
        {
            let cache = self.token_cache.read().await;
            if let Some(ref cached) = *cache
                && !cached.is_expired()
            {
                return Ok(cached.access_token.clone());
            }
        }

        // Slow path: acquire write lock and fetch a new token.
        let mut cache = self.token_cache.write().await;

        // Double-check — another task may have refreshed while we waited.
        if let Some(ref cached) = *cache
            && !cached.is_expired()
        {
            return Ok(cached.access_token.clone());
        }

        let token_endpoint = self
            .config
            .endpoint
            .token_endpoint
            .as_deref()
            .ok_or_else(|| {
                DppError::Internal("registry endpoint has no token_endpoint configured".into())
            })?;

        let resp = self
            .client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("token request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(DppError::Internal(format!(
                "token endpoint returned {status}: {body}"
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| DppError::Internal(format!("failed to parse token response: {e}")))?;

        let cached = CachedToken {
            access_token: token_resp.access_token.clone(),
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_secs(token_resp.expires_in),
        };

        let access_token = cached.access_token.clone();
        *cache = Some(cached);

        Ok(access_token)
    }

    /// Execute an HTTP request with retry logic.
    ///
    /// Retries on 5xx, 429, timeouts, and connection errors.
    /// Returns immediately on 2xx, 4xx (except 429).
    /// Returns the original `RetryableError` variant so callers can
    /// distinguish `Unreachable` from `Fatal` for fallback decisions.
    pub(super) async fn with_retry<F, Fut, T>(&self, operation: F) -> Result<T, RetryableError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, RetryableError>>,
    {
        let mut attempt = 0;
        loop {
            match operation().await {
                Ok(v) => return Ok(v),
                Err(RetryableError::Retryable(msg)) => {
                    attempt += 1;
                    if attempt >= self.config.max_retries {
                        tracing::warn!(
                            code = event_codes::REGISTRY_SYNC_FAILED,
                            attempt,
                            error = %msg,
                            "EU registry request failed after max retries"
                        );
                        return Err(RetryableError::Retryable(format!(
                            "EU registry request failed after {attempt} attempts: {msg}"
                        )));
                    }
                    let delay = self.config.retry_base_delay * 2u32.pow(attempt - 1);
                    tracing::warn!(
                        code = event_codes::REGISTRY_SYNC_FAILED,
                        attempt,
                        max = self.config.max_retries,
                        delay_ms = delay.as_millis() as u64,
                        error = %msg,
                        "retrying EU registry request"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(RetryableError::Unreachable(msg)) => {
                    tracing::warn!(
                        code = event_codes::REGISTRY_SYNC_FAILED,
                        error = %msg,
                        "EU registry unreachable"
                    );
                    return Err(RetryableError::Unreachable(msg));
                }
                Err(RetryableError::Fatal(msg)) => {
                    return Err(RetryableError::Fatal(msg));
                }
            }
        }
    }
}

/// Internal error type for retry classification.
pub(super) enum RetryableError {
    /// Transient — can be retried (5xx, 429, timeout).
    Retryable(String),
    /// Registry is unreachable (DNS failure, connection refused).
    Unreachable(String),
    /// Non-retryable client error (4xx except 429).
    Fatal(String),
}

impl RetryableError {
    pub(super) fn into_dpp_error(self) -> DppError {
        match self {
            Self::Retryable(m) => DppError::Internal(format!("EU registry transient failure: {m}")),
            Self::Unreachable(m) => DppError::Internal(format!("EU registry unreachable: {m}")),
            Self::Fatal(m) => DppError::Internal(m),
        }
    }
}
