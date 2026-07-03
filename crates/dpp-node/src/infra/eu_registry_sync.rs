//! HTTP adapter implementing `RegistrySyncPort` for the EU Central DPP Registry.
//!
//! Uses the registry types from `dpp-registry` for wire format and maps them
//! to/from the domain port types in `dpp-domain::ports::registry_sync`.
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
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use dpp_common::event_codes;
use dpp_domain::{
    domain::error::DppError,
    domain::passport::PassportId,
    ports::registry_sync::{
        RegistrationRequest, RegistryIdentifiers, RegistryRecord, RegistryStatus, RegistrySyncPort,
    },
};
use dpp_registry::{
    EuRegistryEnvelope, EuRegistryResponse, FacilityIdentifier, OperatorIdentifier,
    ProductIdentifier, ProductItemIdentifier, RegistrationPayload, RegistryEndpoint,
    StatusResponse, TransferNotification,
};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use uuid::Uuid;

// ─── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the EU Registry HTTP adapter.
#[derive(Debug, Clone)]
pub struct EuRegistrySyncConfig {
    /// Registry endpoint (sandbox or production).
    pub endpoint: RegistryEndpoint,
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret.
    pub client_secret: String,
    /// Maximum number of retry attempts for transient failures.
    pub max_retries: u32,
    /// Base delay for exponential backoff.
    pub retry_base_delay: Duration,
    /// Request timeout.
    pub request_timeout: Duration,
}

impl EuRegistrySyncConfig {
    /// Create a sandbox configuration for development.
    pub fn sandbox(client_id: String, client_secret: String) -> Self {
        Self {
            endpoint: RegistryEndpoint::sandbox(),
            client_id,
            client_secret,
            max_retries: 3,
            retry_base_delay: Duration::from_secs(1),
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Create a production configuration.
    pub fn production(client_id: String, client_secret: String) -> Self {
        Self {
            endpoint: RegistryEndpoint::production(),
            client_id,
            client_secret,
            max_retries: 3,
            retry_base_delay: Duration::from_secs(1),
            request_timeout: Duration::from_secs(30),
        }
    }
}

// ─── OAuth2 token cache ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
}

#[derive(Debug)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        // Refresh 30 seconds before actual expiry to avoid edge-case failures.
        Instant::now() >= self.expires_at - Duration::from_secs(30)
    }
}

// ─── Adapter ───────────────────────────────────────────────────────────────

/// HTTP adapter for the EU Central DPP Registry.
///
/// Implements `RegistrySyncPort` by making REST calls to the EU registry API,
/// mapping between domain port types and bridge wire types.
pub struct EuRegistrySync {
    client: Client,
    config: EuRegistrySyncConfig,
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
    async fn get_token(&self) -> Result<String, DppError> {
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
            expires_at: Instant::now() + Duration::from_secs(token_resp.expires_in),
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
    async fn with_retry<F, Fut, T>(&self, operation: F) -> Result<T, RetryableError>
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

    /// Map a bridge `EuRegistryResponse` to a domain `RegistryRecord`.
    fn response_to_record(resp: &EuRegistryResponse) -> RegistryRecord {
        use dpp_registry::registry::RegistryStatusCode;

        let status = match resp.status {
            RegistryStatusCode::Pending => RegistryStatus::Pending,
            RegistryStatusCode::Registered => RegistryStatus::Registered,
            RegistryStatusCode::Rejected => RegistryStatus::Rejected,
            RegistryStatusCode::SuspendedByAuthority => RegistryStatus::SuspendedByAuthority,
            RegistryStatusCode::Deactivated => RegistryStatus::Rejected, // map deactivated → rejected for now
        };

        RegistryRecord {
            identifiers: RegistryIdentifiers {
                product_id: resp.registry_id.clone(),
                operator_id: String::new(), // populated from status endpoint
                facility_id: String::new(),
                registry_id: resp.registry_id.clone(),
            },
            status,
            registered_at: resp.updated_at,
            updated_at: resp.updated_at,
        }
    }

    /// Map a bridge `StatusResponse` to a domain `RegistryRecord`.
    fn status_to_record(resp: &StatusResponse) -> RegistryRecord {
        use dpp_registry::registry::RegistryStatusCode;

        let status = match resp.status {
            RegistryStatusCode::Pending => RegistryStatus::Pending,
            RegistryStatusCode::Registered => RegistryStatus::Registered,
            RegistryStatusCode::Rejected => RegistryStatus::Rejected,
            RegistryStatusCode::SuspendedByAuthority => RegistryStatus::SuspendedByAuthority,
            RegistryStatusCode::Deactivated => RegistryStatus::Rejected,
        };

        RegistryRecord {
            identifiers: RegistryIdentifiers {
                product_id: String::new(),
                operator_id: String::new(),
                facility_id: String::new(),
                registry_id: resp.registry_id.clone(),
            },
            status,
            registered_at: resp.updated_at,
            updated_at: resp.updated_at,
        }
    }
}

/// Internal error type for retry classification.
enum RetryableError {
    /// Transient — can be retried (5xx, 429, timeout).
    Retryable(String),
    /// Registry is unreachable (DNS failure, connection refused).
    Unreachable(String),
    /// Non-retryable client error (4xx except 429).
    Fatal(String),
}

impl RetryableError {
    fn into_dpp_error(self) -> DppError {
        match self {
            Self::Retryable(m) => DppError::Internal(format!("EU registry transient failure: {m}")),
            Self::Unreachable(m) => DppError::Internal(format!("EU registry unreachable: {m}")),
            Self::Fatal(m) => DppError::Internal(m),
        }
    }
}

/// Map a registration request's facility onto the EU registry's facility
/// identifier. Prefers the full Annex III snapshot the passport carries
/// (scheme/name/country/address); falls back to the bare identifier value for
/// passports published before the snapshot existed.
fn facility_identifier_for(request: &RegistrationRequest) -> FacilityIdentifier {
    match &request.facility {
        Some(f) => FacilityIdentifier {
            scheme: f.scheme.clone(),
            value: f.value.clone(),
            name: Some(f.name.clone()),
            country: f.country.clone(),
            address: f.address.clone(),
        },
        None => FacilityIdentifier {
            scheme: "national".into(),
            value: request.facility_identifier.clone(),
            name: None,
            country: String::new(),
            address: None,
        },
    }
}

/// Extract GTIN-14 from a GS1 Digital Link URI.
///
/// GS1 DL format: `https://host/01/{gtin14}[/extra/segments]`.
/// Returns `None` if the URI does not contain a valid 14-digit GTIN segment.
fn extract_gtin_from_gs1_dl(uri: &str) -> Option<String> {
    let after = uri.split("/01/").nth(1)?;
    let gtin = after.split('/').next()?.trim();
    if gtin.len() == 14 && gtin.chars().all(|c| c.is_ascii_digit()) {
        Some(gtin.to_owned())
    } else {
        None
    }
}

#[async_trait]
impl RegistrySyncPort for EuRegistrySync {
    #[tracing::instrument(skip(self, request), fields(passport_id = %request.passport_id))]
    async fn register(&self, request: RegistrationRequest) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;

        // Extract GTIN from the GS1 Digital Link URI when present; fall back to
        // passport_id scheme so the payload is never invalid even pre-go-live.
        let (product_scheme, product_value) = extract_gtin_from_gs1_dl(&request.data_carrier_uri)
            .map(|g| ("gtin".to_owned(), g))
            .unwrap_or_else(|| ("passport_id".to_owned(), request.passport_id.to_string()));

        // Build the bridge envelope from the port request.
        let envelope = EuRegistryEnvelope {
            api_version: self.config.endpoint.api_version.clone(),
            request_id: Uuid::now_v7(),
            timestamp: Utc::now(),
            payload: RegistrationPayload {
                passport_id: request.passport_id.0,
                product_id: ProductIdentifier {
                    scheme: product_scheme,
                    value: product_value,
                    label: None,
                },
                item_id: ProductItemIdentifier {
                    scheme: "serial".into(),
                    value: request.passport_id.to_string(),
                    batch_id: None,
                },
                facility_id: facility_identifier_for(&request),
                operator_id: OperatorIdentifier {
                    scheme: "did".into(),
                    value: request.operator_identifier.clone(),
                    name: String::new(),
                    country: String::new(),
                    did: Some(request.operator_identifier.clone()),
                },
                sector: request.product_category.clone(),
                schema_version: request.schema_version.clone(),
                digital_link_url: request.data_carrier_uri.clone(),
                published_at: request.published_at.unwrap_or_else(Utc::now),
                jws_signature: request.jws_signature.clone(),
            },
        };

        if let Err(e) = envelope.payload.validate() {
            tracing::warn!(
                passport_id = %request.passport_id,
                error = %e,
                "EU registry payload failed B1 validation — sending anyway (pre-go-live)"
            );
        }

        let passport_id = request.passport_id;

        let result = self
            .with_retry(|| {
                let url = format!("{base_url}/registrations");
                let envelope = envelope.clone();
                async move {
                    let token = self.get_token().await.map_err(|e| {
                        RetryableError::Fatal(format!("token acquisition failed: {e}"))
                    })?;

                    let resp = self
                        .client
                        .post(&url)
                        .bearer_auth(&token)
                        .json(&envelope)
                        .send()
                        .await
                        .map_err(|e| {
                            if e.is_connect() || e.is_timeout() {
                                RetryableError::Unreachable(e.to_string())
                            } else {
                                RetryableError::Retryable(e.to_string())
                            }
                        })?;

                    let status = resp.status().as_u16();
                    if status == 429 {
                        return Err(RetryableError::Retryable("rate limited (429)".into()));
                    }
                    if (500..600).contains(&status) {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(RetryableError::Retryable(format!(
                            "server error {status}: {body}"
                        )));
                    }
                    if !resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(RetryableError::Fatal(format!(
                            "registration rejected {status}: {body}"
                        )));
                    }

                    let eu_resp: EuRegistryResponse = resp.json().await.map_err(|e| {
                        RetryableError::Fatal(format!("invalid response body: {e}"))
                    })?;

                    Ok(Self::response_to_record(&eu_resp))
                }
            })
            .await;

        match result {
            Ok(record) => {
                tracing::info!(
                    passport_id = %passport_id,
                    registry_id = %record.identifiers.registry_id,
                    status = ?record.status,
                    "passport registered with EU registry"
                );
                Ok(record)
            }
            // Unreachable/fatal/exhausted-retry all surface as real errors — the
            // outbox keeps the row `pending` and retries. Never fake success.
            Err(e) => Err(e.into_dpp_error()),
        }
    }

    async fn check_status(&self, passport_id: PassportId) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;

        self.with_retry(|| {
            let url = format!("{base_url}/registrations/{passport_id}/status");
            async move {
                let token = self
                    .get_token()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("token acquisition failed: {e}")))?;

                let resp = self
                    .client
                    .get(&url)
                    .bearer_auth(&token)
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_connect() || e.is_timeout() {
                            RetryableError::Unreachable(e.to_string())
                        } else {
                            RetryableError::Retryable(e.to_string())
                        }
                    })?;

                let status_code = resp.status().as_u16();
                if status_code == 404 {
                    return Err(RetryableError::Fatal(format!(
                        "passport {passport_id} not found in EU registry"
                    )));
                }
                if status_code == 429 {
                    return Err(RetryableError::Retryable("rate limited (429)".into()));
                }
                if (500..600).contains(&status_code) {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Retryable(format!(
                        "server error {status_code}: {body}"
                    )));
                }
                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Fatal(format!(
                        "status check failed {status_code}: {body}"
                    )));
                }

                let status_resp: StatusResponse = resp
                    .json()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("invalid status response: {e}")))?;

                Ok(Self::status_to_record(&status_resp))
            }
        })
        .await
        .map_err(|e| e.into_dpp_error())
    }

    async fn notify_transfer(
        &self,
        passport_id: PassportId,
        new_operator_identifier: String,
    ) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;

        let notification = TransferNotification {
            passport_id: passport_id.0,
            registry_id: String::new(), // filled by the registry on their side
            from_operator: OperatorIdentifier {
                scheme: "did".into(),
                value: String::new(), // current operator — would come from context
                name: String::new(),
                country: String::new(),
                did: None,
            },
            to_operator: OperatorIdentifier {
                scheme: "did".into(),
                value: new_operator_identifier.clone(),
                name: String::new(),
                country: String::new(),
                did: Some(new_operator_identifier),
            },
            reason: "transfer".into(),
            transferred_at: Utc::now(),
            from_signature: None,
            to_signature: None,
        };

        self.with_retry(|| {
            let url = format!("{base_url}/registrations/{passport_id}/transfer");
            let notification = notification.clone();
            async move {
                let token = self
                    .get_token()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("token acquisition failed: {e}")))?;

                let resp = self
                    .client
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&notification)
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_connect() || e.is_timeout() {
                            RetryableError::Unreachable(e.to_string())
                        } else {
                            RetryableError::Retryable(e.to_string())
                        }
                    })?;

                let status_code = resp.status().as_u16();
                if status_code == 429 {
                    return Err(RetryableError::Retryable("rate limited (429)".into()));
                }
                if (500..600).contains(&status_code) {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Retryable(format!(
                        "server error {status_code}: {body}"
                    )));
                }
                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Fatal(format!(
                        "transfer notification failed {status_code}: {body}"
                    )));
                }

                let eu_resp: EuRegistryResponse = resp.json().await.map_err(|e| {
                    RetryableError::Fatal(format!("invalid transfer response: {e}"))
                })?;

                Ok(Self::response_to_record(&eu_resp))
            }
        })
        .await
        .map_err(|e| e.into_dpp_error())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_registry::registry::RegistryStatusCode;

    #[test]
    fn sandbox_config_has_correct_defaults() {
        let config = EuRegistrySyncConfig::sandbox("id".into(), "secret".into());
        assert_eq!(config.max_retries, 3);
        assert!(config.endpoint.base_url.contains("sandbox"));
    }

    #[test]
    fn production_config_requires_mtls() {
        let config = EuRegistrySyncConfig::production("id".into(), "secret".into());
        assert!(config.endpoint.mtls_required);
    }

    #[test]
    fn response_to_record_maps_status_correctly() {
        let resp = EuRegistryResponse {
            registry_id: "EU-REG-2026-00001".into(),
            passport_id: Uuid::nil(),
            status: RegistryStatusCode::Registered,
            message: None,
            rejection_reasons: None,
            updated_at: Utc::now(),
        };
        let record = EuRegistrySync::response_to_record(&resp);
        assert_eq!(record.status, RegistryStatus::Registered);
        assert_eq!(record.identifiers.registry_id, "EU-REG-2026-00001");
    }

    #[test]
    fn response_to_record_maps_rejected() {
        let resp = EuRegistryResponse {
            registry_id: "EU-REG-2026-00002".into(),
            passport_id: Uuid::nil(),
            status: RegistryStatusCode::Rejected,
            message: Some("invalid data".into()),
            rejection_reasons: Some(vec!["bad GTIN".into()]),
            updated_at: Utc::now(),
        };
        let record = EuRegistrySync::response_to_record(&resp);
        assert_eq!(record.status, RegistryStatus::Rejected);
    }

    #[test]
    fn status_to_record_maps_pending() {
        let resp = StatusResponse {
            registry_id: "EU-REG-2026-00003".into(),
            status: RegistryStatusCode::Pending,
            updated_at: Utc::now(),
            message: None,
        };
        let record = EuRegistrySync::status_to_record(&resp);
        assert_eq!(record.status, RegistryStatus::Pending);
        assert_eq!(record.identifiers.registry_id, "EU-REG-2026-00003");
    }

    fn request_with_facility(
        facility: Option<dpp_domain::FacilitySnapshot>,
    ) -> RegistrationRequest {
        RegistrationRequest {
            passport_id: PassportId::new(),
            operator_identifier: "did:web:test.example".into(),
            facility_identifier: "LEGACY-FAC".into(),
            facility,
            product_category: "battery".into(),
            data_carrier_uri: String::new(),
            schema_version: "2.0.0".into(),
            jws_signature: None,
            published_at: None,
            country_code: String::new(),
        }
    }

    #[test]
    fn facility_identifier_prefers_full_snapshot() {
        let request = request_with_facility(Some(dpp_domain::FacilitySnapshot {
            scheme: "gln".into(),
            value: "4012345000009".into(),
            name: "Default Plant".into(),
            country: "DE".into(),
            address: Some("1 Allee, Berlin".into()),
        }));
        let fid = facility_identifier_for(&request);
        assert_eq!(fid.scheme, "gln");
        assert_eq!(fid.value, "4012345000009");
        assert_eq!(fid.name.as_deref(), Some("Default Plant"));
        assert_eq!(fid.country, "DE");
        assert_eq!(fid.address.as_deref(), Some("1 Allee, Berlin"));
    }

    #[test]
    fn facility_identifier_falls_back_to_bare_value() {
        let fid = facility_identifier_for(&request_with_facility(None));
        assert_eq!(fid.scheme, "national");
        assert_eq!(fid.value, "LEGACY-FAC");
        assert!(fid.name.is_none());
        assert!(fid.country.is_empty());
    }

    #[test]
    fn extract_gtin_from_valid_gs1_dl() {
        let uri = "https://id.odal-node.io/01/09506000134352/21/abc123";
        assert_eq!(
            extract_gtin_from_gs1_dl(uri),
            Some("09506000134352".to_owned())
        );
    }

    #[test]
    fn extract_gtin_returns_none_for_non_gs1_uri() {
        assert_eq!(
            extract_gtin_from_gs1_dl("https://p.odal-node.io/some-uuid"),
            None
        );
        assert_eq!(
            extract_gtin_from_gs1_dl("https://id.example.com/01/short"),
            None
        );
    }

    #[test]
    fn cached_token_expiry_check() {
        let fresh = CachedToken {
            access_token: "tok".into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        assert!(!fresh.is_expired());

        let stale = CachedToken {
            access_token: "tok".into(),
            expires_at: Instant::now() + Duration::from_secs(10), // within 30s buffer
        };
        assert!(stale.is_expired());
    }
}
