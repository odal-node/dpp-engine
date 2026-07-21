//! Configuration for the EU Registry HTTP adapter.

use std::time::Duration;

use dpp_registry::RegistryEndpoint;

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
    /// Submit payloads that fail local validation instead of refusing them.
    ///
    /// **Defaults to `false`, and production deployments should leave it there.**
    /// A registration is a regulatory submission: IR (EU) 2026/1778 Art. 19(2)
    /// obliges the operator to keep registry information "accurate, complete and
    /// up to date at all times", and the registry applies its own automated
    /// conformity checks on submission (Art. 8(7)) — so a payload we already
    /// know to be invalid is one we expect to be rejected anyway.
    ///
    /// The escape hatch exists because our local rules are an interpretation of
    /// the spec and may themselves be wrong; a false positive should be
    /// overridable without a code change. Setting it is a deliberate, logged
    /// decision rather than a default that has to be remembered at go-live.
    pub allow_invalid_payloads: bool,
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
            allow_invalid_payloads: false,
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
            allow_invalid_payloads: false,
        }
    }
}
