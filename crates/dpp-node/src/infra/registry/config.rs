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
