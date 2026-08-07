//! Configuration for the EU Registry HTTP adapter.

use std::time::Duration;

use dpp_registry::RegistryEndpoint;

/// Configuration for the EU Registry HTTP adapter.
///
/// `Debug` is implemented by hand: the derived one printed `client_secret` in
/// full through any `{:?}` — a `tracing` field, an `anyhow` context, a panic
/// message — which is enough to put an OAuth2 credential into the logs of a
/// node nobody thought was handling secrets at that moment.
#[derive(Clone)]
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
    /// A registration is a regulatory submission: the operator must keep registry
    /// information accurate, complete and up to date at all times, and the
    /// registry applies its own automated conformity checks on submission — so a
    /// payload we already know to be invalid is one we expect to be rejected
    /// anyway.
    ///
    /// The escape hatch exists because our local rules are an interpretation of
    /// the spec and may themselves be wrong; a false positive should be
    /// overridable without a code change. Setting it is a deliberate, logged
    /// decision rather than a default that has to be remembered at go-live.
    pub allow_invalid_payloads: bool,
}

impl std::fmt::Debug for EuRegistrySyncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EuRegistrySyncConfig")
            .field("endpoint", &self.endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .field("max_retries", &self.max_retries)
            .field("retry_base_delay", &self.retry_base_delay)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_client_secret() {
        let cfg = EuRegistrySyncConfig::sandbox(
            "client-id".to_owned(),
            "oauth-secret-must-not-leak".to_owned(),
        );
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("oauth-secret-must-not-leak"),
            "Debug leaked the client secret: {rendered}"
        );
        // The client id is not a secret and stays — it is how you tell two
        // registry configurations apart in a log.
        assert!(rendered.contains("client-id"), "{rendered}");
    }
}
