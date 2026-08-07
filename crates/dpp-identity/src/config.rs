//! Runtime configuration for the identity service, loaded from environment variables.

use anyhow::{Context, Result};

/// Runtime configuration for the dpp-identity service.
///
/// All values are required unless the field carries a documented default.
///
/// `Debug` is implemented by hand: the derived one printed
/// `key_store_passphrase`, which decrypts this service's Ed25519 signing keys.
#[derive(Clone)]
pub struct Config {
    /// Path to the AES-256-GCM encrypted key store file.
    pub key_store_path: String,

    /// Passphrase used to derive the AES key for the key store.
    pub key_store_passphrase: String,

    /// The `did:web` base URL for this identity service, e.g. `https://identity.odal-node.io`
    pub did_web_base_url: String,

    /// Port to listen on (default: 8002)
    pub port: u16,
    pub log_level: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("key_store_path", &self.key_store_path)
            .field("key_store_passphrase", &dpp_common::config::REDACTED)
            .field("did_web_base_url", &self.did_web_base_url)
            .field("port", &self.port)
            .field("log_level", &self.log_level)
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// **Required**: `KEY_STORE_PATH`, `KEY_STORE_PASSPHRASE`, `DID_WEB_BASE_URL`.
    /// **Optional**: `PORT` (default 8002), `LOG_LEVEL` (default `"info"`).
    ///
    /// # Errors
    ///
    /// Returns an error if any required variable is absent or if `PORT` cannot
    /// be parsed as a valid port number.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            key_store_path: var("KEY_STORE_PATH")?,
            key_store_passphrase: var("KEY_STORE_PASSPHRASE")?,
            did_web_base_url: var("DID_WEB_BASE_URL")?,
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8002".into())
                .parse()
                .context("PORT must be a valid u16")?,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        })
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_key_store_passphrase() {
        let cfg = Config {
            key_store_path: "/var/lib/odal/keystore.json".into(),
            key_store_passphrase: "passphrase-must-not-leak".into(),
            did_web_base_url: "https://identity.example.com".into(),
            port: 8002,
            log_level: "info".into(),
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("passphrase-must-not-leak"),
            "Debug leaked the key store passphrase: {rendered}"
        );
        // The path is not a secret and is the field you actually need in a log.
        assert!(
            rendered.contains("/var/lib/odal/keystore.json"),
            "{rendered}"
        );
    }
}
