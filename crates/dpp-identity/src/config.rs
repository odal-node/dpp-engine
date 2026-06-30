//! Runtime configuration for the identity service, loaded from environment variables.

use anyhow::{Context, Result};

/// Runtime configuration for the dpp-identity service.
///
/// All values are required unless the field carries a documented default.
#[derive(Debug, Clone)]
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
