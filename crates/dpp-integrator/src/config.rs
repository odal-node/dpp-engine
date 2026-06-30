//! Runtime configuration for the integrator service, loaded from environment variables.

use anyhow::{Context, Result};

/// Runtime configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Port the integrator HTTP server listens on (default: 8004).
    pub port: u16,
    /// Tracing/logging level, e.g. `"info"` or `"debug,odal=trace"`.
    pub log_level: String,
    /// Base URL of `dpp-vault`, e.g. `http://vault:8001`.
    pub vault_service_url: String,
    /// Maximum number of concurrent vault requests during batch import.
    pub batch_concurrency: usize,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// **Optional**: `PORT` (default 8004), `LOG_LEVEL` (default "info"),
    /// `VAULT_SERVICE_URL` (default "http://localhost:8001"),
    /// `BATCH_CONCURRENCY` (default 20).
    ///
    /// # Errors
    ///
    /// Returns error if `PORT` or `BATCH_CONCURRENCY` cannot be parsed.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8004".into())
                .parse()
                .context("PORT must be a valid u16")?,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            vault_service_url: std::env::var("VAULT_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8001".into()),
            batch_concurrency: std::env::var("BATCH_CONCURRENCY")
                .unwrap_or_else(|_| "20".into())
                .parse()
                .context("BATCH_CONCURRENCY must be a positive integer")?,
        })
    }
}
