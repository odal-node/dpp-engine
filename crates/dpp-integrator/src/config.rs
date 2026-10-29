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
    /// Maximum number of imports running at once (default 2).
    pub import_max_concurrent: usize,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// **Optional**: `PORT` (default 8004), `LOG_LEVEL` (default "info"),
    /// `VAULT_SERVICE_URL` (default "http://localhost:8001"),
    /// `BATCH_CONCURRENCY` (default 20), `IMPORT_MAX_CONCURRENT` (default 2).
    ///
    /// # Errors
    ///
    /// Returns error if `PORT`, `BATCH_CONCURRENCY` or `IMPORT_MAX_CONCURRENT`
    /// cannot be parsed, or if `IMPORT_MAX_CONCURRENT` is zero.
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
            import_max_concurrent: import_max_concurrent_from_env()?,
        })
    }
}

/// Read `IMPORT_MAX_CONCURRENT`: how many imports may run at once.
///
/// Zero is refused rather than clamped, since it would turn every import into a
/// `429` and the cause would not be visible from the response.
///
/// # Errors
///
/// Returns error if the value is not a positive integer.
pub fn import_max_concurrent_from_env() -> Result<usize> {
    let n: usize = std::env::var("IMPORT_MAX_CONCURRENT")
        .unwrap_or_else(|_| "2".into())
        .parse()
        .context("IMPORT_MAX_CONCURRENT must be a positive integer")?;
    anyhow::ensure!(n > 0, "IMPORT_MAX_CONCURRENT must be a positive integer");
    Ok(n)
}
