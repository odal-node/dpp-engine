//! Runtime configuration loaded from environment variables.

use anyhow::{Context, Result};

/// Configuration for the `dpp-resolver` binary.
///
/// All fields are populated by `from_env`; there is no config-file format.
#[derive(Debug, Clone)]
pub struct Config {
    /// Redis URL, e.g. `redis://localhost:6379`
    pub redis_url: String,
    /// Cache TTL in seconds (default: 30).
    ///
    /// N-3: this is the worst-case window in which a *suspended/recalled*
    /// passport can still be served from cache as a verified, active page,
    /// because the resolver caches the rendered response and the vault has no
    /// cross-service hook to evict it on suspend. A short default keeps that
    /// recall-blind window small; raise it only with an explicit acceptance of
    /// the recall-propagation latency. The complete fix is event-driven
    /// invalidation (vault publishes a cache-bust on suspend/archive).
    pub cache_ttl_secs: u64,

    /// Port to listen on (default: 8003)
    pub port: u16,
    pub log_level: String,

    /// Bind address for the **private** Prometheus metrics listener (`GET /metrics`).
    /// Loopback by default so it is never served on the public resolver port; set
    /// to a private interface for remote scraping, or empty to disable.
    pub metrics_addr: Option<String>,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required: `REDIS_URL`.
    /// Optional with defaults: `CACHE_TTL_SECS` (30), `RESOLVER_PORT`/`PORT` (8003),
    /// `LOG_LEVEL` (info), `METRICS_ADDR` (127.0.0.1:9101).
    ///
    /// # Errors
    /// Returns an error if any required variable is absent or an optional
    /// variable contains an unparseable value.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            redis_url: var("REDIS_URL")?,
            cache_ttl_secs: std::env::var("CACHE_TTL_SECS")
                .unwrap_or_else(|_| "30".into())
                .parse()
                .context("CACHE_TTL_SECS must be a valid u64")?,
            port: std::env::var("RESOLVER_PORT")
                .or_else(|_| std::env::var("PORT"))
                .unwrap_or_else(|_| "8003".into())
                .parse()
                .context("RESOLVER_PORT must be a valid u16")?,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            metrics_addr: match std::env::var("METRICS_ADDR") {
                Ok(s) if s.trim().is_empty() => None, // explicitly disabled
                Ok(s) => Some(s),
                Err(_) => Some("127.0.0.1:9101".into()), // private default
            },
        })
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}
