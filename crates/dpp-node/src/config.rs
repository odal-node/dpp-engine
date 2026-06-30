//! Unified runtime configuration for the `dpp-node` single binary.

use anyhow::{Context, Result};

/// Unified runtime config for the `dpp-node` single binary.
///
/// All service configs are merged here so a single `.env` file (or environment)
/// drives the full node. Each service library still has its own `Config::from_env()`
/// for standalone deployments.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    // ── Database ────────────────────────────────────────────────────────────
    /// PostgreSQL app connection URL.
    /// Example: `postgres://odal_app:<pass>@host:5432/odal`
    pub database_url: String,

    /// Privileged URL used to run sqlx migrations at startup.
    /// Example: `postgres://postgres:<pass>@host:5432/odal`
    /// If absent, migrations are assumed to be pre-applied (e.g. via `just migrate`).
    pub database_migrate_url: Option<String>,

    // ── Identity service ─────────────────────────────────────────────────────
    /// Filesystem path to the AES-256-GCM encrypted Ed25519 key store JSON file.
    pub key_store_path: String,
    /// Passphrase used to derive the AES key for the key store. Never logged.
    pub key_store_passphrase: String,
    /// Base URL for constructing `did:web` DID document identifiers.
    /// Example: `https://node.example.com`
    pub did_web_base_url: String,

    // ── Vault service ────────────────────────────────────────────────────────
    /// Comma-separated list of allowed CORS origins. Empty disables CORS.
    pub cors_allowed_origins: Vec<String>,

    // ── Auth ──────────────────────────────────────────────────────────────────
    /// Username for the local bootstrap Basic auth admin account.
    /// When set together with `admin_password`, a `LocalAuthProvider` is added.
    pub admin_username: Option<String>,
    /// Password for the local bootstrap Basic auth admin account.
    pub admin_password: Option<String>,

    // ── Integrator service ────────────────────────────────────────────────────
    /// Maximum concurrent vault requests during a batch import run (default 20).
    pub batch_concurrency: usize,

    // ── Event bus ──────────────────────────────────────────────────────────────
    /// NATS server URL, e.g. `nats://localhost:4222`. When absent, events are
    /// discarded silently (NoOp bus) — fine for self-hosted single-node setups.
    pub nats_url: Option<String>,

    // ── Node ──────────────────────────────────────────────────────────────────
    /// Port the node HTTP server listens on (default 8001). Read from `NODE_PORT`,
    /// falling back to `PORT` for compatibility.
    pub port: u16,
    /// Tracing/logging level, e.g. `"info"` or `"debug,odal=trace"`.
    pub log_level: String,

    /// Path to the directory containing `*.wasm` sector plugin files.
    pub plugins_dir: String,

    /// Bind address for the **private** Prometheus metrics listener (`GET /metrics`).
    /// Defaults to loopback so metrics are never served on the public API port;
    /// set to a private interface for remote scraping, or empty to disable.
    pub metrics_addr: Option<String>,
}

impl NodeConfig {
    /// Load unified node configuration from environment variables.
    ///
    /// **Required**: `DATABASE_URL`, `KEY_STORE_PATH`, `KEY_STORE_PASSPHRASE`,
    /// `DID_WEB_BASE_URL`.
    ///
    /// **Optional**: `DATABASE_MIGRATE_URL`, `NODE_PORT` / `PORT` (default 8001),
    /// `LOG_LEVEL` (default "info"), `CORS_ALLOWED_ORIGINS`, `ADMIN_USERNAME`,
    /// `ADMIN_PASSWORD`, `BATCH_CONCURRENCY` (default 20), `NATS_URL`,
    /// `PLUGINS_DIR` (default "./plugins"), `METRICS_ADDR` (default "127.0.0.1:9100").
    ///
    /// # Errors
    ///
    /// Returns error if any required variable is absent or if `NODE_PORT` /
    /// `BATCH_CONCURRENCY` cannot be parsed.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: var("DATABASE_URL")?,
            database_migrate_url: std::env::var("DATABASE_MIGRATE_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            key_store_path: var("KEY_STORE_PATH")?,
            key_store_passphrase: var("KEY_STORE_PASSPHRASE")?,
            did_web_base_url: var("DID_WEB_BASE_URL")?,
            admin_username: std::env::var("ADMIN_USERNAME")
                .ok()
                .filter(|s| !s.is_empty()),
            admin_password: std::env::var("ADMIN_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
            cors_allowed_origins: std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            batch_concurrency: std::env::var("BATCH_CONCURRENCY")
                .unwrap_or_else(|_| "20".into())
                .parse()
                .context("BATCH_CONCURRENCY must be a positive integer")?,
            nats_url: std::env::var("NATS_URL").ok().filter(|s| !s.is_empty()),
            port: std::env::var("NODE_PORT")
                .or_else(|_| std::env::var("PORT"))
                .unwrap_or_else(|_| "8001".into())
                .parse()
                .context("NODE_PORT must be a valid u16")?,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            plugins_dir: std::env::var("PLUGINS_DIR").unwrap_or_else(|_| "./plugins".into()),
            metrics_addr: match std::env::var("METRICS_ADDR") {
                Ok(s) if s.trim().is_empty() => None, // explicitly disabled
                Ok(s) => Some(s),
                Err(_) => Some("127.0.0.1:9100".into()), // private default
            },
        })
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Reset to a clean baseline, then set only the four required vars. Clearing
    /// first makes these tests hermetic: a `.env` loaded into the process (e.g.
    /// via `just`'s `set dotenv-load`) cannot leak optional vars such as
    /// `NODE_PORT` or `DATABASE_MIGRATE_URL` into the assertions below.
    fn set_required_env() {
        clear_env();
        unsafe {
            std::env::set_var(
                "DATABASE_URL",
                "postgres://odal_app:test@localhost:5432/odal",
            )
        };
        unsafe { std::env::set_var("KEY_STORE_PATH", "/tmp/keys.json") };
        unsafe { std::env::set_var("KEY_STORE_PASSPHRASE", "test-passphrase") };
        unsafe { std::env::set_var("DID_WEB_BASE_URL", "http://localhost") };
    }

    fn clear_env() {
        for key in &[
            "DATABASE_URL",
            "DATABASE_MIGRATE_URL",
            "KEY_STORE_PATH",
            "KEY_STORE_PASSPHRASE",
            "DID_WEB_BASE_URL",
            "ADMIN_USERNAME",
            "ADMIN_PASSWORD",
            "CORS_ALLOWED_ORIGINS",
            "BATCH_CONCURRENCY",
            "NATS_URL",
            "NODE_PORT",
            "PORT",
            "LOG_LEVEL",
            "PLUGINS_DIR",
            "METRICS_ADDR",
        ] {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    #[serial]
    fn loads_required_vars() {
        set_required_env();
        let cfg = NodeConfig::from_env().unwrap();
        assert_eq!(
            cfg.database_url,
            "postgres://odal_app:test@localhost:5432/odal"
        );
        assert!(cfg.database_migrate_url.is_none());
        clear_env();
    }

    #[test]
    #[serial]
    fn defaults_for_optional_vars() {
        set_required_env();
        let cfg = NodeConfig::from_env().unwrap();
        assert_eq!(cfg.port, 8001);
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.batch_concurrency, 20);
        assert_eq!(cfg.plugins_dir, "./plugins");
        assert!(cfg.cors_allowed_origins.is_empty());
        assert!(cfg.nats_url.is_none());
        clear_env();
    }

    #[test]
    #[serial]
    fn custom_port_override() {
        set_required_env();
        unsafe { std::env::set_var("NODE_PORT", "9090") };
        let cfg = NodeConfig::from_env().unwrap();
        assert_eq!(cfg.port, 9090);
        clear_env();
    }

    #[test]
    #[serial]
    fn port_fallback_to_legacy_port_var() {
        set_required_env();
        unsafe { std::env::set_var("PORT", "9091") };
        let cfg = NodeConfig::from_env().unwrap();
        assert_eq!(cfg.port, 9091);
        clear_env();
    }

    #[test]
    #[serial]
    fn cors_origins_parsed_from_csv() {
        set_required_env();
        unsafe {
            std::env::set_var(
                "CORS_ALLOWED_ORIGINS",
                "http://localhost:3000, https://app.odal-node.io",
            )
        };
        let cfg = NodeConfig::from_env().unwrap();
        assert_eq!(cfg.cors_allowed_origins.len(), 2);
        assert_eq!(cfg.cors_allowed_origins[0], "http://localhost:3000");
        assert_eq!(cfg.cors_allowed_origins[1], "https://app.odal-node.io");
        clear_env();
    }

    #[test]
    #[serial]
    fn missing_required_var_errors() {
        clear_env();
        let result = NodeConfig::from_env();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("DATABASE_URL"));
    }

    #[test]
    #[serial]
    fn invalid_port_errors() {
        set_required_env();
        unsafe { std::env::set_var("NODE_PORT", "not-a-number") };
        let result = NodeConfig::from_env();
        assert!(result.is_err());
        clear_env();
    }
}
