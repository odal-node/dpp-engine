//! Runtime configuration for the vault service, loaded from environment variables.

use anyhow::{Context, Result};

/// Runtime configuration loaded from environment variables.
///
/// All values are required unless marked `Option`. No defaults except PORT and LOG_LEVEL.
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL app connection URL.
    /// Example: `postgres://odal_app:<pass>@host:5432/odal`
    pub database_url: String,

    /// Internal URL of dpp-identity, e.g. `http://identity:8002`
    pub identity_service_url: String,

    /// Port to listen on (default: 8001)
    pub port: u16,
    pub log_level: String,

    /// Comma-separated list of origins allowed for CORS requests.
    /// Empty (default) disables CORS — correct for server-side API-key access.
    pub cors_allowed_origins: Vec<String>,

    /// Optional local-admin credentials. When both are set, a Basic-auth
    /// `LocalAuthProvider` is wired alongside the API-key provider (used to
    /// mint the first API key via the CLI before any key exists).
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// **Required**: `DATABASE_URL`, `IDENTITY_SERVICE_URL`.
    /// **Optional**: `PORT` (default 8001), `LOG_LEVEL` (default `"info"`),
    /// `CORS_ALLOWED_ORIGINS` (default empty), `ADMIN_USERNAME`, `ADMIN_PASSWORD`.
    ///
    /// # Errors
    ///
    /// Returns an error if any required variable is absent or if `PORT` cannot
    /// be parsed as a valid port number.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: var("DATABASE_URL")?,
            identity_service_url: var("IDENTITY_SERVICE_URL")?,
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8001".into())
                .parse()
                .context("PORT must be a valid u16")?,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            cors_allowed_origins: std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            admin_username: std::env::var("ADMIN_USERNAME")
                .ok()
                .filter(|s| !s.is_empty()),
            admin_password: std::env::var("ADMIN_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn set_required() {
        unsafe {
            std::env::set_var(
                "DATABASE_URL",
                "postgres://odal_app:test@localhost:5432/odal",
            );
            std::env::set_var("IDENTITY_SERVICE_URL", "http://identity:8002");
        }
    }

    fn clear_all() {
        unsafe {
            for v in &[
                "DATABASE_URL",
                "IDENTITY_SERVICE_URL",
                "PORT",
                "LOG_LEVEL",
                "CORS_ALLOWED_ORIGINS",
            ] {
                std::env::remove_var(v);
            }
        }
    }

    #[test]
    fn all_required_fields_parse() {
        let _g = ENV_LOCK.lock().unwrap();
        set_required();
        unsafe {
            std::env::remove_var("PORT");
            std::env::remove_var("LOG_LEVEL");
            std::env::remove_var("CORS_ALLOWED_ORIGINS");
        }

        let cfg = Config::from_env().unwrap();
        assert_eq!(
            cfg.database_url,
            "postgres://odal_app:test@localhost:5432/odal"
        );
        assert_eq!(cfg.identity_service_url, "http://identity:8002");
        assert_eq!(cfg.port, 8001);
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.cors_allowed_origins.is_empty());
        clear_all();
    }

    #[test]
    fn port_and_log_level_are_overridable() {
        let _g = ENV_LOCK.lock().unwrap();
        set_required();
        unsafe {
            std::env::set_var("PORT", "9000");
            std::env::set_var("LOG_LEVEL", "debug");
        }

        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.log_level, "debug");
        clear_all();
    }

    #[test]
    fn cors_origins_parsed_from_comma_list() {
        let _g = ENV_LOCK.lock().unwrap();
        set_required();
        unsafe {
            std::env::set_var(
                "CORS_ALLOWED_ORIGINS",
                "https://a.example.com, https://b.example.com",
            );
        }

        let cfg = Config::from_env().unwrap();
        assert_eq!(
            cfg.cors_allowed_origins,
            vec!["https://a.example.com", "https://b.example.com"]
        );
        clear_all();
    }

    #[test]
    fn missing_required_var_returns_error() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        assert!(Config::from_env().is_err());
    }
}
