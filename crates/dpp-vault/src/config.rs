//! Runtime configuration for the vault service, loaded from environment variables.

use anyhow::{Context, Result};

/// Runtime configuration loaded from environment variables.
///
/// All values are required unless marked `Option`. No defaults except PORT and LOG_LEVEL.
///
/// `Debug` is implemented by hand: the derived one printed `admin_password` in
/// full and the database URL with its password inline.
#[derive(Clone)]
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

    /// Base URL the public resolver serves on, stamped into each passport's
    /// carrier (QR) URL at publish. Required, with no default — read through
    /// [`dpp_common::config::resolver_base_url`], the reader the node and the
    /// resolver use, so a standalone vault cannot sign a carrier under a
    /// different rule than the node does.
    pub resolver_base_url: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use dpp_common::config::{REDACTED, redact_url_credentials};
        f.debug_struct("Config")
            .field("database_url", &redact_url_credentials(&self.database_url))
            .field("identity_service_url", &self.identity_service_url)
            .field("port", &self.port)
            .field("log_level", &self.log_level)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("admin_username", &self.admin_username)
            .field(
                "admin_password",
                &self.admin_password.as_ref().map(|_| REDACTED),
            )
            .field("resolver_base_url", &self.resolver_base_url)
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// **Required**: `DATABASE_URL`, `IDENTITY_SERVICE_URL`, `RESOLVER_BASE_URL`.
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
            resolver_base_url: dpp_common::config::resolver_base_url()?,
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
            std::env::set_var("RESOLVER_BASE_URL", "https://resolver.example.com/");
        }
    }

    fn clear_all() {
        unsafe {
            for v in &[
                "DATABASE_URL",
                "IDENTITY_SERVICE_URL",
                "RESOLVER_BASE_URL",
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
        // Through the shared reader, so the trailing `/` is gone exactly as it
        // is for the node and the resolver.
        assert_eq!(cfg.resolver_base_url, "https://resolver.example.com");
        assert_eq!(cfg.port, 8001);
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.cors_allowed_origins.is_empty());
        clear_all();
    }

    /// The standalone vault signs carriers exactly as the node does, so it must
    /// refuse to start without the resolver's origin rather than fall back to
    /// one. It used to: `PassportService::new` defaulted to a hosted address
    /// that does not resolve, and this binary never overrode it.
    #[test]
    fn a_standalone_vault_refuses_to_start_without_a_resolver_base_url() {
        let _g = ENV_LOCK.lock().unwrap();
        set_required();
        unsafe {
            std::env::remove_var("RESOLVER_BASE_URL");
        }
        let err = Config::from_env().expect_err("no resolver origin, no vault");
        assert!(
            format!("{err:#}").contains("RESOLVER_BASE_URL"),
            "the refusal must name the variable to set: {err:#}"
        );
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

    #[test]
    fn debug_prints_no_secret_values() {
        let cfg = Config {
            database_url: "postgres://odal_app:pg-pass-must-not-leak@db:5432/odal".into(),
            identity_service_url: "http://identity:8002".into(),
            port: 8001,
            log_level: "info".into(),
            cors_allowed_origins: Vec::new(),
            admin_username: Some("odal-admin".into()),
            admin_password: Some("admin-pass-must-not-leak".into()),
            resolver_base_url: "https://resolver.example.com".into(),
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("admin-pass-must-not-leak"),
            "Debug leaked the admin password: {rendered}"
        );
        assert!(
            !rendered.contains("pg-pass-must-not-leak"),
            "Debug leaked the database password: {rendered}"
        );
        assert!(rendered.contains("db:5432"), "{rendered}");
    }
}
