//! Environment variable helpers shared across all engine services.

use anyhow::{Context, Result};

/// What a redacted secret renders as. One constant so every `Debug` impl in the
/// workspace produces the same, greppable string.
pub const REDACTED: &str = "[redacted]";

/// Strip embedded credentials from a connection URL before logging or
/// debug-printing it.
///
/// `postgres://odal_app:s3cr3t@host:5432/odal` → `postgres://host:5432/odal`
///
/// Connection URLs are the easiest secret in the system to leak by accident:
/// they look like configuration rather than credentials, so they end up in
/// tracing fields, `anyhow` contexts and derived `Debug` output. Keeping the
/// host, port and path preserves everything needed to diagnose a connection
/// problem; only the userinfo goes.
///
/// Splits on the **last** `@` so a password containing `@` cannot smuggle part
/// of itself into the output.
#[must_use]
pub fn redact_url_credentials(url: &str) -> String {
    if let Some(at_pos) = url.rfind('@') {
        let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
        // A `@` before the scheme separator is not userinfo — leave it alone.
        if at_pos > scheme_end {
            return format!("{}{}", &url[..scheme_end], &url[at_pos + 1..]);
        }
    }
    url.to_owned()
}

/// Read a required environment variable by name.
pub fn required_var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

/// Read a `u16` port from an environment variable, defaulting to `default_port`.
pub fn port_var(name: &str, default_port: u16) -> Result<u16> {
    std::env::var(name)
        .unwrap_or_else(|_| default_port.to_string())
        .parse::<u16>()
        .with_context(|| format!("{name} must be a valid u16 port number"))
}

/// Read the `LOG_LEVEL` env var, defaulting to `"info"`.
pub fn log_level() -> String {
    std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into())
}

/// Parse a comma-separated `CORS_ALLOWED_ORIGINS` env var into a `Vec<String>`.
pub fn cors_origins() -> Vec<String> {
    std::env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userinfo_is_stripped_but_the_target_is_kept() {
        assert_eq!(
            redact_url_credentials("postgres://odal_app:s3cr3t@db.internal:5432/odal"),
            "postgres://db.internal:5432/odal"
        );
        assert_eq!(
            redact_url_credentials("redis://:s3cr3t@host:6379"),
            "redis://host:6379"
        );
    }

    #[test]
    fn a_password_containing_an_at_sign_does_not_leak() {
        // Splitting on the FIRST `@` would emit `p@ss@host`, publishing part of
        // the password. The last `@` is the userinfo delimiter.
        let out = redact_url_credentials("postgres://user:p@ssw@rd@host:5432/db");
        assert_eq!(out, "postgres://host:5432/db");
        assert!(!out.contains("ssw"), "password fragment survived: {out}");
    }

    #[test]
    fn a_url_without_credentials_is_unchanged() {
        assert_eq!(
            redact_url_credentials("postgres://host:5432/odal"),
            "postgres://host:5432/odal"
        );
        assert_eq!(
            redact_url_credentials("nats://localhost:4222"),
            "nats://localhost:4222"
        );
    }

    /// A bare `user@host` with no scheme has no `://`, so `scheme_end` is 0 and
    /// the guard must not treat the whole string as userinfo.
    #[test]
    fn a_schemeless_value_is_left_alone() {
        assert_eq!(redact_url_credentials("not-a-url"), "not-a-url");
    }
}
