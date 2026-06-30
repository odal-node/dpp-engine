//! Environment variable helpers shared across all engine services.

use anyhow::{Context, Result};

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
