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
    /// cannot be parsed, or if `IMPORT_MAX_CONCURRENT` is zero or more than a
    /// semaphore can hold.
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
/// # Errors
///
/// See [`parse_import_max_concurrent`].
pub fn import_max_concurrent_from_env() -> Result<usize> {
    parse_import_max_concurrent(std::env::var("IMPORT_MAX_CONCURRENT").ok().as_deref())
}

/// The `IMPORT_MAX_CONCURRENT` rule on a raw value, so it is tested without the
/// process environment. Unset is 2.
///
/// Zero is refused rather than clamped, since it would turn every import into a
/// `429` and the cause would not be visible from the response. A value above
/// what a semaphore can hold is refused too: `Semaphore::new` would panic on it
/// while the node was being assembled.
///
/// # Errors
///
/// Returns error if the value is not a positive integer no larger than
/// `tokio::sync::Semaphore::MAX_PERMITS`.
pub fn parse_import_max_concurrent(raw: Option<&str>) -> Result<usize> {
    let n: usize = raw
        .unwrap_or("2")
        .parse()
        .context("IMPORT_MAX_CONCURRENT must be a positive integer")?;
    anyhow::ensure!(
        (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&n),
        "IMPORT_MAX_CONCURRENT must be between 1 and {}",
        tokio::sync::Semaphore::MAX_PERMITS
    );
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_means_two_imports_at_once() {
        assert_eq!(parse_import_max_concurrent(None).unwrap(), 2);
    }

    #[test]
    fn a_positive_value_within_the_limit_is_taken_as_given() {
        assert_eq!(parse_import_max_concurrent(Some("1")).unwrap(), 1);
        assert_eq!(parse_import_max_concurrent(Some("8")).unwrap(), 8);
        let max = tokio::sync::Semaphore::MAX_PERMITS;
        assert_eq!(
            parse_import_max_concurrent(Some(&max.to_string())).unwrap(),
            max
        );
    }

    /// 🚨 Zero would answer every import with `429`, so it is refused at boot
    /// instead of being clamped to something the operator did not write.
    #[test]
    fn a_zero_import_max_concurrent_is_refused() {
        let err = parse_import_max_concurrent(Some("0")).unwrap_err();
        assert!(err.to_string().contains("between 1 and"), "{err}");
    }

    /// 🚨 `Semaphore::new` panics above `MAX_PERMITS`, so the value has to be
    /// refused where the configuration is read, not where the node is built.
    #[test]
    fn a_value_beyond_what_a_semaphore_can_hold_is_refused() {
        let over = (tokio::sync::Semaphore::MAX_PERMITS + 1).to_string();
        assert!(parse_import_max_concurrent(Some(&over)).is_err());
        assert!(parse_import_max_concurrent(Some(&usize::MAX.to_string())).is_err());
    }

    #[test]
    fn something_that_is_not_a_number_is_refused() {
        for bad in ["", "two", "-1", "2.5", " 2"] {
            assert!(parse_import_max_concurrent(Some(bad)).is_err(), "{bad:?}");
        }
    }
}
