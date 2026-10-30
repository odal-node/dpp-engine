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
    /// This is the worst-case window in which a *suspended/recalled*
    /// passport can still be served from cache as a verified, active page,
    /// because the resolver caches the rendered response and the vault has no
    /// cross-service hook to evict it on suspend. A short default keeps that
    /// recall-blind window small; raise it only with an explicit acceptance of
    /// the recall-propagation latency. The complete fix is event-driven
    /// invalidation (vault publishes a cache-bust on suspend/retire).
    pub cache_ttl_secs: u64,

    /// Port to listen on (default: 8003)
    pub port: u16,
    pub log_level: String,

    /// Bind address for the **private** Prometheus metrics listener (`GET /metrics`).
    /// Loopback by default so it is never served on the public resolver port; set
    /// to a private interface for remote scraping, or empty to disable.
    pub metrics_addr: Option<String>,

    /// This resolver's own public origin — what the GS1 Digital Link redirects
    /// and canonical links are built on. Required, with no default, and read
    /// through [`dpp_common::config::resolver_base_url`], the same reader the
    /// node stamps carriers with.
    pub resolver_base_url: String,

    /// Requests a minute one client address may make (default 120, at least 1).
    pub rate_limit_rpm: u32,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required: `REDIS_URL`, `RESOLVER_BASE_URL`.
    /// Optional with defaults: `CACHE_TTL_SECS` (30), `RESOLVER_PORT`/`PORT` (8003),
    /// `LOG_LEVEL` (info), `METRICS_ADDR` (127.0.0.1:9101), `RATE_LIMIT_RPM` (120).
    ///
    /// # Errors
    /// Returns an error if any required variable is absent or an optional
    /// variable contains an unparseable value.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            redis_url: var("REDIS_URL")?,
            resolver_base_url: dpp_common::config::resolver_base_url()?,
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
            rate_limit_rpm: rate_limit_rpm_from(std::env::var("RATE_LIMIT_RPM"))?,
        })
    }
}

/// The `RATE_LIMIT_RPM` rule on a raw value, so it is tested without the process
/// environment. Unset is 120, and so is a blank value: `RATE_LIMIT_RPM=` in a
/// copied `.env.example` means "not set", as it does for the node's optional
/// settings and for Compose's `${RATE_LIMIT_RPM:-120}`.
///
/// # Errors
/// Returns an error if the value is not a whole number, or is zero.
pub fn parse_rate_limit_rpm(raw: Option<&str>) -> Result<u32> {
    let rpm: u32 = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("120")
        .parse()
        .context("RATE_LIMIT_RPM must be a whole number of requests a minute")?;
    anyhow::ensure!(
        rpm >= 1,
        "RATE_LIMIT_RPM must be at least 1: 0 would refuse every request"
    );
    Ok(rpm)
}

/// `RATE_LIMIT_RPM` from the result of reading it. Only a variable that is not
/// there falls back to the default: one that is set to something that is not valid
/// Unicode is not a count, so it is refused like any other value that is not one.
fn rate_limit_rpm_from(read: Result<String, std::env::VarError>) -> Result<u32> {
    match read {
        Ok(value) => parse_rate_limit_rpm(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_rate_limit_rpm(None),
        Err(e) => Err(anyhow::Error::new(e).context("RATE_LIMIT_RPM must be valid Unicode")),
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_is_120_a_minute() {
        assert_eq!(parse_rate_limit_rpm(None).unwrap(), 120);
    }

    #[test]
    fn a_whole_number_is_taken_as_written() {
        assert_eq!(parse_rate_limit_rpm(Some("600")).unwrap(), 600);
        assert_eq!(parse_rate_limit_rpm(Some("1")).unwrap(), 1);
    }

    /// A value that is not a count is refused at boot. Falling back to 120 would
    /// leave an operator who wrote `6,000` or `100/min` believing a limit is in
    /// force that is not the one they set; the other numeric settings here
    /// (`CACHE_TTL_SECS`) already refuse to start on one.
    #[test]
    fn a_value_that_is_not_a_count_is_refused() {
        for bad in ["abc", "6,000", "100/min", "-1", "1.5", "4294967296"] {
            let err = parse_rate_limit_rpm(Some(bad)).unwrap_err().to_string();
            assert!(err.contains("RATE_LIMIT_RPM"), "{bad:?}: {err}");
        }
    }

    /// `RATE_LIMIT_RPM=` in a copied `.env.example` means "not set", as it does for
    /// the node's optional settings, and it is what Compose's `${RATE_LIMIT_RPM:-120}`
    /// already does with a blank value. The two must agree, or the same `.env` starts
    /// a stack and refuses to start the binary.
    #[test]
    fn a_blank_value_reads_as_unset() {
        for blank in ["", " ", "\t"] {
            assert_eq!(parse_rate_limit_rpm(Some(blank)).unwrap(), 120, "{blank:?}");
        }
    }

    /// A value that is not valid Unicode is not a count either. Reading it with
    /// `.ok()` turned it into "unset", so the resolver started on 120.
    #[test]
    fn a_value_that_is_not_unicode_is_refused() {
        let read = Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "x",
        )));
        let err = rate_limit_rpm_from(read).unwrap_err().to_string();
        assert!(err.contains("RATE_LIMIT_RPM"), "{err}");
        assert!(err.contains("Unicode"), "{err}");
    }

    #[test]
    fn an_unset_variable_is_the_default_and_a_set_one_is_taken() {
        let unset = Err(std::env::VarError::NotPresent);
        assert_eq!(rate_limit_rpm_from(unset).unwrap(), 120);
        assert_eq!(rate_limit_rpm_from(Ok("600".into())).unwrap(), 600);
    }

    /// Zero would refuse every request, and the cause would not be visible from
    /// the `429` it answers with, so it is refused rather than clamped.
    #[test]
    fn zero_is_refused_because_it_would_refuse_every_request() {
        let err = parse_rate_limit_rpm(Some("0")).unwrap_err().to_string();
        assert!(err.contains("at least 1"), "{err}");
    }
}
