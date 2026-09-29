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

/// The public origin every printed data carrier resolves at.
pub const RESOLVER_BASE_URL: &str = "RESOLVER_BASE_URL";

/// Read [`RESOLVER_BASE_URL`], the one value the node and the resolver must
/// agree on.
///
/// **Required, with no default, in every binary that reads it.** The node — or
/// a standalone vault — writes it into every passport's carrier URL at publish,
/// inside the signature, so a wrong value cannot be corrected afterwards. The
/// resolver builds its GS1 Digital Link redirects and canonical links from it.
/// All three used to fall back to a hosted address that does not resolve, and
/// the resolver's copy was never handed the operator's value by the compose
/// file — so every scanned carrier redirected to a dead host while the node's
/// own configuration looked right. A default here is a guess about where
/// another component lives, which is exactly what no binary can know.
///
/// # Errors
///
/// When the variable is unset or blank, or is not a URL this value can be (see
/// [`parse_resolver_base_url`]).
pub fn resolver_base_url() -> Result<String> {
    parse_resolver_base_url(std::env::var(RESOLVER_BASE_URL).ok().as_deref())
}

/// Validate a raw `RESOLVER_BASE_URL` value and return it without a trailing
/// `/`, so every caller joins paths onto the same form.
///
/// Refuses anything that is not an absolute `http` or `https` URL with a host,
/// and anything carrying credentials, a query or a fragment: each would be
/// concatenated into every carrier this node prints.
///
/// # Errors
///
/// Names [`RESOLVER_BASE_URL`] and says what is wrong with the value. The value
/// is echoed only with its credentials, query and fragment removed: a refusal
/// is a startup error that lands in logs, and a mistyped value is exactly the
/// one likely to carry something that should not.
pub fn parse_resolver_base_url(raw: Option<&str>) -> Result<String> {
    let value = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .with_context(|| {
            format!(
                "missing required env var: {RESOLVER_BASE_URL} — the public origin \
             this deployment's resolver serves at (e.g. http://localhost:8003 \
             on a laptop). It is written into every carrier at publish and \
             cannot be changed afterwards, so there is no default"
            )
        })?;
    let shown = shown_without_secrets(value);
    let url = url::Url::parse(value)
        .with_context(|| format!("{RESOLVER_BASE_URL} is not an absolute URL: {shown}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("{RESOLVER_BASE_URL} must be an http or https URL: {shown}");
    }
    if url.host_str().is_none_or(str::is_empty) {
        anyhow::bail!("{RESOLVER_BASE_URL} names no host: {shown}");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{RESOLVER_BASE_URL} must not carry credentials: {shown}");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!(
            "{RESOLVER_BASE_URL} must not carry a query or fragment (not shown): {shown}"
        );
    }
    Ok(value.trim_end_matches('/').to_owned())
}

/// A rejected value, fit to print: userinfo stripped by
/// [`redact_url_credentials`], and everything from the first `?` or `#` cut.
fn shown_without_secrets(value: &str) -> String {
    let redacted = redact_url_credentials(value);
    let end = redacted.find(['?', '#']).unwrap_or(redacted.len());
    redacted[..end].to_owned()
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

    /// A value with no `@` at all is returned untouched, whether or not it
    /// looks like a URL.
    #[test]
    fn a_value_with_no_userinfo_is_left_alone() {
        assert_eq!(redact_url_credentials("not-a-url"), "not-a-url");
    }

    /// With no `://`, `scheme_end` is 0, so everything up to the last `@` is
    /// treated as userinfo and dropped — `user@host` becomes `host`.
    ///
    /// Asserted because it is easy to read the guard as leaving schemeless
    /// input alone, which it does not. It errs toward removing too much rather
    /// than too little, so no credential escapes either way; every real caller
    /// passes a schemed connection URL.
    #[test]
    fn a_schemeless_value_is_redacted_up_to_the_last_at() {
        assert_eq!(redact_url_credentials("user@host"), "host");
        assert_eq!(redact_url_credentials("user:pw@host"), "host");
    }

    /// No value means no carrier anyone can scan, so there is nothing to fall
    /// back to — and the refusal has to say which variable, and why.
    #[test]
    fn an_absent_or_blank_resolver_base_url_is_refused_by_name() {
        for raw in [None, Some(""), Some("   ")] {
            let msg = parse_resolver_base_url(raw).unwrap_err().to_string();
            assert!(msg.contains(RESOLVER_BASE_URL), "{msg}");
            assert!(msg.contains("no default"), "{msg}");
        }
    }

    /// `localhost:8003` parses as a URL whose *scheme* is `localhost`, so the
    /// scheme check is what refuses the most likely typo rather than signing a
    /// relative-looking carrier into every passport.
    #[test]
    fn a_resolver_base_url_that_is_not_http_is_refused() {
        for raw in [
            "localhost:8003",
            "ftp://resolver.example",
            "/dpp",
            "file:///tmp/resolver",
        ] {
            assert!(parse_resolver_base_url(Some(raw)).is_err(), "{raw}");
        }
    }

    #[test]
    fn a_resolver_base_url_carrying_credentials_a_query_or_a_fragment_is_refused() {
        for raw in [
            "https://user:pw@resolver.example",
            "https://resolver.example/?tenant=a",
            "https://resolver.example/#top",
        ] {
            assert!(parse_resolver_base_url(Some(raw)).is_err(), "{raw}");
        }
    }

    /// A refusal is a startup error, so it lands in logs. Every path that
    /// echoes the value must leave out a password or a query token — including
    /// the refusals that are about something else entirely (here, the scheme).
    #[test]
    fn a_refused_resolver_base_url_never_echoes_its_secrets() {
        for raw in [
            "ftp://user:s3cret@resolver.example",
            "https://user:s3cret@resolver.example",
            "https://resolver.example/?token=s3cret",
            "https://resolver.example/#s3cret",
            "not a url with user:s3cret@",
        ] {
            let msg = parse_resolver_base_url(Some(raw)).unwrap_err().to_string();
            assert!(!msg.contains("s3cret"), "{raw} leaked into: {msg}");
            assert!(msg.contains(RESOLVER_BASE_URL), "{msg}");
        }
    }

    /// Both consumers join paths onto the value, and the GTIN redirect used it
    /// as-is — so a trailing `/` is dropped here, once, rather than by each.
    #[test]
    fn a_resolver_base_url_is_returned_without_a_trailing_slash() {
        assert_eq!(
            parse_resolver_base_url(Some(" http://localhost:8003/ ")).unwrap(),
            "http://localhost:8003"
        );
        assert_eq!(
            parse_resolver_base_url(Some("https://dpp.example.com/resolve/")).unwrap(),
            "https://dpp.example.com/resolve"
        );
    }
}
