//! Unified runtime configuration for the `dpp-node` single binary.

use anyhow::{Context, Result};

/// Unified runtime config for the `dpp-node` single binary.
///
/// All service configs are merged here so a single `.env` file (or environment)
/// drives the full node. Each service library still has its own `Config::from_env()`
/// for standalone deployments.
///
/// `Debug` is implemented by hand below. The derived one printed
/// `key_store_passphrase` and `admin_password` in full, and the two database
/// URLs carry their passwords inline — so a single `{:?}` in a tracing field,
/// an `anyhow` context or a panic message put the node's signing-key passphrase
/// into the logs. The "Never logged" note on `key_store_passphrase` was an
/// aspiration the type did not enforce.
#[derive(Clone)]
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

    // ── Webhooks ────────────────────────────────────────────────────────────
    /// Allow webhook targets on private/loopback addresses. Off by default (the
    /// SSRF guard refuses non-public receivers); a self-hosting operator whose
    /// receiver lives on their own internal network sets this to opt in.
    pub webhook_allow_private_targets: bool,

    // ── Resolver ────────────────────────────────────────────────────────────
    /// Base URL the public resolver serves on, stamped into each passport's
    /// carrier (QR) URL at publish. Defaults to `https://id.odal-node.io`; a
    /// self-hoster sets `RESOLVER_BASE_URL` to their own domain so printed
    /// labels carry it. Must match the resolver deployment's own base.
    pub resolver_base_url: String,
    /// Public base URL under which this deployment serves its continuity
    /// snapshots, declared to the EU registry as each passport's back-up link.
    ///
    /// `None` unless `SNAPSHOT_PUBLIC_BASE_URL` is set. Writing snapshots to
    /// object storage does not make them reachable, so this is deliberately a
    /// separate, explicit statement that they *are* served — and no back-up is
    /// declared until an operator makes it.
    pub snapshot_public_base_url: Option<String>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use dpp_common::config::{REDACTED, redact_url_credentials};
        // Optional secrets render as presence, not value: whether an admin
        // password is configured is a real diagnostic, its value never is.
        let opt_secret = |v: &Option<String>| v.as_ref().map(|_| REDACTED);
        f.debug_struct("NodeConfig")
            .field("database_url", &redact_url_credentials(&self.database_url))
            .field(
                "database_migrate_url",
                &self
                    .database_migrate_url
                    .as_deref()
                    .map(redact_url_credentials),
            )
            .field("key_store_path", &self.key_store_path)
            .field("key_store_passphrase", &REDACTED)
            .field("did_web_base_url", &self.did_web_base_url)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("admin_username", &self.admin_username)
            .field("admin_password", &opt_secret(&self.admin_password))
            .field("batch_concurrency", &self.batch_concurrency)
            .field(
                "nats_url",
                &self.nats_url.as_deref().map(redact_url_credentials),
            )
            .field("port", &self.port)
            .field("log_level", &self.log_level)
            .field("plugins_dir", &self.plugins_dir)
            .field("metrics_addr", &self.metrics_addr)
            .field(
                "webhook_allow_private_targets",
                &self.webhook_allow_private_targets,
            )
            .field("resolver_base_url", &self.resolver_base_url)
            .finish()
    }
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
    /// `PLUGINS_DIR` (default "./plugins"), `METRICS_ADDR` (default "127.0.0.1:9100"),
    /// `RESOLVER_BASE_URL` (default `https://id.odal-node.io`).
    ///
    /// # Errors
    ///
    /// Returns error if any required variable is absent or if `NODE_PORT` /
    /// `BATCH_CONCURRENCY` cannot be parsed.
    pub fn from_env() -> Result<Self> {
        // Read the required vars in declaration order so an empty environment
        // still reports `DATABASE_URL` first — `missing_required_var_errors`
        // pins that, and "which variable is missing" is the whole value of the
        // message. The credential guard runs after, on values already read.
        let database_url = var("DATABASE_URL")?;
        let key_store_path = var("KEY_STORE_PATH")?;
        let key_store_passphrase = var("KEY_STORE_PASSPHRASE")?;
        let did_web_base_url = var("DID_WEB_BASE_URL")?;
        let admin_username = std::env::var("ADMIN_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let admin_password = std::env::var("ADMIN_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());
        ensure_bootstrap_credentials(
            admin_username.as_deref(),
            admin_password.as_deref(),
            &key_store_passphrase,
        )?;

        Ok(Self {
            database_url,
            database_migrate_url: std::env::var("DATABASE_MIGRATE_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            key_store_path,
            key_store_passphrase,
            did_web_base_url,
            admin_username,
            admin_password,
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
            webhook_allow_private_targets: std::env::var("WEBHOOK_ALLOW_PRIVATE_TARGETS")
                .map(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
            resolver_base_url: std::env::var("RESOLVER_BASE_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://id.odal-node.io".into()),
            snapshot_public_base_url: std::env::var("SNAPSHOT_PUBLIC_BASE_URL")
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        })
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

/// Credential values that shipped as live assignments in `.env.example`, so a
/// node bootstrapped with `cp .env.example .env` inherited them verbatim.
///
/// Matched case-insensitively and after trimming, because the failure being
/// prevented is "the operator never changed this", not "the operator chose a
/// weak-but-deliberate value" — judging general password strength is not this
/// function's job and would be the wrong control to put at boot.
const SHIPPED_ADMIN_USERNAME: &str = "admin";
const SHIPPED_ADMIN_PASSWORD: &str = "admin";
const SHIPPED_KEY_STORE_PASSPHRASE: &str = "dev-passphrase-change-in-prod";

/// Escape hatch for the one legitimate case: a throwaway local node where the
/// placeholder values are exactly what you want.
const ALLOW_DEV_CREDENTIALS: &str = "ALLOW_DEV_CREDENTIALS";

/// Refuse to boot on the credential placeholders this repo used to ship.
///
/// `ADMIN_USERNAME`/`ADMIN_PASSWORD` back a `Basic`-scheme credential that
/// authenticates as full admin with no API-key row behind it — so it also
/// bypasses the self-revocation guard — and `KEY_STORE_PASSPHRASE` protects the
/// Ed25519 key every passport is signed with. Both were live assignments in
/// `.env.example`, whose own header says `cp .env.example .env`, so the default
/// path produced a node whose most powerful credential was public knowledge.
///
/// This is a pure function so it is testable without mutating process-global
/// environment state, matching `ensure_signing_policy` in `plugins.rs`. It
/// deliberately checks only for the *shipped literals*: a boot-time password
/// strength policy is a different control with a different failure mode, and
/// bundling the two would make this one arguable.
///
/// An empty passphrase is refused unconditionally. `.env.example` now ships
/// `KEY_STORE_PASSPHRASE=` (present but blank) so the template stays copyable,
/// and `var()` only proves the variable *exists* — blank would otherwise sail
/// through and derive a key from nothing.
///
/// # Errors
/// A message naming the offending variable and how to fix it, unless
/// `ALLOW_DEV_CREDENTIALS=true` is set.
fn ensure_bootstrap_credentials(
    admin_username: Option<&str>,
    admin_password: Option<&str>,
    key_store_passphrase: &str,
) -> Result<()> {
    if key_store_passphrase.trim().is_empty() {
        anyhow::bail!(
            "KEY_STORE_PASSPHRASE is empty — refusing to boot. It protects the signing key \
             every passport is verified against. Generate one with `openssl rand -base64 32`."
        );
    }

    let allow_dev = std::env::var(ALLOW_DEV_CREDENTIALS)
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_dev {
        tracing::warn!(
            "{ALLOW_DEV_CREDENTIALS}=true — placeholder credentials accepted. \
             Never set this on a node reachable by anyone else."
        );
        return Ok(());
    }

    let matches_shipped = |value: &str, shipped: &str| value.trim().eq_ignore_ascii_case(shipped);

    if matches_shipped(key_store_passphrase, SHIPPED_KEY_STORE_PASSPHRASE) {
        anyhow::bail!(
            "KEY_STORE_PASSPHRASE is still the placeholder this repo used to ship — refusing \
             to boot. Anyone with the repository can decrypt this key store and forge \
             passports that verify against your DID. Generate one with \
             `openssl rand -base64 32`, or set {ALLOW_DEV_CREDENTIALS}=true for a throwaway \
             local node."
        );
    }

    // Only a *pair* constructs the local-admin provider, so only a pair is a
    // reachable credential. A stray `ADMIN_USERNAME=admin` with no password
    // authenticates nothing and must not block a boot.
    if let (Some(user), Some(pass)) = (admin_username, admin_password)
        && matches_shipped(user, SHIPPED_ADMIN_USERNAME)
        && matches_shipped(pass, SHIPPED_ADMIN_PASSWORD)
    {
        anyhow::bail!(
            "ADMIN_USERNAME/ADMIN_PASSWORD are still `admin`/`admin`, the placeholder this \
             repo used to ship — refusing to boot. That credential authenticates as full \
             admin over HTTP Basic and can revoke every API key. Set both to values you \
             generate, unset them once the first API key is minted, or set \
             {ALLOW_DEV_CREDENTIALS}=true for a throwaway local node."
        );
    }

    Ok(())
}

#[cfg(test)]
mod bootstrap_credentials {
    //! The guard is a pure function precisely so these need no env mutation and
    //! no `#[serial]` — the one exception being the escape hatch, which reads a
    //! process-global var by design.
    use super::{ALLOW_DEV_CREDENTIALS, ensure_bootstrap_credentials};

    const GOOD_PASS: &str = "PmDq0aUu0kXwQ0nS+9kQ0Q==";

    #[test]
    fn the_shipped_admin_pair_is_refused() {
        let err = ensure_bootstrap_credentials(Some("admin"), Some("admin"), GOOD_PASS)
            .expect_err("`admin`/`admin` must not boot");
        assert!(err.to_string().contains("ADMIN_USERNAME/ADMIN_PASSWORD"));
    }

    /// Trimming and case-folding, because the failure being prevented is "never
    /// changed it", and `ADMIN_PASSWORD=Admin ` is the same non-change.
    #[test]
    fn the_shipped_pair_is_matched_loosely() {
        assert!(ensure_bootstrap_credentials(Some(" Admin"), Some("ADMIN "), GOOD_PASS).is_err());
    }

    #[test]
    fn the_shipped_key_store_passphrase_is_refused() {
        let err = ensure_bootstrap_credentials(None, None, "dev-passphrase-change-in-prod")
            .expect_err("the shipped passphrase must not boot");
        assert!(err.to_string().contains("KEY_STORE_PASSPHRASE"));
    }

    /// `.env.example` ships `KEY_STORE_PASSPHRASE=` so the template stays
    /// copyable. `var()` only proves the variable exists, so blank has to be
    /// refused here or it derives a key from nothing.
    #[test]
    fn an_empty_key_store_passphrase_is_refused() {
        for blank in ["", "   ", "\t"] {
            assert!(
                ensure_bootstrap_credentials(None, None, blank).is_err(),
                "{blank:?} must be refused"
            );
        }
    }

    /// Only a *pair* constructs the local-admin provider, so a lone
    /// `ADMIN_USERNAME=admin` authenticates nothing and must not block a boot.
    #[test]
    fn a_lone_shipped_username_is_not_a_credential() {
        assert!(ensure_bootstrap_credentials(Some("admin"), None, GOOD_PASS).is_ok());
        assert!(ensure_bootstrap_credentials(None, Some("admin"), GOOD_PASS).is_ok());
    }

    /// The guard checks for the shipped literals, not for password strength.
    /// A weak-but-deliberate choice is the operator's to make; conflating the
    /// two would make this guard arguable and therefore disabled.
    #[test]
    fn a_deliberate_choice_is_not_second_guessed() {
        assert!(ensure_bootstrap_credentials(Some("root"), Some("hunter2"), "hunter2").is_ok());
    }

    #[test]
    fn no_admin_credentials_at_all_is_the_recommended_state() {
        assert!(ensure_bootstrap_credentials(None, None, GOOD_PASS).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn the_escape_hatch_allows_the_placeholders() {
        // Safety: `#[serial]`, so no concurrent env mutation in this process.
        unsafe { std::env::set_var(ALLOW_DEV_CREDENTIALS, "true") };
        let allowed = ensure_bootstrap_credentials(
            Some("admin"),
            Some("admin"),
            "dev-passphrase-change-in-prod",
        );
        unsafe { std::env::remove_var(ALLOW_DEV_CREDENTIALS) };
        assert!(allowed.is_ok(), "the dev escape hatch must permit them");
    }

    /// The escape hatch is for placeholders, not for an absent passphrase —
    /// there is no key to derive from an empty string in any environment.
    #[test]
    #[serial_test::serial]
    fn the_escape_hatch_does_not_permit_an_empty_passphrase() {
        unsafe { std::env::set_var(ALLOW_DEV_CREDENTIALS, "true") };
        let refused = ensure_bootstrap_credentials(None, None, "");
        unsafe { std::env::remove_var(ALLOW_DEV_CREDENTIALS) };
        assert!(refused.is_err());
    }
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
            "WEBHOOK_ALLOW_PRIVATE_TARGETS",
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

    /// Asserts on the **secret values**, not on the marker. A test that only
    /// checked for `[redacted]` would pass on output that printed the marker for
    /// one field and the passphrase for another.
    #[test]
    #[serial]
    fn debug_prints_no_secret_values() {
        clear_env();
        unsafe {
            std::env::set_var(
                "DATABASE_URL",
                "postgres://odal_app:pg-pass-must-not-leak@db.internal:5432/odal",
            );
            std::env::set_var(
                "DATABASE_MIGRATE_URL",
                "postgres://postgres:migrate-pass-must-not-leak@db.internal:5432/odal",
            );
            std::env::set_var("KEY_STORE_PATH", "/tmp/ks.json");
            std::env::set_var("KEY_STORE_PASSPHRASE", "passphrase-must-not-leak");
            std::env::set_var("DID_WEB_BASE_URL", "https://node.example.com");
            std::env::set_var("ADMIN_USERNAME", "odal-admin");
            std::env::set_var("ADMIN_PASSWORD", "admin-pass-must-not-leak");
        }
        let cfg = NodeConfig::from_env().expect("config loads");
        let rendered = format!("{cfg:?}");
        clear_env();

        for secret in [
            "passphrase-must-not-leak",
            "admin-pass-must-not-leak",
            "pg-pass-must-not-leak",
            "migrate-pass-must-not-leak",
        ] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked {secret}: {rendered}"
            );
        }

        // Non-secret context must survive, or the redaction has cost the
        // diagnostic value that makes Debug worth having at all.
        assert!(rendered.contains("db.internal:5432"), "{rendered}");
        assert!(rendered.contains("odal-admin"), "{rendered}");
        assert!(rendered.contains("/tmp/ks.json"), "{rendered}");
    }

    /// An unset optional secret must be distinguishable from a set one — the
    /// presence of an admin password is a real diagnostic, its value is not.
    #[test]
    #[serial]
    fn debug_distinguishes_an_absent_optional_secret() {
        set_required_env();
        let cfg = NodeConfig::from_env().expect("config loads");
        let rendered = format!("{cfg:?}");
        clear_env();
        assert!(
            rendered.contains("admin_password: None"),
            "an unset admin password should read as None: {rendered}"
        );
    }
}
