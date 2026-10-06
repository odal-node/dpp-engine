//! Unified runtime configuration for the `dpp-node` single binary.

use anyhow::{Context, Result};
use dpp_domain::ports::registry_sync::ServiceProviderRef;

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

    /// Path to the directory containing `*.wasm` product group plugin files.
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
    /// carrier (QR) URL at publish. Required, with no default — read through
    /// [`dpp_common::config::resolver_base_url`], which the resolver reads its
    /// own copy through too, so the two cannot disagree about the rule.
    pub resolver_base_url: String,
    /// Public base URL under which this deployment serves its continuity
    /// snapshots, declared to the EU registry as each passport's back-up link.
    ///
    /// `None` unless `SNAPSHOT_PUBLIC_BASE_URL` is set. Writing snapshots to
    /// object storage does not make them reachable, so this is deliberately a
    /// separate, explicit statement that they *are* served — and no back-up is
    /// declared until an operator makes it.
    pub snapshot_public_base_url: Option<String>,
    /// Who hosts that back-up — ESPR Annex III point (l), declared to the EU
    /// registry beside the link.
    ///
    /// Always `Some` when `snapshot_public_base_url` is: the registry refuses a
    /// link that names no provider, so [`snapshot_provider`] refuses to boot
    /// without one rather than letting every registration fail later.
    pub snapshot_provider: Option<ServiceProviderRef>,
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
    /// `DID_WEB_BASE_URL`, `RESOLVER_BASE_URL`.
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
        // Read the required vars in declaration order so an empty environment
        // still reports `DATABASE_URL` first — `missing_required_var_errors`
        // pins that, and "which variable is missing" is the whole value of the
        // message. The credential guard runs after, on values already read.
        let database_url = var("DATABASE_URL")?;
        let key_store_path = var("KEY_STORE_PATH")?;
        let key_store_passphrase = var("KEY_STORE_PASSPHRASE")?;
        let did_web_base_url = var("DID_WEB_BASE_URL")?;
        let resolver_base_url = dpp_common::config::resolver_base_url()?;
        let admin_username = std::env::var("ADMIN_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let admin_password = std::env::var("ADMIN_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());
        // Read here, beside the other two credentials, rather than inside the
        // check — see `ensure_bootstrap_credentials` for what reading it in
        // there cost.
        let allow_dev_credentials = std::env::var(ALLOW_DEV_CREDENTIALS)
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        ensure_key_store_path(&key_store_path)?;
        ensure_bootstrap_credentials(
            admin_username.as_deref(),
            admin_password.as_deref(),
            &key_store_passphrase,
            allow_dev_credentials,
        )?;
        let snapshot_public_base_url = optional_var("SNAPSHOT_PUBLIC_BASE_URL");
        let snapshot_provider = snapshot_provider(
            snapshot_public_base_url.as_deref(),
            optional_var("SNAPSHOT_PROVIDER_NAME"),
            optional_var("SNAPSHOT_PROVIDER_SCHEME"),
            optional_var("SNAPSHOT_PROVIDER_VALUE"),
            optional_var("SNAPSHOT_PROVIDER_COUNTRY"),
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
            resolver_base_url,
            snapshot_public_base_url,
            snapshot_provider,
        })
    }
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

/// An optional variable, trimmed — a blank one reads as unset, which is what
/// `FOO=` in a copied `.env.example` means.
fn optional_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The party hosting the back-up behind `SNAPSHOT_PUBLIC_BASE_URL`.
///
/// A pure function of what was read, so it needs no environment in a test.
///
/// The registry refuses a back-up link that names no digital product passport
/// service provider — ESPR Art. 10(4) makes the copy available *through* one —
/// and the refusal is not at boot but at registration: every registration of a
/// node that set the link and not the provider is refused and retried for as
/// long as the node runs, which reads as a registry outage. So the pair is
/// settled here, once, where the operator is looking.
///
/// A provider with no link is accepted: naming one is never wrong.
///
/// Only the name is required — Annex III(l) mandates no identifier scheme, and
/// inventing a default would be a claim about who the provider is. The
/// optional scheme, value and country are checked with the registry's own rules
/// so a pair missing half, or a country that is not ISO 3166-1 alpha-2, fails
/// here too.
///
/// # Errors
/// A message naming the variables involved and how to fix them.
fn snapshot_provider(
    public_base_url: Option<&str>,
    name: Option<String>,
    scheme: Option<String>,
    value: Option<String>,
    country: Option<String>,
) -> Result<Option<ServiceProviderRef>> {
    let Some(name) = name else {
        if public_base_url.is_some() {
            anyhow::bail!(
                "SNAPSHOT_PUBLIC_BASE_URL is set but SNAPSHOT_PROVIDER_NAME is not — refusing \
                 to boot. The EU registry refuses a back-up link that names no digital product \
                 passport service provider (ESPR Art. 10(4)), so every registration would be \
                 refused. Set SNAPSHOT_PROVIDER_NAME to the legal name of whoever hosts the \
                 back-up, or unset SNAPSHOT_PUBLIC_BASE_URL to declare no back-up link."
            );
        }
        if scheme.is_some() || value.is_some() || country.is_some() {
            anyhow::bail!(
                "SNAPSHOT_PROVIDER_SCHEME, SNAPSHOT_PROVIDER_VALUE or SNAPSHOT_PROVIDER_COUNTRY \
                 is set without SNAPSHOT_PROVIDER_NAME — refusing to boot. They describe the \
                 provider the name identifies; alone they identify nobody."
            );
        }
        return Ok(None);
    };
    let provider = ServiceProviderRef {
        name,
        scheme,
        value,
        country,
    };
    crate::infra::registry::service_provider_reference(&provider)
        .validate()
        .map_err(|e| {
            anyhow::anyhow!(
                "SNAPSHOT_PROVIDER_NAME / _SCHEME / _VALUE / _COUNTRY do not describe a service \
                 provider the registry would accept: {e}"
            )
        })?;
    Ok(Some(provider))
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

/// Refuse to boot when `KEY_STORE_PATH` holds a key rather than a path.
///
/// This is not hypothetical. `.env.example` documented the passphrase directly
/// above `KEY_STORE_PATH` and ended with `openssl rand -base64 32`, so the
/// instruction to generate a secret sat on the line *before* the path variable
/// and two before the passphrase it referred to. Filling the template top-down
/// puts the generated key in `KEY_STORE_PATH`, and the node then does exactly
/// what it was told: it writes the encrypted signing key to a file of that
/// name, in whatever directory it was started from.
///
/// That produced an unignored file of Ed25519 key material in the repository
/// root of a public repo — the `.gitignore` rules are extension-based
/// (`*.enc`, `*-keystore.enc`), so they match the configured path and miss the
/// misconfigured one precisely because it does not look like a key store.
///
/// # Why this shape of check
///
/// Decoding is the test, not a guess at what a path looks like. A value that
/// base64-decodes to exactly 32 bytes is an `openssl rand -base64 32` output;
/// a filesystem path is not one, because standard base64 needs a length that is
/// a multiple of four and paths do not carry `=` padding. Refusing on
/// "no directory separator" or "no file extension" would have argued with
/// legitimate configurations instead.
fn ensure_key_store_path(key_store_path: &str) -> Result<()> {
    use base64::Engine as _;

    let looks_like_a_generated_key = base64::engine::general_purpose::STANDARD
        .decode(key_store_path.trim())
        .is_ok_and(|bytes| bytes.len() == 32);

    if looks_like_a_generated_key {
        anyhow::bail!(
            "KEY_STORE_PATH is a 32-byte base64 value, which is a key and not a path — \
             refusing to boot. It is where the encrypted key store file is written, so \
             the node would create a file of that name in its working directory. You \
             probably meant KEY_STORE_PASSPHRASE; set KEY_STORE_PATH to a location such \
             as ./dev-keystore.enc."
        );
    }
    Ok(())
}

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
/// environment state, matching `ensure_signing_policy` in `plugins.rs` — which
/// is why `allow_dev` is a parameter rather than a `std::env::var` call in the
/// body. It used to be the latter, and the difference was not academic: the
/// `justfile` loads `.env`, a developer `.env` sets `ALLOW_DEV_CREDENTIALS=true`
/// because that is what it is for, and so `just check` handed the escape hatch
/// to the three tests whose whole purpose is to prove the placeholders are
/// refused. They failed on every machine set up for development and passed in
/// CI, where no `.env` exists — the gate was green exactly where nobody was
/// running it.
///
/// It deliberately checks only for the *shipped literals*: a boot-time password
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
    allow_dev: bool,
) -> Result<()> {
    if key_store_passphrase.trim().is_empty() {
        anyhow::bail!(
            "KEY_STORE_PASSPHRASE is empty — refusing to boot. It protects the signing key \
             every passport is verified against. Generate one with `openssl rand -base64 32`."
        );
    }

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
    //! no `#[serial]` — the escape hatch included, now that it is a parameter
    //! rather than a `std::env::var` read inside the guard.
    //!
    //! That exception was not free. `just check` loads `.env`, a developer
    //! `.env` sets `ALLOW_DEV_CREDENTIALS=true` because that is what it is for,
    //! and the three "the placeholders are refused" tests inherited it — so
    //! they failed on every machine set up for development and passed in CI,
    //! where there is no `.env`. A test whose subject is a process-global reads
    //! that global from whoever ran it.
    use super::ensure_bootstrap_credentials;

    const GOOD_PASS: &str = "PmDq0aUu0kXwQ0nS+9kQ0Q==";

    mod key_store_path {
        use super::super::ensure_key_store_path;

        /// A stand-in for the value found in a working `.env` on a developer
        /// machine, which had written an Ed25519 key store to the repository
        /// root.
        ///
        /// Deliberately all-zero rather than that value. What the guard reads is
        /// the *shape* — 44 base64 characters decoding to 32 bytes — so a
        /// synthetic value exercises it identically, and this repository is
        /// public. The real one protected nothing (it sat in `KEY_STORE_PATH`
        /// and so was never used to encrypt anything), but it is character for
        /// character an `openssl rand -base64 32` output, which is
        /// indistinguishable from a live key to every secret scanner that will
        /// ever read this file.
        const GENERATED_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        #[test]
        fn a_generated_key_in_the_path_variable_is_refused() {
            let err = ensure_key_store_path(GENERATED_KEY)
                .expect_err("a key in the path variable must not boot");
            let msg = err.to_string();
            assert!(msg.contains("KEY_STORE_PATH"), "{msg}");
            assert!(
                msg.contains("KEY_STORE_PASSPHRASE"),
                "the message must name the variable it was meant for: {msg}"
            );
        }

        /// Surrounding whitespace is the same mistake — `.env` parsers differ
        /// on trimming and the value is no more a path for having a space.
        #[test]
        fn a_generated_key_is_refused_despite_whitespace() {
            assert!(ensure_key_store_path(&format!("  {GENERATED_KEY}  ")).is_err());
        }

        /// The check has to be quiet about real paths, or it becomes the thing
        /// people work around. These are all legitimate.
        #[test]
        fn real_paths_are_left_alone() {
            for path in [
                "./dev-keystore.enc",
                "/var/lib/odal/keystore.enc",
                "keystore.enc",
                "C:\\ProgramData\\odal\\keystore.enc",
                "../shared/dev-keystore.enc",
                // No separator and no extension, but decodes to nothing like
                // 32 bytes — a bare word is a poor location, not a key.
                "keystore",
            ] {
                assert!(
                    ensure_key_store_path(path).is_ok(),
                    "{path} is a path and must be accepted"
                );
            }
        }

        /// A base64 value of some *other* length is not what `openssl rand
        /// -base64 32` emits, so it is not the mistake being caught here.
        #[test]
        fn only_a_thirty_two_byte_value_is_treated_as_a_key() {
            // 16 bytes.
            assert!(ensure_key_store_path("YWJjZGVmZ2hpamtsbW5vcA==").is_ok());
        }
    }

    #[test]
    fn the_shipped_admin_pair_is_refused() {
        let err = ensure_bootstrap_credentials(Some("admin"), Some("admin"), GOOD_PASS, false)
            .expect_err("`admin`/`admin` must not boot");
        assert!(err.to_string().contains("ADMIN_USERNAME/ADMIN_PASSWORD"));
    }

    /// Trimming and case-folding, because the failure being prevented is "never
    /// changed it", and `ADMIN_PASSWORD=Admin ` is the same non-change.
    #[test]
    fn the_shipped_pair_is_matched_loosely() {
        assert!(
            ensure_bootstrap_credentials(Some(" Admin"), Some("ADMIN "), GOOD_PASS, false).is_err()
        );
    }

    #[test]
    fn the_shipped_key_store_passphrase_is_refused() {
        let err = ensure_bootstrap_credentials(None, None, "dev-passphrase-change-in-prod", false)
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
                ensure_bootstrap_credentials(None, None, blank, false).is_err(),
                "{blank:?} must be refused"
            );
        }
    }

    /// Only a *pair* constructs the local-admin provider, so a lone
    /// `ADMIN_USERNAME=admin` authenticates nothing and must not block a boot.
    #[test]
    fn a_lone_shipped_username_is_not_a_credential() {
        assert!(ensure_bootstrap_credentials(Some("admin"), None, GOOD_PASS, false).is_ok());
        assert!(ensure_bootstrap_credentials(None, Some("admin"), GOOD_PASS, false).is_ok());
    }

    /// The guard checks for the shipped literals, not for password strength.
    /// A weak-but-deliberate choice is the operator's to make; conflating the
    /// two would make this guard arguable and therefore disabled.
    #[test]
    fn a_deliberate_choice_is_not_second_guessed() {
        assert!(
            ensure_bootstrap_credentials(Some("root"), Some("hunter2"), "hunter2", false).is_ok()
        );
    }

    #[test]
    fn no_admin_credentials_at_all_is_the_recommended_state() {
        assert!(ensure_bootstrap_credentials(None, None, GOOD_PASS, false).is_ok());
    }

    #[test]
    fn the_escape_hatch_allows_the_placeholders() {
        let allowed = ensure_bootstrap_credentials(
            Some("admin"),
            Some("admin"),
            "dev-passphrase-change-in-prod",
            true,
        );
        assert!(allowed.is_ok(), "the dev escape hatch must permit them");
    }

    /// The escape hatch is for placeholders, not for an absent passphrase —
    /// there is no key to derive from an empty string in any environment.
    #[test]
    fn the_escape_hatch_does_not_permit_an_empty_passphrase() {
        assert!(ensure_bootstrap_credentials(None, None, "", true).is_err());
    }
}

#[cfg(test)]
mod snapshot_provider_rules {
    //! Pure, like the guard above, so none of these touches the environment.
    use super::{ServiceProviderRef, snapshot_provider};

    const URL: Option<&str> = Some("https://backup.example.com/dpp");

    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    /// The failure this exists to move: a link with nobody named beside it is
    /// refused by the registry on every registration, which reads as an outage.
    #[test]
    fn a_link_with_no_provider_is_refused_naming_both_variables() {
        let err = snapshot_provider(URL, None, None, None, None)
            .expect_err("a link with no provider must not boot")
            .to_string();
        assert!(err.contains("SNAPSHOT_PUBLIC_BASE_URL"), "{err}");
        assert!(err.contains("SNAPSHOT_PROVIDER_NAME"), "{err}");
    }

    #[test]
    fn nothing_configured_is_nothing_declared() {
        assert_eq!(
            snapshot_provider(None, None, None, None, None).unwrap(),
            None
        );
    }

    /// Naming a provider is never wrong, so a provider needs no link.
    #[test]
    fn a_provider_without_a_link_is_accepted() {
        assert_eq!(
            snapshot_provider(None, s("Backup Host B.V."), None, None, None).unwrap(),
            Some(ServiceProviderRef::named("Backup Host B.V."))
        );
    }

    /// Only the name is required. No scheme is invented for the provider.
    #[test]
    fn a_name_alone_is_enough() {
        let provider = snapshot_provider(URL, s("Backup Host B.V."), None, None, None)
            .unwrap()
            .expect("a provider");
        assert_eq!(provider, ServiceProviderRef::named("Backup Host B.V."));
        assert_eq!((provider.scheme, provider.value), (None, None));
    }

    #[test]
    fn every_stated_field_is_carried() {
        let provider = snapshot_provider(
            URL,
            s("Backup Host B.V."),
            s("vat"),
            s("NL853371178B01"),
            s("NL"),
        )
        .unwrap()
        .expect("a provider");
        assert_eq!(provider.scheme.as_deref(), Some("vat"));
        assert_eq!(provider.value.as_deref(), Some("NL853371178B01"));
        assert_eq!(provider.country.as_deref(), Some("NL"));
    }

    /// Settled with the registry's own rules, so a half pair or a malformed
    /// country fails here and not on the first registration.
    #[test]
    fn a_scheme_without_its_value_is_refused() {
        assert!(snapshot_provider(URL, s("Backup Host B.V."), s("vat"), None, None).is_err());
    }

    #[test]
    fn a_country_that_is_not_alpha_2_is_refused() {
        assert!(
            snapshot_provider(URL, s("Backup Host B.V."), None, None, s("Netherlands")).is_err()
        );
    }

    /// Fields that describe a provider nobody named identify nobody, and
    /// silently ignoring them would hide a mistyped `SNAPSHOT_PROVIDER_NAME`.
    #[test]
    fn details_without_a_name_are_refused() {
        let err = snapshot_provider(None, None, s("vat"), s("NL853371178B01"), None)
            .expect_err("details with no name must not boot")
            .to_string();
        assert!(err.contains("SNAPSHOT_PROVIDER_NAME"), "{err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // SAFETY, for every `set_var`/`remove_var` in this module: mutating the
    // environment is unsound only while another thread reads or writes it.
    // Every test here that touches it is `#[serial]`, so under `cargo test`'s
    // shared process no two run at once, and nextest runs each test in a
    // process of its own. Nothing in `NodeConfig::from_env` spawns a thread.
    /// Reset to a clean baseline, then set only the five required vars. Clearing
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
        unsafe { std::env::set_var("RESOLVER_BASE_URL", "http://localhost:8003") };
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
            "RESOLVER_BASE_URL",
            "SNAPSHOT_PUBLIC_BASE_URL",
            "SNAPSHOT_PROVIDER_NAME",
            "SNAPSHOT_PROVIDER_SCHEME",
            "SNAPSHOT_PROVIDER_VALUE",
            "SNAPSHOT_PROVIDER_COUNTRY",
        ] {
            unsafe { std::env::remove_var(key) };
        }
    }

    /// The boot refusal, through the real loader: a node that serves its
    /// snapshots and names nobody hosting them must not start.
    #[test]
    #[serial]
    fn a_snapshot_url_without_a_provider_does_not_boot() {
        set_required_env();
        unsafe { std::env::set_var("SNAPSHOT_PUBLIC_BASE_URL", "https://backup.example.com/dpp") };
        let err = NodeConfig::from_env().expect_err("must refuse");
        clear_env();
        assert!(err.to_string().contains("SNAPSHOT_PROVIDER_NAME"), "{err}");
    }

    #[test]
    #[serial]
    fn a_snapshot_url_with_its_provider_boots_carrying_both() {
        set_required_env();
        unsafe { std::env::set_var("SNAPSHOT_PUBLIC_BASE_URL", "https://backup.example.com/dpp") };
        unsafe { std::env::set_var("SNAPSHOT_PROVIDER_NAME", "Backup Host B.V.") };
        let cfg = NodeConfig::from_env().expect("loads");
        clear_env();
        assert_eq!(
            cfg.snapshot_public_base_url.as_deref(),
            Some("https://backup.example.com/dpp")
        );
        assert_eq!(
            cfg.snapshot_provider,
            Some(ServiceProviderRef::named("Backup Host B.V."))
        );
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

    /// The value lands inside every signed carrier, so a node that would have
    /// to guess it does not boot. Everything else required is present here —
    /// this is the only reason the load can fail.
    #[test]
    #[serial]
    fn a_node_without_a_resolver_base_url_does_not_boot() {
        set_required_env();
        unsafe { std::env::remove_var("RESOLVER_BASE_URL") };
        let msg = NodeConfig::from_env().unwrap_err().to_string();
        clear_env();
        assert!(msg.contains("RESOLVER_BASE_URL"), "{msg}");
    }

    #[test]
    #[serial]
    fn the_resolver_base_url_is_carried_without_a_trailing_slash() {
        set_required_env();
        unsafe { std::env::set_var("RESOLVER_BASE_URL", "https://dpp.example.com/") };
        let cfg = NodeConfig::from_env().unwrap();
        clear_env();
        assert_eq!(cfg.resolver_base_url, "https://dpp.example.com");
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
            std::env::set_var("RESOLVER_BASE_URL", "https://dpp.example.com");
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
