//! Configuration for the eID Easy Cloud Direct e-Sealing backend.
//!
//! The HMAC key is an operator-supplied, node-wide credential for one outbound
//! service, needed at boot and never created at runtime — the same category as
//! `EU_REGISTRY_CLIENT_SECRET` and `MTLS_PROXY_SHARED_SECRET`, and delivered the
//! same way (the node's `.env`, mode 600). It is deliberately not
//! in the key store, which holds Ed25519 key pairs for DID publication, and not
//! in Postgres, which would put a live signing credential in every backup.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::SealError;

/// Which eID Easy deployment the configured base URL points at.
///
/// Derived from the host rather than configured separately, so the environment
/// and the URL cannot disagree. This is what the node maps to its trust tier —
/// a sandbox seal is a real seal from a real API, but it carries eID Easy's test
/// certificate and has no legal validity, which is a different claim from Ghost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EideasyEnvironment {
    /// `test.eideasy.com` — developer credentials, eID Easy test certificates.
    Sandbox,
    /// `id.eideasy.com` — production, bound to the qualified certificate.
    Production,
}

pub const SANDBOX_BASE_URL: &str = "https://test.eideasy.com";
pub const PRODUCTION_BASE_URL: &str = "https://id.eideasy.com";

const SANDBOX_HOST: &str = "test.eideasy.com";
const PRODUCTION_HOST: &str = "id.eideasy.com";

/// Resolved eID Easy configuration.
///
/// `Debug` is implemented by hand: the derived one would print `hmac_key` in
/// full through any `{:?}` — a `tracing` field, an `anyhow` context, a panic
/// message.
#[derive(Clone)]
pub struct EideasyConfig {
    /// Origin only, no trailing slash. The path is [`crate::eideasy::client::ESEAL_PATH`].
    pub base_url: String,
    /// Which deployment `base_url` names.
    pub environment: EideasyEnvironment,
    /// From eID Easy "My Webpages". Not a secret — it travels in the request body.
    pub client_id: String,
    /// The e-seal HMAC key, shown once at generation.
    pub hmac_key: Zeroizing<String>,
    /// Must be a profile eID Easy has enabled for `client_id`.
    pub signature_profile: String,
    pub request_timeout: Duration,
}

impl std::fmt::Debug for EideasyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EideasyConfig")
            .field("base_url", &self.base_url)
            .field("environment", &self.environment)
            .field("client_id", &self.client_id)
            .field("hmac_key", &"[redacted]")
            .field("signature_profile", &self.signature_profile)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

/// Selects which QTSP backend the node seals with.
///
/// `eideasy` is the only value today. It exists as a selector anyway because env
/// var names are a published interface: adding a provider later must not force
/// every self-hoster through a config migration. An unrecognised value is a boot
/// error, not a fallback — a node that cannot name its trust provider must not
/// quietly become one that has none.
pub const SEAL_PROVIDER: &str = "SEAL_PROVIDER";

const PROVIDER_EIDEASY: &str = "eideasy";
const PROVIDER_NONE: &str = "none";

impl EideasyConfig {
    /// Read configuration from the environment.
    ///
    /// Returns `Ok(None)` when no provider is selected — the node then wires
    /// `GhostSeal`, which a development profile permits and a production profile
    /// refuses at boot.
    ///
    /// A *partial* configuration is an error, not a `None`. Silently falling back
    /// to a ghost because one of three variables was misspelled would downgrade a
    /// node from qualified sealing to no sealing on a typo, which is precisely the
    /// failure the trust report exists to make impossible. Setting the
    /// `SEAL_EIDEASY_*` variables without selecting the provider is the same class
    /// of mistake and is refused for the same reason.
    ///
    /// When a second backend lands this becomes a dispatch on
    /// [`SEAL_PROVIDER`]; the shape is here so that change is additive.
    pub fn from_env() -> Result<Option<Self>, SealError> {
        Self::resolve(|name| std::env::var(name).ok())
    }

    /// The whole of [`Self::from_env`]'s logic, over an arbitrary lookup.
    ///
    /// Split out so the rules above — provider selection, all-or-nothing
    /// credentials, host allowlisting — are testable as a pure function.
    /// Exercising them through the real environment would mean mutating
    /// process-global state from tests, which is `unsafe` under Rust 2024, forces
    /// them to serialise against one another, and lets a stray variable in the
    /// developer's shell change the result.
    pub fn resolve(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, SealError> {
        let read = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let base_url = read("SEAL_EIDEASY_BASE_URL");
        let client_id = read("SEAL_EIDEASY_CLIENT_ID");
        let hmac_key = read("SEAL_EIDEASY_HMAC_KEY");
        let any_eideasy_var = base_url.is_some() || client_id.is_some() || hmac_key.is_some();

        match read(SEAL_PROVIDER).as_deref() {
            None | Some(PROVIDER_NONE) => {
                if any_eideasy_var {
                    return Err(SealError::Config(format!(
                        "SEAL_EIDEASY_* is set but {SEAL_PROVIDER} is not `{PROVIDER_EIDEASY}` — \
                         set it, or unset the SEAL_EIDEASY_* variables to run with GhostSeal"
                    )));
                }
                return Ok(None);
            }
            Some(PROVIDER_EIDEASY) => {}
            Some(other) => {
                return Err(SealError::Config(format!(
                    "unknown {SEAL_PROVIDER} `{other}` — supported: `{PROVIDER_EIDEASY}`, \
                     `{PROVIDER_NONE}`"
                )));
            }
        }

        let missing: Vec<&str> = [
            ("SEAL_EIDEASY_BASE_URL", &base_url),
            ("SEAL_EIDEASY_CLIENT_ID", &client_id),
            ("SEAL_EIDEASY_HMAC_KEY", &hmac_key),
        ]
        .iter()
        .filter(|(_, v)| v.is_none())
        .map(|(n, _)| *n)
        .collect();
        if !missing.is_empty() {
            return Err(SealError::Config(format!(
                "{SEAL_PROVIDER}=`{PROVIDER_EIDEASY}` but {} not set",
                missing.join(", ")
            )));
        }

        let base_url = base_url.expect("checked non-empty above");
        let environment = environment_for(&base_url)?;

        Ok(Some(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            environment,
            client_id: client_id.expect("checked non-empty above"),
            hmac_key: Zeroizing::new(hmac_key.expect("checked non-empty above")),
            signature_profile: read("SEAL_EIDEASY_SIGNATURE_PROFILE").unwrap_or_else(|| {
                crate::eideasy::EsealRequest::PROFILE_CADES_BASELINE_T.to_owned()
            }),
            request_timeout: Duration::from_secs(30),
        }))
    }
}

/// Map a base URL to its eID Easy deployment, refusing anything else.
///
/// The allowlist is the point: an unrecognised host cannot be classified, and a
/// seal whose trust tier we cannot state is worse than no seal. A typo in
/// `SEAL_EIDEASY_BASE_URL` fails the node at boot rather than shipping passport
/// digests to whatever host was actually spelled.
fn environment_for(base_url: &str) -> Result<EideasyEnvironment, SealError> {
    let parsed = url::Url::parse(base_url)
        .map_err(|e| SealError::Config(format!("SEAL_EIDEASY_BASE_URL is not a URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(SealError::Config(format!(
            "SEAL_EIDEASY_BASE_URL must be https, got {}",
            parsed.scheme()
        )));
    }
    match parsed.host_str() {
        Some(SANDBOX_HOST) => Ok(EideasyEnvironment::Sandbox),
        Some(PRODUCTION_HOST) => Ok(EideasyEnvironment::Production),
        other => Err(SealError::Config(format!(
            "SEAL_EIDEASY_BASE_URL host {} is not eID Easy — expected {SANDBOX_HOST} or {PRODUCTION_HOST}",
            other.unwrap_or("<none>")
        ))),
    }
}

/// Config pointed at an arbitrary base URL, for tests that stand up a local mock.
///
/// Deliberately bypasses [`environment_for`]: the host allowlist guards the
/// operator-facing `from_env` path, and applying it here would make the endpoint
/// untestable without reaching eID Easy.
#[cfg(test)]
pub(crate) fn test_config(base_url: &str) -> EideasyConfig {
    EideasyConfig {
        base_url: base_url.to_owned(),
        environment: EideasyEnvironment::Sandbox,
        client_id: "test-client".into(),
        hmac_key: Zeroizing::new("test-key".into()),
        signature_profile: "CAdES_BASELINE_T".into(),
        request_timeout: Duration::from_secs(5),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve against a fixed set of variables — no process environment, so
    /// these are pure, parallel-safe, and cannot be perturbed by the developer's
    /// shell.
    fn resolve(vars: &[(&str, &str)]) -> Result<Option<EideasyConfig>, SealError> {
        let owned: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        EideasyConfig::resolve(|name| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }

    const FULL: [(&str, &str); 4] = [
        (SEAL_PROVIDER, PROVIDER_EIDEASY),
        ("SEAL_EIDEASY_BASE_URL", SANDBOX_BASE_URL),
        ("SEAL_EIDEASY_CLIENT_ID", "client-id"),
        ("SEAL_EIDEASY_HMAC_KEY", "hmac-key"),
    ];

    #[test]
    fn no_provider_selected_is_a_ghost_not_an_error() {
        assert!(resolve(&[]).unwrap().is_none());
        assert!(
            resolve(&[(SEAL_PROVIDER, PROVIDER_NONE)])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_full_configuration_resolves() {
        let cfg = resolve(&FULL).unwrap().expect("configured");
        assert_eq!(cfg.environment, EideasyEnvironment::Sandbox);
        assert_eq!(cfg.client_id, "client-id");
        // Defaulted, not required.
        assert_eq!(cfg.signature_profile, "CAdES_BASELINE_T");
    }

    /// The failure this selector exists to prevent: credentials present, provider
    /// not selected. Silently ghosting here would downgrade a node that was
    /// configured for qualified sealing into one with none.
    #[test]
    fn credentials_without_a_selected_provider_are_refused() {
        let err = resolve(&FULL[1..]).expect_err("must not ghost silently");
        assert!(err.to_string().contains(SEAL_PROVIDER));
    }

    #[test]
    fn a_partial_configuration_names_what_is_missing() {
        let err = resolve(&FULL[..2]).expect_err("partial must fail");
        let msg = err.to_string();
        assert!(msg.contains("SEAL_EIDEASY_CLIENT_ID"), "{msg}");
        assert!(msg.contains("SEAL_EIDEASY_HMAC_KEY"), "{msg}");
    }

    #[test]
    fn an_unknown_provider_fails_the_boot() {
        let err =
            resolve(&[(SEAL_PROVIDER, "some-other-qtsp")]).expect_err("unknown provider must fail");
        assert!(err.to_string().contains("some-other-qtsp"));
    }

    /// Blank is not "set" — an operator commenting a value out leaves an empty
    /// string behind, and that must read as absent rather than as a credential.
    #[test]
    fn blank_values_count_as_unset() {
        assert!(
            resolve(&[(SEAL_PROVIDER, "  ")]).unwrap().is_none(),
            "a whitespace-only provider should ghost, not fail as unknown"
        );
    }

    #[test]
    fn known_hosts_map_to_their_environments() {
        assert_eq!(
            environment_for(SANDBOX_BASE_URL).unwrap(),
            EideasyEnvironment::Sandbox
        );
        assert_eq!(
            environment_for(PRODUCTION_BASE_URL).unwrap(),
            EideasyEnvironment::Production
        );
    }

    #[test]
    fn an_unknown_host_is_refused() {
        // A typo must not become "some seal from somewhere" — it must not boot.
        for url in [
            "https://id.eideasy.com.evil.test",
            "https://eideasy.com",
            "https://localhost:8080",
        ] {
            assert!(
                environment_for(url).is_err(),
                "{url} was accepted as an eID Easy host"
            );
        }
    }

    #[test]
    fn plaintext_http_is_refused() {
        assert!(environment_for("http://test.eideasy.com").is_err());
    }

    #[test]
    fn debug_does_not_print_the_hmac_key() {
        let mut cfg = test_config(SANDBOX_BASE_URL);
        cfg.hmac_key = Zeroizing::new("super-secret-key-material".into());
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("super-secret-key-material"),
            "Debug leaked the HMAC key: {rendered}"
        );
        assert!(rendered.contains("[redacted]"));
    }
}
