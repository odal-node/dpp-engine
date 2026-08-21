//! The resolved config types: environment kind, on-disk profile shape, and
//! the active `Config` the rest of the CLI consumes.

use std::fmt;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::profiles::{ConfigFile, DEFAULT_PROFILE, normalize, resolve_api_key};

/// Environment kind for a profile. Drives the console banner colour, prod
/// confirmations, and which Docker Compose file infrastructure commands target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnvKind {
    #[default]
    Dev,
    Prod,
}

impl EnvKind {
    /// Infer the kind from a vault URL: localhost → dev, anything else → prod.
    pub fn infer(url: &str) -> Self {
        if url_is_localhost(url) {
            EnvKind::Dev
        } else {
            EnvKind::Prod
        }
    }
}

impl fmt::Display for EnvKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvKind::Dev => f.write_str("dev"),
            EnvKind::Prod => f.write_str("prod"),
        }
    }
}

/// A single named connection profile as stored on disk under `[profiles.<name>]`.
///
/// Holds only what the CLI needs to talk to one node: the environment kind, the
/// service URLs, and (for now) the operator API key. Node runtime config (DB,
/// key store, JWT) lives in the node's own `.env` — the CLI never duplicates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Environment kind (`dev` | `prod`).
    #[serde(default)]
    pub kind: EnvKind,

    /// Base URL of the vault sub-router, e.g. `http://localhost:8001/vault`.
    #[serde(default = "default_vault_url")]
    pub vault_url: String,

    /// Base URL of the identity sub-router, e.g. `http://localhost:8001/identity`.
    #[serde(default = "default_identity_url")]
    pub identity_url: String,

    /// Base URL of the resolver service, e.g. `http://localhost:8003`.
    #[serde(default = "default_resolver_url")]
    pub resolver_url: String,

    /// Operator API key (`Authorization: Bearer odal_sk_…`). Minted during
    /// first-run setup or via `odal key create`. (Phase 2 moves this into a
    /// separate 0600 credentials store.)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_key: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            kind: EnvKind::Dev,
            vault_url: default_vault_url(),
            identity_url: default_identity_url(),
            resolver_url: default_resolver_url(),
            api_key: String::new(),
        }
    }
}

/// True when a profile targets a remote node but kept the localhost resolver
/// default.
///
/// The resolver is a separately deployed process on its own host, so
/// [`normalize`] cannot re-host it the way it re-hosts identity. An unstated
/// resolver stays pointed at the operator's own machine, which `odal status`
/// then reports as a permanently unreachable resolver against a perfectly
/// healthy deployment.
pub fn resolver_is_unstated_default(kind: EnvKind, resolver_url: &str) -> bool {
    kind == EnvKind::Prod && url_is_localhost(resolver_url)
}

/// Derive a vault URL from a node origin.
///
/// The single-binary node mounts the vault and identity sub-routers on one
/// origin, so stating that origin once fixes both — [`normalize`] aligns
/// identity onto the vault's host and scheme. The resolver is deployed
/// separately and is deliberately not derived here.
pub fn vault_url_from_node(node_url: &str) -> String {
    let base = node_url.trim().trim_end_matches('/');
    if base.is_empty() {
        // Let `normalize` supply the default rather than inventing "/vault".
        return String::new();
    }
    match base.strip_suffix("/vault") {
        Some(_) => base.to_owned(),
        None => format!("{base}/vault"),
    }
}

/// The resolved active profile, plus its name — what the rest of the CLI sees.
///
/// Field names match the legacy flat config so existing call sites
/// (`cfg.vault_url`, `cfg.api_key`, …) keep working unchanged.
#[derive(Debug, Clone)]
pub struct Config {
    /// The active profile's name (e.g. `dev`, `prod`).
    pub name: String,
    /// The active profile's environment kind.
    pub kind: EnvKind,
    pub vault_url: String,
    pub identity_url: String,
    pub resolver_url: String,
    pub api_key: String,
}

// The default deployment is the single-binary `dpp-node` on port 8001, with
// the vault and identity sub-routers mounted under `/vault` and `/identity`, and
// the resolver as a separate process on 8003.
pub(super) fn default_vault_url() -> String {
    "http://localhost:8001/vault".into()
}

pub(super) fn default_identity_url() -> String {
    "http://localhost:8001/identity".into()
}

pub(super) fn default_resolver_url() -> String {
    "http://localhost:8003".into()
}

/// True if the URL points at the local machine.
pub(super) fn url_is_localhost(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("localhost") || lower.contains("127.0.0.1") || lower.contains("::1")
}

impl Config {
    /// Load the active profile from `~/.config/odal/config.toml`.
    ///
    /// On a fresh install (no profiles yet) this returns a default profile under
    /// the requested name rather than erroring, so first-run setup works. If
    /// profiles exist but the requested one is missing, it errors.
    pub fn load() -> Result<Self> {
        let file = ConfigFile::load()?;
        let name = file.active_name();

        let mut profile = match file.profiles.get(&name) {
            Some(p) => p.clone(),
            None if file.profiles.is_empty() => Profile::default(),
            None => anyhow::bail!(
                "profile '{name}' not found. Run `odal profile list` to see available \
                 profiles, or `odal profile create {name}` to add it."
            ),
        };

        // 12-factor: an env var overrides the saved target URL (re-infer kind).
        if let Ok(url) = std::env::var("ODAL_VAULT_URL")
            && !url.is_empty()
        {
            profile.vault_url = url;
            profile.kind = EnvKind::infer(&profile.vault_url);
        }

        let profile = normalize(profile);
        let api_key = resolve_api_key(&name, &profile);

        Ok(Config {
            name,
            kind: profile.kind,
            vault_url: profile.vault_url,
            identity_url: profile.identity_url,
            resolver_url: profile.resolver_url,
            api_key,
        })
    }

    /// Persist this profile back to the config file under `self.name`, leaving
    /// every other profile untouched. Sets `current_profile` if unset.
    ///
    /// The API key is **not** written to `config.toml` — it goes to the separate
    /// 0600 credentials store (see [`crate::credentials`]).
    pub fn save(&self) -> Result<()> {
        let mut file = ConfigFile::load().unwrap_or_default();
        file.profiles.insert(self.name.clone(), self.to_profile());
        if file.current_profile.is_none() {
            file.current_profile = Some(self.name.clone());
        }
        file.write()?;

        if !self.api_key.is_empty() {
            crate::credentials::save_key(&self.name, &self.api_key)?;
        }
        Ok(())
    }

    /// True when this profile targets the local machine.
    pub fn is_localhost(&self) -> bool {
        url_is_localhost(&self.vault_url)
    }

    /// Base URL of the integrator sub-router (CSV/XLSX bulk import), derived from
    /// `vault_url`. The single-binary node mounts the vault under `/vault` and the
    /// integrator under `/integrator` on the same host, so we swap the suffix.
    pub fn integrator_url(&self) -> String {
        match self.vault_url.strip_suffix("/vault") {
            Some(base) => format!("{base}/integrator"),
            None => format!("{}/integrator", self.vault_url.trim_end_matches('/')),
        }
    }

    /// The on-disk profile this config writes, normalised.
    ///
    /// Normalising on the way out is what keeps `config.toml` honest. `load`
    /// normalises on the way in, so a profile written raw shows one identity
    /// URL in the file and a different one everywhere the CLI reports it.
    fn to_profile(&self) -> Profile {
        normalize(Profile {
            kind: self.kind,
            vault_url: self.vault_url.clone(),
            identity_url: self.identity_url.clone(),
            resolver_url: self.resolver_url.clone(),
            api_key: String::new(), // secrets live in credentials.toml
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        let p = Profile::default();
        Self {
            name: DEFAULT_PROFILE.to_owned(),
            kind: p.kind,
            vault_url: p.vault_url,
            identity_url: p.identity_url,
            resolver_url: p.resolver_url,
            api_key: p.api_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_default_urls() {
        let cfg = Config::default();
        assert_eq!(cfg.name, "default");
        assert_eq!(cfg.kind, EnvKind::Dev);
        assert_eq!(cfg.vault_url, "http://localhost:8001/vault");
        assert_eq!(cfg.identity_url, "http://localhost:8001/identity");
        assert_eq!(cfg.resolver_url, "http://localhost:8003");
    }

    #[test]
    fn env_kind_infers_from_url() {
        assert_eq!(EnvKind::infer("http://localhost:8001/vault"), EnvKind::Dev);
        assert_eq!(EnvKind::infer("http://127.0.0.1:8001"), EnvKind::Dev);
        assert_eq!(
            EnvKind::infer("https://node.acme.example/vault"),
            EnvKind::Prod
        );
    }

    #[test]
    fn node_origin_derives_the_vault_url() {
        assert_eq!(
            vault_url_from_node("https://node.example.com"),
            "https://node.example.com/vault"
        );
        assert_eq!(
            vault_url_from_node("https://node.example.com/"),
            "https://node.example.com/vault"
        );
        // Idempotent, so an operator who passes the URL they already know does
        // not get `/vault/vault`.
        assert_eq!(
            vault_url_from_node("https://node.example.com/vault"),
            "https://node.example.com/vault"
        );
        // A node mounted under a path keeps the path.
        assert_eq!(
            vault_url_from_node("https://example.com/odal"),
            "https://example.com/odal/vault"
        );
        // A blank value must fall back to the default, not become the bare
        // path "/vault" — which `normalize` cannot repair and `EnvKind::infer`
        // reads as a remote host.
        assert_eq!(vault_url_from_node(""), "");
        assert_eq!(vault_url_from_node("   "), "");
    }

    /// The guarantee `--node-url` makes: one origin settles both sub-routers,
    /// and neither is left on localhost.
    #[test]
    fn node_origin_settles_both_sub_routers() {
        let p = normalize(Profile {
            kind: EnvKind::Prod,
            vault_url: vault_url_from_node("https://node.example.com"),
            ..Profile::default()
        });
        assert_eq!(p.vault_url, "https://node.example.com/vault");
        assert_eq!(p.identity_url, "https://node.example.com/identity");
    }

    /// The write path must normalise. `load` normalises on the way in, so a
    /// profile written raw leaves a localhost identity URL on disk under a
    /// remote vault URL — `config.toml` then disagrees with every command that
    /// reports it, and hand-editing the file is the only apparent remedy.
    #[test]
    fn saved_profile_is_normalised() {
        let written = Config {
            name: "prod".into(),
            kind: EnvKind::Prod,
            vault_url: "https://node.example.com/vault".into(),
            identity_url: default_identity_url(),
            resolver_url: default_resolver_url(),
            api_key: "odal_sk_example".into(),
        }
        .to_profile();

        assert_eq!(written.identity_url, "https://node.example.com/identity");
        // Secrets live in the 0600 credentials store, never in config.toml.
        assert!(written.api_key.is_empty());
        // The resolver is deliberately NOT derived: it is a separate deployment
        // on its own host, and guessing it would only replace one wrong answer
        // with another. `resolver_is_unstated_default` is what surfaces it.
        assert_eq!(written.resolver_url, default_resolver_url());
    }

    /// A prod profile that never stated a resolver keeps pointing at the
    /// operator's own machine. Nothing else in the config path catches this,
    /// which is why `odal status` reported a dead resolver against a healthy
    /// node with no indication of the cause.
    #[test]
    fn unstated_resolver_is_flagged_only_for_remote_profiles() {
        assert!(resolver_is_unstated_default(
            EnvKind::Prod,
            &default_resolver_url()
        ));
        // A dev profile is supposed to resolve locally.
        assert!(!resolver_is_unstated_default(
            EnvKind::Dev,
            &default_resolver_url()
        ));
        // Stated explicitly — nothing to warn about.
        assert!(!resolver_is_unstated_default(
            EnvKind::Prod,
            "https://dpp.example.com"
        ));
    }
}
