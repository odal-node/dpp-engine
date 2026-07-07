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
        file.profiles.insert(
            self.name.clone(),
            Profile {
                kind: self.kind,
                vault_url: self.vault_url.clone(),
                identity_url: self.identity_url.clone(),
                resolver_url: self.resolver_url.clone(),
                api_key: String::new(), // secrets live in credentials.toml
            },
        );
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
}
