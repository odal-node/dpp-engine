//! On-disk profile file (`config.toml`): load/save, legacy migration, the
//! active-profile override, and the `odal profile …` CRUD surface.

use std::{collections::BTreeMap, fs, path::Path, sync::OnceLock};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::model::{
    EnvKind, Profile, default_identity_url, default_resolver_url, default_vault_url,
};
use super::paths::config_path;

/// On-disk config file format: a set of named profiles plus the active one.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct ConfigFile {
    /// The active profile name. `--profile` / `ODAL_PROFILE` override this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) current_profile: Option<String>,
    /// All known profiles, keyed by name.
    #[serde(default)]
    pub(super) profiles: BTreeMap<String, Profile>,
}

/// Legacy flat config (pre-profiles) — used only to migrate old files.
#[derive(Debug, Default, Deserialize)]
struct LegacyConfig {
    vault_url: Option<String>,
    identity_url: Option<String>,
    resolver_url: Option<String>,
    api_key: Option<String>,
}

impl LegacyConfig {
    fn has_content(&self) -> bool {
        self.vault_url.is_some()
            || self.identity_url.is_some()
            || self.resolver_url.is_some()
            || self.api_key.is_some()
    }

    fn into_profile(self) -> Profile {
        let vault_url = self.vault_url.unwrap_or_else(default_vault_url);
        Profile {
            kind: EnvKind::infer(&vault_url),
            identity_url: self.identity_url.unwrap_or_else(default_identity_url),
            resolver_url: self.resolver_url.unwrap_or_else(default_resolver_url),
            api_key: self.api_key.unwrap_or_default(),
            vault_url,
        }
    }
}

pub(super) const DEFAULT_PROFILE: &str = "default";

/// Process-wide override for the active profile, set once from the `--profile`
/// flag in `main()`. Takes precedence over `ODAL_PROFILE` and the file's
/// `current_profile`.
static PROFILE_OVERRIDE: OnceLock<Option<String>> = OnceLock::new();

/// Record the `--profile` flag value (if any). Call once, early in `main()`.
pub fn set_active_profile_override(name: Option<String>) {
    let _ = PROFILE_OVERRIDE.set(name.filter(|s| !s.is_empty()));
}

/// Extract the `host:port` portion of an HTTP URL (no scheme, no path).
fn host_and_port(url: &str) -> Option<String> {
    let no_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    Some(no_scheme.split('/').next()?.to_owned())
}

/// If the user pointed at the node's root URL but forgot the sub-router path
/// (e.g. `http://localhost:8001` instead of `http://localhost:8001/vault`),
/// append `suffix` for them.
fn ensure_path_suffix(url: &str, suffix: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    if trimmed.is_empty() || trimmed.ends_with(suffix) {
        trimmed.to_owned()
    } else if trimmed.split('/').count() == 3 {
        // `http://host:port` — three slash-separated parts, no path component.
        format!("{trimmed}{suffix}")
    } else {
        trimmed.to_owned()
    }
}

/// Normalise a profile's URLs (fill blanks, append `/vault` + `/identity`,
/// keep identity on the same host:port as vault for the single-binary node).
pub(super) fn normalize(mut p: Profile) -> Profile {
    if p.vault_url.is_empty() {
        p.vault_url = default_vault_url();
    }
    if p.identity_url.is_empty() {
        p.identity_url = default_identity_url();
    }
    if p.resolver_url.is_empty() {
        p.resolver_url = default_resolver_url();
    }
    p.vault_url = ensure_path_suffix(&p.vault_url, "/vault");
    p.identity_url = ensure_path_suffix(&p.identity_url, "/identity");
    if p.vault_url.ends_with("/vault") {
        let vault_host = host_and_port(&p.vault_url);
        let id_host = host_and_port(&p.identity_url);
        if vault_host != id_host
            && let Some(vh) = vault_host
        {
            // Preserve the vault's scheme so an https prod node keeps https.
            let scheme = if p.vault_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            p.identity_url = format!("{scheme}://{vh}/identity");
        }
    }
    p
}

/// Resolve a profile's API key: `ODAL_API_KEY` env → credentials store →
/// (back-compat) any `api_key` still inline in `config.toml`.
/// The env var wins before the store is even opened, so a corrupt credentials
/// file cannot block the 12-factor path that does not need it.
pub(super) fn resolve_api_key(name: &str, profile: &Profile) -> Result<String> {
    if let Ok(key) = std::env::var("ODAL_API_KEY")
        && !key.is_empty()
    {
        return Ok(key);
    }
    if let Some(key) = crate::credentials::load_key(name)? {
        return Ok(key);
    }
    Ok(profile.api_key.clone())
}

impl ConfigFile {
    /// Load the on-disk config, migrating a legacy flat file into a `default`
    /// profile if necessary. Returns an empty file if none exists.
    pub(super) fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        Self::parse(&content, &path)
    }

    /// Parse the config file's contents, naming the file in any failure.
    ///
    /// A parse failure must **never** degrade to `Self::default()`. An empty
    /// `ConfigFile` is indistinguishable from a fresh install, and
    /// [`Self::write`] replaces the whole file, so a swallowed error made the
    /// next command that persists anything — `profile create`, `profile use`,
    /// `Config::save` — rewrite `config.toml` with that one profile and drop
    /// every other, silently.
    ///
    /// The legacy migration below is a different thing and is preserved: a
    /// pre-profiles flat file is *valid* TOML whose keys this struct does not
    /// name, so it parses here as an empty `ConfigFile` (serde ignores unknown
    /// fields) and reaches the migration on the empty-profiles branch — not via
    /// a parse error. What is gone is the swallow: **both** reads propagate now,
    /// because that same unknown-field tolerance means a flat file with a
    /// wrong-typed value reaches the second read, where dropping its error
    /// produced the identical erase (see the comment on that read).
    fn parse(content: &str, path: &Path) -> Result<Self> {
        // Try the new profile-based format first.
        let file: ConfigFile = toml::from_str(content).with_context(|| {
            format!(
                "Failed to parse config: {}. Fix or move that file — refusing to \
                 continue as though nothing were configured, because saving a profile \
                 would then overwrite every profile it still holds.",
                path.display()
            )
        })?;
        if !file.profiles.is_empty() {
            return Ok(file);
        }

        // Fall back to migrating a legacy flat config.
        //
        // This read must propagate for the same reason the one above does, and the
        // reachable case is narrow enough to be worth naming: `ConfigFile` ignores
        // unknown top-level keys, so a flat file whose `vault_url` or `api_key`
        // carries the wrong type parses *there* as an empty file and arrives here,
        // where reading it as `LegacyConfig` is what fails. Dropping that failure
        // returned the empty `file` and the next save overwrote the operator's
        // values — the same erase, one branch further down.
        //
        // It cannot fire for a new-format file: the four legacy keys only ever
        // appear under `[profiles.*]` there, so at the top level `LegacyConfig`
        // finds none of them and parses as all-`None`.
        let legacy: LegacyConfig = toml::from_str(content).with_context(|| {
            format!(
                "Failed to parse config: {}. It holds no [profiles.*] table, and \
                 reading it as a pre-profiles flat config failed too — refusing to \
                 continue as though nothing were configured, because saving a profile \
                 would then overwrite what it still holds.",
                path.display()
            )
        })?;
        if legacy.has_content() {
            let mut profiles = BTreeMap::new();
            profiles.insert(DEFAULT_PROFILE.to_owned(), legacy.into_profile());
            return Ok(ConfigFile {
                current_profile: Some(DEFAULT_PROFILE.to_owned()),
                profiles,
            });
        }
        Ok(file)
    }

    /// Persist the config file.
    pub(super) fn write(&self) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config dir: {}", parent.display()))?;
        }
        let content = toml::to_string_pretty(self).context("Failed to serialise config")?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))?;
        Ok(())
    }

    /// Resolve the active profile name: `--profile` → `ODAL_PROFILE` →
    /// file `current_profile` → `default`.
    pub(super) fn active_name(&self) -> String {
        if let Some(Some(name)) = PROFILE_OVERRIDE.get() {
            return name.clone();
        }
        if let Ok(env) = std::env::var("ODAL_PROFILE")
            && !env.is_empty()
        {
            return env;
        }
        self.current_profile
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_PROFILE.to_owned())
    }
}

/// What to tell someone whose CLI holds no configuration at all.
///
/// One string, because two commands say it and the pair drifting is the whole
/// complaint: `profile list` reported the real state while every other command
/// reached the node anyway and blamed the credential for a 401.
pub const NO_PROFILE_HINT: &str = "No profile configured yet. Run `odal` to set one up, or \
     `odal profile create <name> --node-url <url>`.";

/// True when the config file holds at least one profile.
///
/// Distinguishes "not configured yet" from "configured and wrong", which the
/// CLI could not previously tell apart: [`Config::load`] hands back a default
/// localhost profile on a fresh install so first-run setup works, and every
/// caller downstream then behaved as though the operator had chosen it.
///
/// [`Config::load`]: crate::config::Config::load
pub fn has_profiles() -> bool {
    ConfigFile::load().is_ok_and(|f| !f.profiles.is_empty())
}
// ── Profile management (used by `odal profile …`) ───────────────────────────────

/// A profile entry for listing: name, the profile, and whether it is active.
pub struct ProfileEntry {
    pub name: String,
    pub profile: Profile,
    pub is_active: bool,
}

/// List all profiles plus the resolved active name.
pub fn list_profiles() -> Result<Vec<ProfileEntry>> {
    let file = ConfigFile::load()?;
    let active = file.active_name();
    Ok(file
        .profiles
        .iter()
        .map(|(name, profile)| ProfileEntry {
            name: name.clone(),
            profile: normalize(profile.clone()),
            is_active: *name == active,
        })
        .collect())
}

/// The resolved active profile name (without loading the full profile).
pub fn active_profile_name() -> Result<String> {
    Ok(ConfigFile::load()?.active_name())
}

/// Set the file's `current_profile`. Errors if the profile does not exist.
pub fn use_profile(name: &str) -> Result<()> {
    let mut file = ConfigFile::load()?;
    if !file.profiles.contains_key(name) {
        bail!("profile '{name}' not found. Create it first with `odal profile create {name}`.");
    }
    file.current_profile = Some(name.to_owned());
    file.write()
}

/// Create a new profile. Refuses to overwrite an existing one unless `force`.
pub fn create_profile(name: &str, profile: Profile, force: bool) -> Result<()> {
    if name.is_empty() {
        bail!("profile name must not be empty");
    }
    let mut file = ConfigFile::load()?;
    if file.profiles.contains_key(name) && !force {
        bail!("profile '{name}' already exists. Pass --force to overwrite it.");
    }
    file.profiles.insert(name.to_owned(), normalize(profile));
    if file.current_profile.is_none() {
        file.current_profile = Some(name.to_owned());
    }
    file.write()
}

/// Remove a profile. Errors if it is the only one or does not exist.
pub fn remove_profile(name: &str) -> Result<()> {
    let mut file = ConfigFile::load()?;
    if !file.profiles.contains_key(name) {
        bail!("profile '{name}' not found.");
    }
    file.profiles.remove(name);
    if file.current_profile.as_deref() == Some(name) {
        // Point current at any remaining profile, or clear it.
        file.current_profile = file.profiles.keys().next().cloned();
    }
    file.write()?;
    crate::credentials::remove_key(name)?;
    Ok(())
}

/// Rename a profile, preserving its active status.
pub fn rename_profile(old: &str, new: &str) -> Result<()> {
    if new.is_empty() {
        bail!("new profile name must not be empty");
    }
    let mut file = ConfigFile::load()?;
    let profile = file
        .profiles
        .remove(old)
        .ok_or_else(|| anyhow::anyhow!("profile '{old}' not found."))?;
    if file.profiles.contains_key(new) {
        bail!("profile '{new}' already exists.");
    }
    file.profiles.insert(new.to_owned(), profile);
    if file.current_profile.as_deref() == Some(old) {
        file.current_profile = Some(new.to_owned());
    }
    file.write()?;
    crate::credentials::rename_key(old, new)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_round_trip_toml() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "prod".to_owned(),
            Profile {
                kind: EnvKind::Prod,
                vault_url: "https://node.example/vault".into(),
                identity_url: "https://node.example/identity".into(),
                resolver_url: "https://node.example:8003".into(),
                api_key: "odal_sk_test123".into(),
            },
        );
        let file = ConfigFile {
            current_profile: Some("prod".into()),
            profiles,
        };
        let toml_str = toml::to_string_pretty(&file).unwrap();
        let back: ConfigFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(back.current_profile.as_deref(), Some("prod"));
        let p = back.profiles.get("prod").unwrap();
        assert_eq!(p.kind, EnvKind::Prod);
        assert_eq!(p.api_key, "odal_sk_test123");
    }

    #[test]
    fn legacy_flat_config_migrates_to_default_profile() {
        let legacy = r#"
            vault_url = "https://old.example/vault"
            api_key = "odal_sk_legacy"
        "#;
        let parsed: LegacyConfig = toml::from_str(legacy).unwrap();
        assert!(parsed.has_content());
        let p = parsed.into_profile();
        assert_eq!(p.vault_url, "https://old.example/vault");
        assert_eq!(p.api_key, "odal_sk_legacy");
        // Non-localhost vault → inferred prod.
        assert_eq!(p.kind, EnvKind::Prod);
    }

    /// A config that does not parse must be an error, never `Self::default()`.
    ///
    /// The round-trip test above cannot reach this: it serialises and
    /// deserialises with the same `toml` version, so it only ever sees input
    /// this build can parse. The case guarded here is input this build *cannot*
    /// parse degrading to an empty file that `write` then commits over every
    /// configured profile.
    #[test]
    fn a_malformed_config_is_an_error_not_an_empty_default() {
        let malformed = "current_profile = \"new_dev\"\n\
                         [profiles.new_dev]\n\
                         vault_url = \"https://node.example.com/vault\n";
        let path = Path::new("/home/op/.config/odal/config.toml");
        let err = ConfigFile::parse(malformed, path)
            .expect_err("a malformed config must not parse as an empty file");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("config.toml"),
            "the error must name the file to fix:\n{rendered}"
        );
    }

    /// The legacy migration must survive the change above.
    ///
    /// It is reached on the parsed-but-no-profiles branch, not on a parse error:
    /// a flat pre-profiles file is valid TOML whose keys `ConfigFile` does not
    /// name, so serde ignores them. Asserting that through `parse` — rather than
    /// against `LegacyConfig` alone, as the test below it does — is what pins
    /// the branch order, since propagating the error would otherwise be free to
    /// cut the fallback off.
    #[test]
    fn a_legacy_flat_config_still_migrates_through_parse() {
        let legacy = "vault_url = \"https://old.example/vault\"\n\
                      api_key = \"odal_sk_legacy\"\n";
        let path = Path::new("/home/op/.config/odal/config.toml");
        let file = ConfigFile::parse(legacy, path).expect("a legacy flat config must still load");
        assert_eq!(file.current_profile.as_deref(), Some(DEFAULT_PROFILE));
        let p = file
            .profiles
            .get(DEFAULT_PROFILE)
            .expect("migrated into the default profile");
        assert_eq!(p.vault_url, "https://old.example/vault");
        assert_eq!(p.api_key, "odal_sk_legacy");
    }

    /// The legacy branch must not swallow its own parse error.
    ///
    /// `ConfigFile` ignores unknown top-level keys, so a flat file whose
    /// `vault_url` (or any of the four) carries the wrong type still parses as an
    /// empty `ConfigFile` and lands on the empty-profiles branch. Reading it as
    /// `LegacyConfig` is what fails — and dropping that failure hands back the
    /// empty file, so the next save overwrites the operator's values. Same erase
    /// as the main read, one branch further down.
    #[test]
    fn a_malformed_legacy_config_is_an_error_not_an_empty_default() {
        // A legacy flat file with an integer where a URL belongs.
        let malformed = "vault_url = 8001\napi_key = \"odal_sk_legacy\"\n";
        let path = Path::new("/home/op/.config/odal/config.toml");
        // It must reach the legacy branch at all — i.e. the new-format parse has
        // to accept it, which is what makes the swallow reachable.
        assert!(
            toml::from_str::<ConfigFile>(malformed)
                .expect("unknown top-level keys are ignored, so this parses")
                .profiles
                .is_empty()
        );
        let err = ConfigFile::parse(malformed, path)
            .expect_err("a malformed legacy config must not parse as an empty file");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("config.toml"),
            "the error must name the file to fix:\n{rendered}"
        );
    }

    /// An absent file is a fresh install; an empty one carries no profiles.
    /// Making a parse failure loud must not make either of those loud.
    #[test]
    fn an_empty_config_still_parses_as_no_profiles() {
        let path = Path::new("/home/op/.config/odal/config.toml");
        assert!(ConfigFile::parse("", path).unwrap().profiles.is_empty());
    }

    #[test]
    fn new_format_parses_over_legacy() {
        let toml_str = r#"
            current_profile = "dev"
            [profiles.dev]
            kind = "dev"
            vault_url = "http://localhost:8001/vault"
        "#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        assert!(!file.profiles.is_empty());
        assert_eq!(file.active_name(), "dev");
    }

    #[test]
    fn ensure_path_suffix_appends_to_bare_url() {
        assert_eq!(
            ensure_path_suffix("http://127.0.0.1:8001", "/vault"),
            "http://127.0.0.1:8001/vault"
        );
    }

    #[test]
    fn ensure_path_suffix_leaves_url_with_suffix_alone() {
        assert_eq!(
            ensure_path_suffix("http://localhost:8001/vault", "/vault"),
            "http://localhost:8001/vault"
        );
    }

    #[test]
    fn normalize_aligns_identity_host_with_vault() {
        let p = normalize(Profile {
            vault_url: "http://example:9000".into(),
            identity_url: "http://other:1234/identity".into(),
            ..Profile::default()
        });
        assert_eq!(p.vault_url, "http://example:9000/vault");
        assert_eq!(p.identity_url, "http://example:9000/identity");
    }

    #[test]
    fn normalize_preserves_https_scheme_for_identity() {
        let p = normalize(Profile {
            kind: EnvKind::Prod,
            vault_url: "https://node.acme.example/vault".into(),
            ..Profile::default()
        });
        // identity must follow the vault's host AND scheme (https, not http).
        assert_eq!(p.identity_url, "https://node.acme.example/identity");
    }
}
