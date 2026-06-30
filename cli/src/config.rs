//! Connection config and named profiles (`config.toml`): load, save, and resolution.

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

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

/// On-disk config file format: a set of named profiles plus the active one.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigFile {
    /// The active profile name. `--profile` / `ODAL_PROFILE` override this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_profile: Option<String>,
    /// All known profiles, keyed by name.
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
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
fn default_vault_url() -> String {
    "http://localhost:8001/vault".into()
}

fn default_identity_url() -> String {
    "http://localhost:8001/identity".into()
}

fn default_resolver_url() -> String {
    "http://localhost:8003".into()
}

const DEFAULT_PROFILE: &str = "default";

/// Process-wide override for the active profile, set once from the `--profile`
/// flag in `main()`. Takes precedence over `ODAL_PROFILE` and the file's
/// `current_profile`.
static PROFILE_OVERRIDE: OnceLock<Option<String>> = OnceLock::new();

/// Record the `--profile` flag value (if any). Call once, early in `main()`.
pub fn set_active_profile_override(name: Option<String>) {
    let _ = PROFILE_OVERRIDE.set(name.filter(|s| !s.is_empty()));
}

/// True if the URL points at the local machine.
fn url_is_localhost(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("localhost") || lower.contains("127.0.0.1") || lower.contains("::1")
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
fn normalize(mut p: Profile) -> Profile {
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
fn resolve_api_key(name: &str, profile: &Profile) -> String {
    if let Ok(key) = std::env::var("ODAL_API_KEY")
        && !key.is_empty()
    {
        return key;
    }
    if let Some(key) = crate::credentials::load_key(name) {
        return key;
    }
    profile.api_key.clone()
}

impl ConfigFile {
    /// Load the on-disk config, migrating a legacy flat file into a `default`
    /// profile if necessary. Returns an empty file if none exists.
    fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        // Try the new profile-based format first.
        let file: ConfigFile = toml::from_str(&content).unwrap_or_default();
        if !file.profiles.is_empty() {
            return Ok(file);
        }

        // Fall back to migrating a legacy flat config.
        if let Ok(legacy) = toml::from_str::<LegacyConfig>(&content)
            && legacy.has_content()
        {
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
    fn write(&self) -> Result<()> {
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
    fn active_name(&self) -> String {
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
            None => bail!(
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
    file.profiles.insert(name.to_owned(), profile);
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

/// Mask a secret to its identifying prefix for display, e.g. `odal_sk_ab…`.
pub fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        return "(none)".to_owned();
    }
    let shown: String = secret.chars().take(11).collect();
    format!("{shown}…")
}

/// Returns the path to `~/.config/odal/config.toml`.
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// Returns the `~/.config/odal` directory.
pub fn config_dir() -> Result<PathBuf> {
    let home =
        home_dir().context("Could not determine home directory — set HOME environment variable")?;
    Ok(home.join(".config").join("odal"))
}

/// Returns the `~/.config/odal/exports` directory — where bare-filename exports
/// land so they never clutter (or get committed from) the working directory.
pub fn export_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("exports"))
}

/// True if `output` carries a directory component (relative or absolute), e.g.
/// `./out.csv`, `sub/out.csv`, `/abs/out.csv`. A bare filename like `out.csv`
/// has none.
fn has_dir_component(output: &str) -> bool {
    Path::new(output)
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
}

/// Resolve a user-supplied export `-o` value to a final path.
///
/// A bare filename (no directory component) is placed in [`export_dir`], which
/// is created if missing. Any path with a directory component — relative or
/// absolute — is honoured exactly as given (resolved against the cwd by the OS).
pub fn export_target(output: &str) -> Result<PathBuf> {
    if has_dir_component(output) {
        return Ok(PathBuf::from(output));
    }
    let dir = export_dir()?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create export dir: {}", dir.display()))?;
    Ok(dir.join(output))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| {
            // Fallback for Windows: HOMEDRIVE + HOMEPATH
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            let mut p = PathBuf::from(drive);
            p.push(path);
            Some(p)
        })
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
    fn env_kind_infers_from_url() {
        assert_eq!(EnvKind::infer("http://localhost:8001/vault"), EnvKind::Dev);
        assert_eq!(EnvKind::infer("http://127.0.0.1:8001"), EnvKind::Dev);
        assert_eq!(
            EnvKind::infer("https://node.acme.example/vault"),
            EnvKind::Prod
        );
    }

    #[test]
    fn mask_secret_shows_prefix_only() {
        assert_eq!(mask_secret("odal_sk_abcdefghijklmnop"), "odal_sk_abc…");
        assert_eq!(mask_secret(""), "(none)");
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

    #[test]
    fn config_path_returns_odal_dir() {
        let path = config_path().unwrap();
        assert!(path.to_string_lossy().contains("odal"));
        assert!(path.to_string_lossy().ends_with("config.toml"));
    }

    #[test]
    fn bare_filename_has_no_dir_component() {
        // Bare names route to the managed exports dir.
        assert!(!has_dir_component("report.csv"));
        assert!(!has_dir_component("export"));
        // Anything with a path component is honoured as-is (cwd or absolute).
        assert!(has_dir_component("./report.csv"));
        assert!(has_dir_component("sub/report.csv"));
        assert!(has_dir_component("/abs/report.csv"));
    }
}
