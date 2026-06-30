//! Secret-at-rest store for operator API keys, kept **separate** from the
//! non-secret connection config (the AWS CLI `config` vs `credentials` split).
//!
//! Keys live in `~/.config/odal/credentials.toml`, keyed by profile name, and
//! the file is written with owner-only permissions (`0600` on Unix; on Windows
//! it inherits the per-user ACL of the profile directory under `%USERPROFILE%`).
//! `config.toml` therefore never has to contain a secret.
//!
//! Resolution precedence for a profile's key is handled in `config::Config::load`:
//! `ODAL_API_KEY` env → this store → (back-compat) any `api_key` still inline in
//! `config.toml`.

use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::config_dir;

/// On-disk credentials file: API keys keyed by profile name.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CredentialsFile {
    #[serde(default)]
    keys: BTreeMap<String, String>,
}

/// Path to `~/.config/odal/credentials.toml`.
pub fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("credentials.toml"))
}

impl CredentialsFile {
    fn load() -> Result<Self> {
        let path = credentials_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read credentials: {}", path.display()))?;
        Ok(toml::from_str(&content).unwrap_or_default())
    }

    fn write(&self) -> Result<()> {
        let path = credentials_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create credentials dir: {}", parent.display())
            })?;
        }
        let content = toml::to_string_pretty(self).context("Failed to serialise credentials")?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write credentials: {}", path.display()))?;
        restrict_permissions(&path)?;
        Ok(())
    }
}

/// Read a profile's stored API key, if any.
pub fn load_key(profile: &str) -> Option<String> {
    CredentialsFile::load()
        .ok()?
        .keys
        .get(profile)
        .filter(|s| !s.is_empty())
        .cloned()
}

/// Store (or replace) a profile's API key.
pub fn save_key(profile: &str, key: &str) -> Result<()> {
    let mut file = CredentialsFile::load().unwrap_or_default();
    file.keys.insert(profile.to_owned(), key.to_owned());
    file.write()
}

/// Remove a profile's API key (no-op if absent).
pub fn remove_key(profile: &str) -> Result<()> {
    let mut file = CredentialsFile::load().unwrap_or_default();
    if file.keys.remove(profile).is_some() {
        file.write()?;
    }
    Ok(())
}

/// Move a profile's API key under a new profile name (used by `profile rename`).
pub fn rename_key(old: &str, new: &str) -> Result<()> {
    let mut file = CredentialsFile::load().unwrap_or_default();
    if let Some(key) = file.keys.remove(old) {
        file.keys.insert(new.to_owned(), key);
        file.write()?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<()> {
    // Windows: the file lives under %USERPROFILE%\.config\odal, which carries a
    // per-user ACL by default. No portable chmod equivalent is applied here.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_toml() {
        let mut keys = BTreeMap::new();
        keys.insert("dev".to_owned(), "odal_sk_dev".to_owned());
        keys.insert("prod".to_owned(), "odal_sk_prod".to_owned());
        let file = CredentialsFile { keys };
        let s = toml::to_string_pretty(&file).unwrap();
        let back: CredentialsFile = toml::from_str(&s).unwrap();
        assert_eq!(back.keys.get("dev").unwrap(), "odal_sk_dev");
        assert_eq!(back.keys.get("prod").unwrap(), "odal_sk_prod");
    }

    #[test]
    fn credentials_path_is_in_odal_dir() {
        let p = credentials_path().unwrap();
        assert!(p.to_string_lossy().ends_with("credentials.toml"));
        assert!(p.to_string_lossy().contains("odal"));
    }
}
