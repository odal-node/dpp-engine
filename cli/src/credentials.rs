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

/// The conventional "read this from stdin" argument value.
pub const STDIN_SENTINEL: &str = "-";

/// Interpret a secret supplied as a command-line argument.
///
/// `-` means "read it from stdin", the usual Unix convention and the only form
/// that is both scriptable and free of exposure: a literal argument is visible
/// in shell history and, for the lifetime of the process, to any local user via
/// `ps` or `/proc/<pid>/cmdline`. Environment variables are better but not
/// equivalent — they are inherited by every child process and readable from
/// `/proc/<pid>/environ` by the same user.
///
/// A literal value is still accepted, because removing it would break existing
/// scripts, but it warns so the safer form is discoverable at the moment it
/// matters.
///
/// # Errors
/// If `-` was given and stdin cannot be read.
pub fn resolve_secret_arg(arg: Option<String>, safer: &str) -> Result<Option<String>> {
    let Some(value) = arg else {
        return Ok(None);
    };
    if value == STDIN_SENTINEL {
        return read_secret_from_stdin().map(Some);
    }
    eprintln!(
        "warning: passing a secret as a command-line argument exposes it in shell \
         history and to local users via `ps`. Use `-` to read it from stdin, or {safer}."
    );
    Ok(Some(value))
}

/// Read a single secret from stdin.
fn read_secret_from_stdin() -> Result<String> {
    use std::io::Read as _;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("Failed to read the secret from stdin")?;
    parse_stdin_secret(&buf)
}

/// Trim the line ending a pipe, heredoc or `echo` leaves behind, and reject an
/// empty read rather than storing a blank credential.
///
/// Only the *trailing* newline is removed: a secret is taken as the literal
/// bytes otherwise, so leading or interior whitespace someone deliberately put
/// in a passphrase survives.
fn parse_stdin_secret(raw: &str) -> Result<String> {
    let secret = raw.trim_end_matches(['\n', '\r']).to_owned();
    if secret.is_empty() {
        anyhow::bail!("no secret received on stdin");
    }
    Ok(secret)
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

    /// Omitting the argument must stay "no value" so the caller can fall back
    /// to its env var or prompt — the stdin handling must not swallow that.
    #[test]
    fn absent_argument_resolves_to_none() {
        assert_eq!(resolve_secret_arg(None, "set $X").unwrap(), None);
    }

    /// A literal value is still honoured — removing it would break scripts —
    /// but the caller gets it back unchanged, warning notwithstanding.
    #[test]
    fn literal_argument_is_passed_through() {
        assert_eq!(
            resolve_secret_arg(Some("odal_sk_literal".to_owned()), "set $X").unwrap(),
            Some("odal_sk_literal".to_owned())
        );
    }

    /// `-` is the stdin sentinel, not a secret whose value happens to be "-".
    #[test]
    fn stdin_sentinel_is_the_hyphen() {
        assert_eq!(STDIN_SENTINEL, "-");
    }

    /// `echo secret | odal key use -` and the CRLF equivalent must both yield
    /// the secret, not the secret plus a line ending that would fail auth in a
    /// way nobody could diagnose from the error.
    #[test]
    fn stdin_secret_trims_the_trailing_line_ending() {
        assert_eq!(parse_stdin_secret("odal_sk_abc\n").unwrap(), "odal_sk_abc");
        assert_eq!(
            parse_stdin_secret("odal_sk_abc\r\n").unwrap(),
            "odal_sk_abc"
        );
        assert_eq!(parse_stdin_secret("odal_sk_abc").unwrap(), "odal_sk_abc");
    }

    /// Only the trailing line ending goes — a passphrase may legitimately
    /// contain spaces, and silently trimming them would lock someone out.
    #[test]
    fn stdin_secret_preserves_interior_and_leading_whitespace() {
        assert_eq!(
            parse_stdin_secret("  pass phrase with spaces  \n").unwrap(),
            "  pass phrase with spaces  "
        );
    }

    /// An empty pipe must fail loudly rather than store a blank credential.
    #[test]
    fn stdin_secret_rejects_an_empty_read() {
        assert!(parse_stdin_secret("").is_err());
        assert!(parse_stdin_secret("\n").is_err());
        assert!(parse_stdin_secret("\r\n").is_err());
    }

    #[test]
    fn credentials_path_is_in_odal_dir() {
        let p = credentials_path().unwrap();
        assert!(p.to_string_lossy().ends_with("credentials.toml"));
        assert!(p.to_string_lossy().contains("odal"));
    }
}
