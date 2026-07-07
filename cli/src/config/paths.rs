//! Filesystem locations: the config dir, the config file, and export targets.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

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
