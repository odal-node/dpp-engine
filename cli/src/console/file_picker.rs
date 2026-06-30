//! Native OS file picker for `Passports › Import`.
//!
//! A terminal path prompt forces the operator to type `../../../` to reach a
//! file anywhere but the current directory. Instead we hand off to the native
//! OS open-file dialog (Explorer / Finder / portal), which browses the whole
//! machine with the familiar sidebar, search, and recents — then remember the
//! chosen directory so the next import opens right where the data lives.

use std::path::{Path, PathBuf};

use crate::config::config_dir;

/// Open the native "open file" dialog, filtered to importable formats.
///
/// Returns the chosen path, or `None` if the operator cancels **or** no display
/// is available (e.g. a localhost node reached over SSH). Callers must treat
/// `None` as "fall back to typing a path", never as a hard stop — otherwise a
/// headless session would have no way to select a file.
pub async fn pick_import_file() -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .set_title("Select a passport import file")
        .add_filter("Data files (CSV, TSV, JSON)", &["csv", "tsv", "json"])
        .set_directory(start_dir())
        .pick_file()
        .await
        .map(|handle| handle.path().to_path_buf())
}

/// Where the dialog opens: the last successful import's directory, then the
/// user's Documents folder, then home, then the current directory. This is the
/// difference between "technically a picker" and one that feels intuitive.
fn start_dir() -> PathBuf {
    last_import_dir()
        .or_else(dirs::document_dir)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Remember the directory containing `file` so the next picker opens there.
/// Best-effort: a failure to persist must never block the import.
pub fn remember_dir(file: &Path) {
    let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return;
    };
    let Ok(state) = state_path() else { return };
    if let Some(parent) = state.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&state, dir.to_string_lossy().as_bytes());
}

/// The last remembered import directory, if the file exists and still resolves
/// to a real directory (it may have been moved or deleted since).
fn last_import_dir() -> Option<PathBuf> {
    let raw = std::fs::read_to_string(state_path().ok()?).ok()?;
    let dir = PathBuf::from(raw.trim());
    dir.is_dir().then_some(dir)
}

/// `~/.config/odal/last-import-dir` — a one-line state file, deliberately kept
/// out of `config.toml` (it's transient UX state, not connection config).
fn state_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("last-import-dir"))
}
