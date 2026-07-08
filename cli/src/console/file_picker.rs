//! Native OS file picker, shared by any console flow that needs to pick a
//! local file (`Passports › Import`, `Verify`).
//!
//! A terminal path prompt forces the operator to type `../../../` to reach a
//! file anywhere but the current directory. Instead we hand off to the native
//! OS open-file dialog (Explorer / Finder / portal), which browses the whole
//! machine with the familiar sidebar, search, and recents — then remember the
//! chosen directory (one remembered directory per picker) so the next pick
//! opens right where that kind of file lives.

use std::path::{Path, PathBuf};

use crate::config::config_dir;

/// Open the native "open file" dialog, filtered to importable formats.
///
/// Returns the chosen path, or `None` if the operator cancels **or** no display
/// is available (e.g. a localhost node reached over SSH). Callers must treat
/// `None` as "fall back to typing a path", never as a hard stop — otherwise a
/// headless session would have no way to select a file.
pub async fn pick_import_file() -> Option<PathBuf> {
    pick_file(
        "Select a passport import file",
        "Data files (CSV, TSV, JSON)",
        &["csv", "tsv", "json"],
        "import",
    )
    .await
}

/// Open the native "open file" dialog, filtered to evidence dossier JSON files.
/// Same cancel/no-display semantics as [`pick_import_file`].
pub async fn pick_dossier_file() -> Option<PathBuf> {
    pick_file(
        "Select an evidence dossier file",
        "Dossier files (JSON)",
        &["json"],
        "dossier",
    )
    .await
}

async fn pick_file(
    title: &str,
    filter_name: &str,
    filter_exts: &[&str],
    remember_key: &str,
) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .set_title(title)
        .add_filter(filter_name, filter_exts)
        .set_directory(start_dir(remember_key))
        .pick_file()
        .await
        .map(|handle| handle.path().to_path_buf())
}

/// Where the dialog opens: the last successful pick's directory (per
/// `remember_key`), then the user's Documents folder, then home, then the
/// current directory. This is the difference between "technically a picker"
/// and one that feels intuitive.
fn start_dir(remember_key: &str) -> PathBuf {
    last_dir(remember_key)
        .or_else(dirs::document_dir)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Remember the directory containing `file` so the next import picker opens there.
pub fn remember_import_dir(file: &Path) {
    remember_dir("import", file);
}

/// Remember the directory containing `file` so the next dossier picker opens there.
pub fn remember_dossier_dir(file: &Path) {
    remember_dir("dossier", file);
}

/// Best-effort: a failure to persist must never block the caller's flow.
fn remember_dir(remember_key: &str, file: &Path) {
    let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return;
    };
    let Ok(state) = state_path(remember_key) else {
        return;
    };
    if let Some(parent) = state.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&state, dir.to_string_lossy().as_bytes());
}

/// The last remembered directory for `remember_key`, if it still resolves to
/// a real directory (it may have been moved or deleted since).
fn last_dir(remember_key: &str) -> Option<PathBuf> {
    let raw = std::fs::read_to_string(state_path(remember_key).ok()?).ok()?;
    let dir = PathBuf::from(raw.trim());
    dir.is_dir().then_some(dir)
}

/// `~/.config/odal/last-{key}-dir` — a one-line state file per picker,
/// deliberately kept out of `config.toml` (it's transient UX state, not
/// connection config).
fn state_path(remember_key: &str) -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(format!("last-{remember_key}-dir")))
}
