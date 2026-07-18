//! Plugin discovery — find `.wasm` files and derive their sector key.

use std::path::Path;

use anyhow::Result;

/// Discover all `.wasm` and precompiled `.cwasm` files in `plugins_dir` and
/// return (sector_key, path) pairs.
///
/// The sector key is the file stem, e.g. `sector-textile.wasm` → `"textile"`
/// (and likewise `sector-battery.cwasm` → `"battery"`).
pub fn discover_plugins(plugins_dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut found = Vec::new();
    if !plugins_dir.exists() {
        tracing::warn!(dir = %plugins_dir.display(), "plugins directory not found — no plugins loaded");
        return Ok(found);
    }
    for entry in std::fs::read_dir(plugins_dir)? {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("wasm") | Some("cwasm")) {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .trim_start_matches("sector-")
                .to_owned();
            found.push((stem, path));
        }
    }
    Ok(found)
}
