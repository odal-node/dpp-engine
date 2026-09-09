//! Plugin discovery — find `.wasm` files and derive their product group key.

use std::path::Path;

use anyhow::Result;

/// The filename convention a plugin artifact must follow.
const PREFIX: &str = "product-group-";

/// Discover all `.wasm` and precompiled `.cwasm` files in `plugins_dir` and
/// return (product_group_key, path) pairs.
///
/// The product group key is the file stem with [`PREFIX`] removed, e.g.
/// `product-group-textile.wasm` → `"textile"` (and likewise
/// `product-group-battery.cwasm` → `"battery"`).
///
/// # Why a file that breaks the convention is skipped rather than loaded
///
/// This used to take the whole stem when the prefix was absent, so
/// `sector-battery.wasm` registered under the key `"sector-battery"`. Nothing
/// ever asks for that key: `has_plugin("battery")` stays false, the compliance
/// port resolves `ghost`, and every determination falls through to the
/// passthrough registry. The boot logged `plugin loaded` and named the bogus
/// key, so a total loss of compliance checking presented as a healthy node.
///
/// Skipping loses nothing that worked — a key outside the convention could
/// never bind to a product group — and replaces a reassuring line with one that
/// says what is wrong. The node still boots; its compliance port still reports
/// `ghost`, which is now the honest answer rather than an unexplained one.
///
/// A **well-named** file whose key the catalog does not know is a different
/// case and is loaded with a warning rather than skipped: a newer `dpp-domain`
/// can name a product group this build has never heard of, and refusing it
/// would turn a forward-compatible deployment into a broken one.
///
/// `strip_prefix`, not `trim_start_matches`: the latter removes the prefix
/// *repeatedly*, so `product-group-product-group-battery.wasm` also resolved to
/// `"battery"` — two different files silently claiming one key.
pub fn discover_plugins(plugins_dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut found = Vec::new();
    if !plugins_dir.exists() {
        tracing::warn!(dir = %plugins_dir.display(), "plugins directory not found — no plugins loaded");
        return Ok(found);
    }
    let catalog = dpp_domain::catalog::ProductGroupCatalog::new();
    for entry in std::fs::read_dir(plugins_dir)? {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("wasm") | Some("cwasm")) {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let Some(key) = stem.strip_prefix(PREFIX) else {
            tracing::warn!(
                file = %path.display(),
                expected = %format!("{PREFIX}<product group>.wasm"),
                "ignoring a plugin artifact that does not follow the filename convention — \
                 its product group cannot be derived, so it could only ever load under a key \
                 nothing asks for"
            );
            continue;
        };
        if key.is_empty() {
            tracing::warn!(
                file = %path.display(),
                "ignoring a plugin artifact whose filename carries the prefix and no product group"
            );
            continue;
        }
        if catalog.get(key).is_none() {
            tracing::warn!(
                file = %path.display(),
                key,
                "loading a plugin for a product group this build's catalog does not know — \
                 it will bind only if something asks for that key"
            );
        }
        found.push((key.to_owned(), path));
    }
    Ok(found)
}
