//! `POST /api/v1/plugins` — admin-only runtime install of a signed product group plugin.
//!
//! Delegates to the node's [`PluginAdmin`] port (the Wasm plugin host), which
//! verifies the signature against the pinned publisher key, gates the ABI,
//! instantiate-smokes the module, persists it so a restart re-loads it, and
//! hot-swaps it into service — fail-closed, last-good on any rejection.

use axum::{
    Json,
    extract::{Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::plugin_admin::PluginInstallError;

use crate::state::AppState;

use super::error::api_error;
use crate::middleware::scope::RequireAdmin;

/// `POST /api/v1/plugins` — verify, persist, and hot-swap a signed product group plugin.
///
/// `multipart/form-data` with:
/// - `wasm` (required, file) — the `.wasm` (or precompiled `.cwasm`) artifact. A
///   `.cwasm` filename selects the AOT path (loaded only if it matches this
///   node's engine).
/// - `sig` (required) — its detached Ed25519 signature over `SHA-256(artifact)`.
/// - `productGroup` (optional, text) — the product group key; if omitted it is derived from
///   the `wasm` part's filename (`product-group-<key>.wasm`). Spelled camelCase, as the
///   match arm below and the API description both have it; this line said `product_group`,
///   and an unrecognised multipart field is skipped rather than refused, so a caller
///   following it had the value silently ignored and fell through to the filename.
pub async fn install_plugin_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireAdmin(_auth): RequireAdmin,
    mut multipart: Multipart,
) -> Response {
    let Some(admin) = state.plugin_admin.clone() else {
        return api_error(
            StatusCode::NOT_IMPLEMENTED,
            "PLUGINS_DISABLED",
            "This node has no plugin host configured; runtime install is unavailable.",
        );
    };

    let mut wasm: Option<Vec<u8>> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut product_group: Option<String> = None;
    let mut wasm_filename: Option<String> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_owned();
                match name.as_str() {
                    "wasm" => {
                        wasm_filename = field.file_name().map(|s| s.to_owned());
                        match field.bytes().await {
                            Ok(b) => wasm = Some(b.to_vec()),
                            Err(e) => return bad(format!("could not read 'wasm' field: {e}")),
                        }
                    }
                    "sig" => match field.bytes().await {
                        Ok(b) => sig = Some(b.to_vec()),
                        Err(e) => return bad(format!("could not read 'sig' field: {e}")),
                    },
                    "productGroup" => {
                        product_group = field.text().await.ok().filter(|s| !s.is_empty())
                    }
                    _ => {
                        // Drain and ignore unknown parts.
                        let _ = field.bytes().await;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => return bad(format!("multipart read error: {e}")),
        }
    }

    let (Some(wasm), Some(sig)) = (wasm, sig) else {
        return bad("multipart body must include both a 'wasm' and a 'sig' field.".to_owned());
    };
    let Some(product_group) =
        product_group.or_else(|| wasm_filename.as_deref().and_then(derive_product_group))
    else {
        return bad(
            "product_group could not be determined — pass a 'product_group' field or name the file \
             'product-group-<key>.wasm'."
                .to_owned(),
        );
    };
    // A `.cwasm` filename marks a precompiled (AOT) artifact; anything else is a
    // portable `.wasm` compiled on the node.
    let precompiled = wasm_filename
        .as_deref()
        .is_some_and(|f| f.ends_with(".cwasm"));

    // Install is blocking (wasm compile + disk IO); keep it off the async worker.
    match tokio::task::spawn_blocking(move || admin.install(&product_group, wasm, sig, precompiled))
        .await
    {
        Ok(Ok(report)) => (StatusCode::CREATED, Json(report)).into_response(),
        Ok(Err(e)) => install_error(e),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            &format!("plugin install task failed: {e}"),
        ),
    }
}

/// Derive a product group key from an uploaded filename: `product-group-battery.wasm` → `battery`.
fn derive_product_group(filename: &str) -> Option<String> {
    let stem = std::path::Path::new(filename).file_stem()?.to_str()?;
    let key = stem.trim_start_matches("product-group-");
    (!key.is_empty()).then(|| key.to_owned())
}

fn bad(msg: String) -> Response {
    api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", &msg)
}

fn install_error(e: PluginInstallError) -> Response {
    match e {
        PluginInstallError::Rejected(m) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PLUGIN_REJECTED",
            &format!("plugin rejected: {m}"),
        ),
        PluginInstallError::NotSupported => api_error(
            StatusCode::NOT_IMPLEMENTED,
            "PLUGINS_DISABLED",
            "Runtime plugin install is not enabled on this node.",
        ),
        PluginInstallError::Persist(m) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PLUGIN_PERSIST_FAILED",
            &format!("failed to persist plugin: {m}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_product_group_strips_prefix_and_extension() {
        assert_eq!(
            derive_product_group("product-group-battery.wasm").as_deref(),
            Some("battery")
        );
        assert_eq!(
            derive_product_group("textile.wasm").as_deref(),
            Some("textile")
        );
        assert_eq!(derive_product_group("product-group-.wasm"), None);
    }
}
