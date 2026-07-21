//! `POST /api/v1/plugins` — admin-only runtime install of a signed sector plugin.
//!
//! Delegates to the node's [`PluginAdmin`] port (the Wasm plugin host), which
//! verifies the signature against the pinned publisher key, gates the ABI,
//! instantiate-smokes the module, persists it so a restart re-loads it, and
//! hot-swaps it into service — fail-closed, last-good on any rejection.

use axum::{
    Json,
    extract::{Extension, Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::plugin_admin::PluginInstallError;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::api_error;

/// Installing executable plugin code is an administrative action — a
/// least-privilege (`read`/`write`) key must never be able to swap the code the
/// node runs.
fn require_admin(auth: &AuthContext) -> Option<Response> {
    if auth.scope.is_admin() {
        None
    } else {
        Some(api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Installing a plugin requires an admin-scoped credential.",
        ))
    }
}

/// `POST /api/v1/plugins` — verify, persist, and hot-swap a signed sector plugin.
///
/// `multipart/form-data` with:
/// - `wasm` (required, file) — the `.wasm` (or precompiled `.cwasm`) artifact. A
///   `.cwasm` filename selects the AOT path (loaded only if it matches this
///   node's engine).
/// - `sig` (required) — its detached Ed25519 signature over `SHA-256(artifact)`.
/// - `sector` (optional, text) — the sector key; if omitted it is derived from
///   the `wasm` part's filename (`sector-<key>.wasm`).
pub async fn install_plugin_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    mut multipart: Multipart,
) -> Response {
    if let Some(resp) = require_admin(&auth) {
        return resp;
    }

    let Some(admin) = state.plugin_admin.clone() else {
        return api_error(
            StatusCode::NOT_IMPLEMENTED,
            "PLUGINS_DISABLED",
            "This node has no plugin host configured; runtime install is unavailable.",
        );
    };

    let mut wasm: Option<Vec<u8>> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut sector: Option<String> = None;
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
                    "sector" => sector = field.text().await.ok().filter(|s| !s.is_empty()),
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
    let Some(sector) = sector.or_else(|| wasm_filename.as_deref().and_then(derive_sector)) else {
        return bad(
            "sector could not be determined — pass a 'sector' field or name the file \
             'sector-<key>.wasm'."
                .to_owned(),
        );
    };
    // A `.cwasm` filename marks a precompiled (AOT) artifact; anything else is a
    // portable `.wasm` compiled on the node.
    let precompiled = wasm_filename
        .as_deref()
        .is_some_and(|f| f.ends_with(".cwasm"));

    // Install is blocking (wasm compile + disk IO); keep it off the async worker.
    match tokio::task::spawn_blocking(move || admin.install(&sector, wasm, sig, precompiled)).await
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

/// Derive a sector key from an uploaded filename: `sector-battery.wasm` → `battery`.
fn derive_sector(filename: &str) -> Option<String> {
    let stem = std::path::Path::new(filename).file_stem()?.to_str()?;
    let key = stem.trim_start_matches("sector-");
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
    use dpp_types::api_key::ApiKeyScope;

    fn ctx(scope: ApiKeyScope) -> AuthContext {
        AuthContext {
            user_id: "test".into(),
            scope,
            key_id: None,
        }
    }

    #[test]
    fn admin_scope_allowed() {
        assert!(require_admin(&ctx(ApiKeyScope::Admin)).is_none());
    }

    #[test]
    fn non_admin_blocked() {
        assert!(require_admin(&ctx(ApiKeyScope::Write)).is_some());
        assert!(require_admin(&ctx(ApiKeyScope::Read)).is_some());
    }

    #[test]
    fn derive_sector_strips_prefix_and_extension() {
        assert_eq!(
            derive_sector("sector-battery.wasm").as_deref(),
            Some("battery")
        );
        assert_eq!(derive_sector("textile.wasm").as_deref(), Some("textile"));
        assert_eq!(derive_sector("sector-.wasm"), None);
    }
}
