use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

use dpp_domain::domain::error::DppError;
use dpp_types::api_key::CreateApiKeyRequest;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, not_found_error, require_admin, validation_error};

/// Self-lockout guard: a key may not revoke *itself*. Revoking the very
/// credential used for this request would lock out the caller (and every client
/// sharing that key) from all authenticated routes. The caller must authenticate
/// with a *different* key — or local-admin Basic auth, whose `key_id` is `None`
/// and which is therefore always allowed (the lockout-recovery path). Returns a
/// `409 Conflict` response when the target is the authenticating key.
fn blocks_self_revoke(auth: &AuthContext, target: Uuid) -> Option<axum::response::Response> {
    if auth.key_id == Some(target) {
        Some(api_error(
            StatusCode::CONFLICT,
            "SELF_REVOKE",
            "Cannot revoke the API key you are currently authenticating with. \
             Authenticate with a different key (or admin credentials), then revoke this one.",
        ))
    } else {
        None
    }
}

/// `GET /api/v1/api-keys` — list active keys for this deployment.
pub async fn api_keys_list_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "API key management") {
        return resp;
    }
    match state.api_key_service.list().await {
        Ok(keys) => (StatusCode::OK, Json(keys)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/api-keys` — generate a new key and return its plaintext
/// secret ONCE. Subsequent listings only expose the prefix.
pub async fn api_keys_create_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "API key management") {
        return resp;
    }
    // Omitted scope defaults to Admin (backward compatible). Operators should
    // pass `"write"`/`"read"` for least-privilege integration keys.
    let scope = body.scope.unwrap_or_default();
    match state
        .api_key_service
        .create(&body.name, scope, body.expires_at)
        .await
    {
        Ok(key) => (StatusCode::CREATED, Json(key)).into_response(),
        Err(DppError::Validation(msg)) => validation_error(&msg.to_string()),
        Err(e) => internal_error(e),
    }
}

/// `DELETE /api/v1/api-keys/{id}` — soft-revoke a key. The row stays for
/// audit but `isActive` flips to false; subsequent auths with that key
/// fail and the dashboard stops listing it.
pub async fn api_keys_delete_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "API key management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid api-key id"),
    };
    if let Some(resp) = blocks_self_revoke(&auth, parsed) {
        return resp;
    }

    match state.api_key_service.revoke(parsed).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DppError::NotFound(_)) => not_found_error("API key not found"),
        Err(e) => internal_error(e),
    }
}

#[cfg(test)]
mod tests {
    //! Self-lockout guard: a key cannot revoke itself, but may revoke any other
    //! key, and admin Basic auth (no key_id) may revoke anything.
    use super::*;
    use dpp_types::api_key::ApiKeyScope;

    fn ctx_with_key(key_id: Option<Uuid>) -> AuthContext {
        AuthContext {
            user_id: "test".into(),
            scope: ApiKeyScope::Admin,
            key_id,
        }
    }

    #[test]
    fn revoking_own_key_blocked() {
        let id = Uuid::now_v7();
        let resp = blocks_self_revoke(&ctx_with_key(Some(id)), id).expect("self-revoke must block");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn revoking_other_key_allowed() {
        let mine = Uuid::now_v7();
        let other = Uuid::now_v7();
        assert!(blocks_self_revoke(&ctx_with_key(Some(mine)), other).is_none());
    }

    #[test]
    fn admin_basic_auth_may_revoke_any_key() {
        // key_id == None (admin Basic auth) is the recovery path — never blocked.
        let target = Uuid::now_v7();
        assert!(blocks_self_revoke(&ctx_with_key(None), target).is_none());
    }
}
