//! `GET /api/v1/whoami` — what the presented credential actually is.

use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use dpp_types::api_key::ApiKeyScope;
use serde::Serialize;

use crate::middleware::auth::AuthContext;

/// What the presented credential is.
///
/// A named type rather than a `json!` literal so the OpenAPI contract test can
/// check `components/schemas/access/WhoamiResponse` against it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoamiResponse {
    /// The caller's own identity, as authenticated.
    pub user_id: String,
    /// What this credential is allowed to do.
    pub scope: ApiKeyScope,
    /// The key's row id — never the token. Absent for local-admin Basic auth,
    /// which has no key row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<uuid::Uuid>,
}

/// `GET /api/v1/whoami` — echo the caller's own identity and scope.
///
/// A client cannot otherwise discover what its credential is allowed to do: a
/// `read` key learns it is read-only by having a write rejected, which is a
/// poor way to find out and impossible to check ahead of time. This lets a
/// dashboard grey out what the key cannot reach, and lets an SDK fail early
/// with a useful message instead of surfacing a 403 from deep in a call.
///
/// Reports only what the caller already presented. It reveals nothing about
/// any other key, and the key's secret is never stored in a recoverable form
/// anyway — `keyId` is the row id, not the token.
pub async fn whoami_handler(Extension(auth): Extension<AuthContext>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(WhoamiResponse {
            user_id: auth.user_id,
            scope: auth.scope,
            key_id: auth.key_id,
        }),
    )
}

#[cfg(test)]
mod tests {
    use axum::{extract::Extension, response::IntoResponse};
    use dpp_types::api_key::ApiKeyScope;

    use super::*;

    async fn body_of(auth: AuthContext) -> serde_json::Value {
        let response = whoami_handler(Extension(auth)).await.into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn reports_the_presented_identity_and_scope() {
        let key_id = uuid::Uuid::now_v7();
        let body = body_of(AuthContext {
            user_id: "svc-dashboard".into(),
            scope: ApiKeyScope::Read,
            key_id: Some(key_id),
        })
        .await;

        assert_eq!(body["userId"], "svc-dashboard");
        assert_eq!(body["scope"], "read");
        assert_eq!(body["keyId"], key_id.to_string());
    }

    /// Local-admin Basic auth has no key row, so `keyId` must be absent rather
    /// than a placeholder a client could mistake for a real id.
    #[tokio::test]
    async fn omits_key_id_for_local_admin() {
        let body = body_of(AuthContext {
            user_id: "admin".into(),
            scope: ApiKeyScope::Admin,
            key_id: None,
        })
        .await;

        assert_eq!(body["userId"], "admin");
        assert!(body["keyId"].is_null(), "keyId must not be invented");
    }
}
