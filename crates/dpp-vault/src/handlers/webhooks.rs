//! HTTP handlers for webhook subscription management.
//!
//! Webhook configuration is an administrative action — a subscription streams
//! this operator's events to an external URL, so (like API-key management) it
//! requires an admin-scoped credential; a leaked least-privilege key must not be
//! able to point events at an attacker-controlled receiver.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use uuid::Uuid;

use dpp_domain::domain::error::DppError;
use dpp_types::{NewWebhookSubscription, WebhookSubscription};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, require_admin};

/// Create response — the redacted subscription plus the signing secret, shown once.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedWebhookResponse {
    #[serde(flatten)]
    subscription: WebhookSubscription,
    /// Signing secret. Store it now — it is never shown again.
    secret: String,
}

/// `GET /api/v1/webhooks` — list subscriptions (secrets redacted).
pub async fn webhooks_list_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Webhook management") {
        return resp;
    }
    match state.webhook_service.list().await {
        Ok(subs) => (StatusCode::OK, Json(subs)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/webhooks` — create a subscription; returns the secret once.
pub async fn webhooks_create_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<NewWebhookSubscription>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Webhook management") {
        return resp;
    }
    match state.webhook_service.create(body).await {
        Ok(created) => (
            StatusCode::CREATED,
            Json(CreatedWebhookResponse {
                subscription: created.subscription,
                secret: created.secret,
            }),
        )
            .into_response(),
        Err(DppError::Validation(msg)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &msg.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}

/// `DELETE /api/v1/webhooks/{id}` — soft-remove (`active = false`). In-flight
/// deliveries already queued still drain; no new events are enqueued.
pub async fn webhooks_delete_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Webhook management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid webhook id"),
    };
    match state.webhook_service.deactivate(parsed).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DppError::NotFound(_)) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Webhook subscription not found",
        ),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/webhooks/{id}/test` — enqueue a synthetic test delivery.
pub async fn webhooks_test_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Webhook management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid webhook id"),
    };
    match state.webhook_service.test(parsed).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(DppError::NotFound(_)) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Webhook subscription not found",
        ),
        Err(e) => internal_error(e),
    }
}
