//! Axum router for the integrator service — wires routes, body limits, and telemetry layers.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use tower_http::{
    request_id::{PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use dpp_common::{
    metrics::http_metrics_middleware,
    request_id::{UuidRequestId, inject_request_id},
};

use crate::{
    handlers::{health, import, job_status, templates},
    state::AppState,
};

/// Hard cap on the size of an import upload body (5 MiB). Bounds the work an
/// (unauthenticated) caller can force the spreadsheet/CSV parser to do.
const IMPORT_BODY_LIMIT: usize = 5 * 1024 * 1024;

/// Build the Axum router with all integrator routes and telemetry layers.
///
/// Import uploads are subject to a 5 MiB body cap (`DefaultBodyLimit`) to bound
/// the work an authenticated caller can force the parser to do. Auth is enforced
/// inside each handler by forwarding the `Bearer` token to the vault.
pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/api/v1/templates/{sector}", get(templates::get_template))
        .route(
            "/api/v1/import/{sector}",
            post(import::import_file).layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT)),
        )
        .route("/api/v1/imports/{job_id}", get(job_status::get_job_status))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn(inject_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::{
        infra::{job_store::InMemoryJobStore, vault_client::VaultHttpClient},
        state::AppState,
    };

    /// Regression (red-team ATK-7): the import-job status endpoint must reject
    /// unauthenticated requests, so job status / failure details are not exposed.
    #[tokio::test]
    async fn job_status_requires_auth() {
        let state = AppState {
            vault_client: Arc::new(VaultHttpClient::new("http://127.0.0.1:1")),
            job_store: Arc::new(InMemoryJobStore::new()),
            batch_concurrency: 1,
        };
        let app = super::build(state);

        let req = Request::builder()
            .uri("/api/v1/imports/00000000-0000-0000-0000-000000000000")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    fn test_state() -> AppState {
        AppState {
            vault_client: Arc::new(VaultHttpClient::new("http://127.0.0.1:1")),
            job_store: Arc::new(InMemoryJobStore::new()),
            batch_concurrency: 1,
        }
    }

    /// Regression (red-team RT2-1): an import POST with no Bearer token must be
    /// rejected with 401 *before* the file is parsed, so anonymous callers can't
    /// drive the allocation-heavy parser.
    #[tokio::test]
    async fn import_requires_bearer_token() {
        let app = super::build(test_state());

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/import/battery")
            .header("content-type", "multipart/form-data; boundary=x")
            .body(Body::from("--x--\r\n"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Regression (red-team RT2-1): an oversized upload must be rejected, never
    /// parsed to a `200`. Two layered controls enforce this: the auth gate (the
    /// token is validated against the vault before the body is read) and the
    /// `DefaultBodyLimit` cap. In this unit context there is no live vault, so the
    /// request is rejected at the auth gate; the body-limit cap is the runtime
    /// backstop for an *authenticated* hostile upload (exercised end-to-end in the
    /// node integration suite). Either way the parser is never reached.
    #[tokio::test]
    async fn import_oversized_upload_rejected() {
        let app = super::build(test_state());

        let oversized = vec![b'a'; super::IMPORT_BODY_LIMIT + 1];
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/import/battery")
            .header("authorization", "Bearer odal_sk_test")
            .header("content-type", "multipart/form-data; boundary=x")
            .body(Body::from(oversized))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "oversized upload must be rejected, got {}",
            resp.status()
        );
    }
}
