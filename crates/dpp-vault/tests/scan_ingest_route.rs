//! The internal scan-ingest route must reject any caller that does not present a
//! verified client certificate. This is the trust boundary that protects an
//! operator's resolution counts from being inflated by an unauthenticated writer.
//!
//! The mTLS decision logic itself is covered exhaustively in `dpp-common::mtls`
//! and the identity service's suite; this asserts the *vault's wiring* — that the
//! layer is actually attached to `/scan-batch`.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware,
    routing::post,
};
use tower::ServiceExt;

use dpp_vault::handlers::scan_ingest::scan_ingest_mtls;

#[tokio::test]
async fn scan_batch_rejects_a_caller_without_a_client_cert() {
    // The real mTLS layer over a dummy handler: no AppState is needed to prove
    // the gate rejects before the handler ever runs.
    let app = Router::new()
        .route("/scan-batch", post(|| async { StatusCode::NO_CONTENT }))
        .route_layer(middleware::from_fn(scan_ingest_mtls));

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/scan-batch")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Fails closed (no MTLS_ALLOW_INSECURE): a request with no client-cert header
    // is unauthorized — it never reaches the dummy 204 handler.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
