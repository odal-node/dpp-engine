//! Axum router for the identity service — wires public and mTLS-gated internal routes.

use axum::{
    Router, middleware,
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
    handlers::{
        did_document::did_document_handler,
        health::{health_handler, ready_handler},
        rotate_key::rotate_key_handler,
        sign::sign_handler,
        verify::verify_handler,
    },
    middleware::mtls::mtls_middleware,
    state::AppState,
};

/// Build the full Axum router: public routes merged with mTLS-gated internal routes.
///
/// Standalone deployment only — the fused `dpp-node` uses [`build_public`] instead
/// and calls the signer in-process, so the `/internal/*` surface is never
/// network-reachable in the fused binary (ATK-1 regression test).
pub fn build(state: AppState) -> Router {
    // Internal endpoints are protected by the mTLS middleware.
    // Only requests from `CN=odal-vault` are accepted when MTLS_ENFORCE=true.
    let internal = Router::new()
        .route("/internal/sign", post(sign_handler))
        .route("/internal/verify", post(verify_handler))
        .route("/internal/keys/rotate", post(rotate_key_handler))
        .route_layer(middleware::from_fn(mtls_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn(inject_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        .with_state(state.clone());

    build_public(state).merge(internal)
}

/// Public-only router: health, readiness and the did:web document. Contains NO
/// signing/rotation endpoints. The fused `dpp-node` mounts this so the internal
/// signing surface is never reachable over the network — signing is performed
/// in-process via `LocalIdentityService`.
pub fn build_public(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        // Public DID document endpoint — no auth required
        .route("/.well-known/did.json", get(did_document_handler))
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
    use serial_test::serial;
    use tower::ServiceExt;

    /// A throwaway keystore in a directory that is removed when the returned
    /// `TempDir` drops.
    ///
    /// The `TempDir` comes back with it deliberately: it owns the directory the
    /// store writes into, so a helper returning only the `KeyStore` would have
    /// the file vanish underneath it. `tempfile` also creates the directory with
    /// restrictive permissions, which `env::temp_dir()` does not — this holds
    /// Ed25519 private keys, throwaway or not.
    fn temp_store() -> (dpp_crypto::keystore::KeyStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = dpp_crypto::keystore::KeyStore::open(dir.path().join("keystore.json"), "test")
            .expect("open store");
        (store, dir)
    }

    /// No X-Client-Cert-Subject header → 401 Unauthorized (enforcement on by default).
    #[tokio::test]
    #[serial]
    async fn mtls_rejects_internal_request_without_cert() {
        let (store, _dir) = temp_store();
        let state = crate::state::AppState {
            store: Arc::new(store),
            did_web_base_url: "http://localhost".into(),
        };
        let app = super::build(state);

        let req = Request::builder()
            .method("POST")
            .uri("/internal/sign")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"operator_id":"t","passport_id":"p","payload":"dA=="}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Regression (red-team ATK-1): the public router mounted by the fused node
    /// exposes NO internal signing/rotation surface, on any port. Signing is
    /// done in-process; these endpoints must simply not exist here.
    #[tokio::test]
    async fn public_router_has_no_internal_endpoints() {
        let (store, _dir) = temp_store();
        store.generate_key("root").expect("provision root key");
        let state = crate::state::AppState {
            store: Arc::new(store),
            did_web_base_url: "http://localhost".into(),
        };
        let app = super::build_public(state);

        for path in [
            "/internal/sign",
            "/internal/verify",
            "/internal/keys/rotate",
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{path} must not be reachable on the public router"
            );
        }

        // The public DID document IS still served.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/did.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Wrong CN in client certificate → 403 Forbidden (enforcement on by default).
    /// Sets the proxy-binding secret and its header first — without it the
    /// request is rejected at the (now fail-closed) proxy-binding gate before
    /// the CN is ever checked, which is a different case ([`dpp_common::mtls`]
    /// covers that one).
    #[tokio::test]
    #[serial]
    async fn mtls_rejects_wrong_cn() {
        unsafe { std::env::set_var("MTLS_PROXY_SHARED_SECRET", "s3cr3t") };
        let (store, _dir) = temp_store();
        let state = crate::state::AppState {
            store: Arc::new(store),
            did_web_base_url: "http://localhost".into(),
        };
        let app = super::build(state);

        let req = Request::builder()
            .method("POST")
            .uri("/internal/sign")
            .header("content-type", "application/json")
            .header(dpp_common::mtls::PROXY_AUTH_HEADER, "s3cr3t")
            .header(
                crate::middleware::mtls::CLIENT_CERT_SUBJECT_HEADER,
                "CN=some-other-service,O=Odal",
            )
            .body(Body::from(
                r#"{"operator_id":"t","passport_id":"p","payload":"dA=="}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        unsafe { std::env::remove_var("MTLS_PROXY_SHARED_SECRET") };
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
