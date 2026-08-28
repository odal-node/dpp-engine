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
    handlers::{health, import, job_status, product_groups, schemas, templates},
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
        .route(
            "/api/v1/templates/{productGroup}",
            get(templates::get_template),
        )
        .route(
            "/api/v1/product-groups",
            get(product_groups::list_product_groups),
        )
        .route(
            "/api/v1/product-groups/{productGroup}",
            get(product_groups::get_product_group),
        )
        .route("/api/v1/schemas", get(schemas::list_schemas))
        .route(
            "/api/v1/schemas/{productGroup}",
            get(schemas::get_current_schema),
        )
        .route(
            "/api/v1/schemas/{productGroup}/{version}",
            get(schemas::get_pinned_schema),
        )
        .route(
            "/api/v1/import/{productGroup}",
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

    /// The three schema routes serve, and what they serve carries no prose.
    ///
    /// End-to-end through the router rather than against `strip_descriptions`
    /// directly: the unit test proves the function strips, this proves the route
    /// actually calls it before the bytes leave.
    #[tokio::test]
    async fn schema_routes_serve_without_descriptions() {
        for uri in [
            "/api/v1/schemas",
            "/api/v1/schemas/battery",
            "/api/v1/schemas/battery/2.6.0",
            // A `v` prefix is accepted, since that is how the versions are
            // spelled on disk and in the fixture directories.
            "/api/v1/schemas/battery/v2.6.0",
        ] {
            let app = super::build(test_state());
            let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri} must serve");

            let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
                .await
                .unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !text.contains("\"description\""),
                "{uri} leaked an unaudited regulatory description"
            );
        }
    }

    async fn get_json(uri: &str) -> (StatusCode, serde_json::Value) {
        let app = super::build(test_state());
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// The obligation endpoint covers every product group the catalog models —
    /// discovered from the catalog rather than compared against a list here, so
    /// adding a product group cannot leave it silently unserved.
    #[tokio::test]
    async fn every_catalogued_product_group_is_served() {
        let (status, body) = get_json("/api/v1/product-groups").await;
        assert_eq!(status, StatusCode::OK);

        let served: std::collections::BTreeSet<String> = body["productGroups"]
            .as_array()
            .expect("productGroups is an array")
            .iter()
            .map(|e| e["productGroup"].as_str().unwrap().to_owned())
            .collect();

        let catalogued: std::collections::BTreeSet<String> =
            dpp_domain::catalog::ProductGroupCatalog::new()
                .keys()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect();

        assert_eq!(served, catalogued);
    }

    /// **The rule this endpoint exists to keep.** Most of the catalog is undated,
    /// and of the dates that exist some trace to an adopted text and some are a
    /// reading. A date served without its basis turns a qualified reading into an
    /// unqualified claim, which is the failure the schema endpoint strips its
    /// prose to avoid.
    #[tokio::test]
    async fn no_date_is_ever_served_without_its_basis() {
        let (_, body) = get_json("/api/v1/product-groups").await;
        let mut checked = 0usize;

        for entry in body["productGroups"].as_array().unwrap() {
            let key = entry["productGroup"].as_str().unwrap();

            if let Some(from) = entry["passport"]["from"].as_object() {
                assert!(
                    from.get("date").is_some_and(|d| d.is_string()),
                    "{key}: an obligation date must be a string"
                );
                assert!(
                    from.get("basis").is_some_and(|b| b.is_string()),
                    "{key}: served an obligation date with no basis"
                );
                checked += 1;
            }
            if let Some(retention) = entry["retention"].as_object() {
                assert!(
                    retention.get("basis").is_some_and(|b| b.is_string()),
                    "{key}: served a retention period with no basis"
                );
                checked += 1;
            }
        }

        // Most of the catalog is undated, so this loop could inspect nothing and
        // still pass. A test that cannot fail is not enforcing the rule it was
        // written for.
        assert!(
            checked > 0,
            "no dated or retained product group was inspected — this assertion \
             passed vacuously and is enforcing nothing"
        );
    }

    /// A worked case from the catalog, so the wiring is checked against a real
    /// answer rather than only against its shape. The Toy Safety Regulation is
    /// adopted with a firm passport date, and its implementing acts are not
    /// published — so the duty is `required` and nothing is determinable yet.
    /// Those two being different is the reason `determinable` is reported at all.
    #[tokio::test]
    async fn an_adopted_act_can_require_a_passport_that_is_not_yet_determinable() {
        let (status, body) = get_json("/api/v1/product-groups/toy").await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(body["passport"]["required"], serde_json::json!(true));
        assert_eq!(body["passport"]["from"]["date"], "2030-08-01");
        assert_eq!(body["passport"]["from"]["basis"], "sourced");
        assert_eq!(
            body["determinable"],
            serde_json::json!(false),
            "the implementing acts are unpublished, so nothing is bindingly determinable"
        );
    }

    /// An unmodelled key is a 404 rather than an entry with an empty obligation,
    /// which would read as "no passport required" — the opposite of "this node
    /// does not know".
    #[tokio::test]
    async fn an_unmodelled_product_group_is_not_an_empty_obligation() {
        let (status, _) = get_json("/api/v1/product-groups/nosuchgroup").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// An unknown product group and an unknown version are told apart, and both name
    /// what is available rather than only refusing.
    #[tokio::test]
    async fn schema_routes_refuse_helpfully() {
        for (uri, status) in [
            ("/api/v1/schemas/nosuchproduct_group", StatusCode::NOT_FOUND),
            ("/api/v1/schemas/battery/9.9.9", StatusCode::NOT_FOUND),
            (
                "/api/v1/schemas/battery/not-semver",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let app = super::build(test_state());
            let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), status, "{uri}");
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
