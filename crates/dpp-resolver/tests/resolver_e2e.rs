//! End-to-end tests for the DPP resolver.
//!
//! Covers functionality not exercised by the inline unit tests in `lib.rs`:
//! - QR PNG generation and cacheability
//! - Content negotiation edge cases (no Accept, wildcard Accept)
//! - HTML rendering with battery and textile product group data
//! - Health and readiness probes
//!
//! JWS verification itself (valid/tampered/missing signatures, DID
//! reachability) is covered in `src/jws_verification_tests.rs`, driven
//! through a real `operator_did_url`.
//!
//! All tests use mock vault servers (no Docker required).
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-resolver -- --nocapture
//! ```

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde_json::json;
use tower::ServiceExt;

use dpp_resolver::{infra::cache::Cache, router, state::AppState};

fn test_state(vault_base_url: String) -> AppState {
    AppState {
        vault_base_url,
        // Signature verification disabled for these resolution/caching e2e tests.
        operator_did_url: String::new(),
        resolver_base_url: "https://id.odal-node.io".into(),
        cache: Cache::new_noop(),
        http: reqwest::Client::new(),
        scan_counter: None,
    }
}

async fn start_mock_vault(mock_router: Router) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock vault");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock_router)
            .await
            .expect("mock vault serve");
    });
    port
}

fn sample_passport() -> serde_json::Value {
    json!({
        "id": "00000000-0000-4000-9000-000000000001",
        "productName": "E2E Test Widget",
        "status": "active",
        "manufacturer": {"name": "E2E Corp", "address": "Berlin, DE"},
        "materials": [{"name": "Copper", "weightKg": 0.3}],
        "schemaVersion": "1.0.0"
    })
}

/// `sample_passport()` plus product group data carrying a GTIN, and the carrier
/// publish signs beside it — what a real carrier-bearing product passport looks
/// like, for the QR tests. The QR route prints the signed `qrCodeUrl`, so a
/// passport without one has no carrier to print.
fn sample_passport_with_gtin() -> serde_json::Value {
    let mut p = sample_passport();
    p["productGroupData"] = json!({
        "productGroup": "electronics",
        "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" }
    });
    p["qrCodeUrl"] = json!("https://id.odal-node.io/01/09506000134352/21/40009000000000000001");
    p
}

fn sample_battery_passport() -> serde_json::Value {
    json!({
        "id": "00000000-0000-4000-9000-000000000002",
        "productName": "EcoCell 48V",
        "status": "active",
        "manufacturer": {"name": "Example Batteries GmbH", "address": "Munich, DE"},
        "productGroupData": {
            "productGroup": "battery",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 72.5,
            "recycledContentCobaltPct": 12.0,
            "recycledContentLithiumPct": 8.0
        }
    })
}

fn sample_textile_passport() -> serde_json::Value {
    json!({
        "id": "00000000-0000-4000-9000-000000000003",
        "productName": "Eco Jacket",
        "status": "active",
        "manufacturer": {"name": "FabriqGreen", "address": "Milan, IT"},
        "productGroupData": {
            "productGroup": "textile",
            "countryOfOrigin": "IT",
            "careInstructions": "Machine wash cold",
            "chemicalComplianceStandard": "OEKO-TEX 100",
            "recycledContentPct": 40.0,
            "fibreComposition": [
                {"fibre": "Organic Cotton", "pct": 60.0},
                {"fibre": "Recycled Polyester", "pct": 40.0}
            ]
        }
    })
}

// ---------------------------------------------------------------------------
// Health probes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_ok() {
    let vault = Router::new();
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ready_returns_ok() {
    let vault = Router::new();
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/ready")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// QR code generation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn qr_endpoint_returns_png() {
    let passport = sample_passport_with_gtin();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000001/qr")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "image/png", "QR endpoint must return image/png");

    let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    // PNG magic bytes
    assert!(
        body.starts_with(&[0x89, b'P', b'N', b'G']),
        "response body must be valid PNG"
    );
    assert!(body.len() > 100, "PNG must not be empty");
}

/// A passport whose product group data carries no GTIN (e.g. an untyped record,
/// or here simply no `productGroupData` at all) has no valid GS1 Digital Link
/// carrier to print — the endpoint must fail closed, not encode a broken or
/// misleading code.
#[tokio::test]
async fn qr_endpoint_returns_422_without_a_gtin() {
    let passport = sample_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000001/qr")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Content negotiation edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_accept_header_defaults_to_json_ld() {
    let passport = sample_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    // No Accept header → should default to JSON-LD
    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000001")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/ld+json"),
        "no Accept should default to JSON-LD, got: {ct}"
    );
}

#[tokio::test]
async fn wildcard_accept_returns_json_ld() {
    let passport = sample_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000001")
        .header("accept", "*/*")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/ld+json"),
        "*/* should get JSON-LD, got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// HTML rendering with product group data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn html_includes_battery_product_group_data() {
    let passport = sample_battery_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000002")
        .header("accept", "text/html")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("EcoCell 48V"),
        "HTML must contain product name"
    );
    assert!(
        html.contains("Battery Information"),
        "HTML must contain battery section header"
    );
    assert!(html.contains("LFP"), "HTML must contain battery chemistry");
    assert!(html.contains("3000"), "HTML must contain lifetime cycles");
}

#[tokio::test]
async fn html_includes_textile_fibre_bar() {
    let passport = sample_textile_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000003")
        .header("accept", "text/html")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Textile Information"),
        "HTML must contain textile section"
    );
    assert!(
        html.contains("Organic Cotton"),
        "HTML must contain fibre name"
    );
    assert!(
        html.contains("fibre-bar"),
        "HTML must contain fibre composition bar"
    );
}

// ---------------------------------------------------------------------------
// JSON-LD includes @context
// ---------------------------------------------------------------------------

#[tokio::test]
async fn json_ld_response_includes_context() {
    let passport = sample_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000001")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
    assert!(
        doc.get("@context").is_some(),
        "JSON-LD response must include @context"
    );
    assert_eq!(
        doc["productName"], "E2E Test Widget",
        "product name must be preserved"
    );
}

// ---------------------------------------------------------------------------
// Vault unreachable returns 502
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vault_unreachable_returns_502() {
    // Point at a port with nothing listening
    let app = router::build(test_state("http://127.0.0.1:1".into()));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000005")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "unreachable vault should return 502"
    );
}

// ---------------------------------------------------------------------------
// Metrics — the resolver's signature-verification counter is emitted (RT2-6)
// ---------------------------------------------------------------------------

fn prometheus_handle() -> &'static PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("failed to install Prometheus recorder")
    })
}

/// A resolve must record `jws_verify_total` so the public-facing tamper signal is
/// collectable. Guards against the emission being removed/renamed (RT2-6). The
/// recorder is installed in-test, then a resolve is driven and the rendered
/// output is asserted to contain the counter.
#[tokio::test]
async fn resolve_records_jws_verify_total() {
    let handle = prometheus_handle();

    let passport = sample_passport();
    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000001")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let output = handle.render();
    assert!(
        output.contains("jws_verify_total"),
        "jws_verify_total not found in Prometheus output:\n{output}"
    );
}

// ── GS1 Digital Link: multi-AI carrier shapes ───────────────────────────────

/// Every AI combination a printed carrier can carry must reach a route. The
/// publisher emits `/01/{gtin}`, `/01/{gtin}/10/{batch}` or
/// `/01/{gtin}/21/{serial}` by the passport's level, and labels printed before
/// that carry `/10/{batch}/21/{serial}`, so a GTIN-only route alone means this
/// node's own printed QR codes 404. Which passport each reaches is the vault's
/// answer — see `the_label_s_qualifiers_reach_the_vault`.
#[tokio::test]
async fn gs1_digital_link_resolves_every_carrier_ai_shape() {
    let gtin = "09506000134352";
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async { axum::Json(sample_passport_with_gtin()) }),
    );
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    for uri in [
        format!("/01/{gtin}"),
        format!("/01/{gtin}/21/A1B2C3D4E5F6G7H8J9K0"),
        format!("/01/{gtin}/10/LOT-2026-07"),
        format!("/01/{gtin}/10/LOT-2026-07/21/A1B2C3D4E5F6G7H8J9K0"),
    ] {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "no route matched {uri} — a printed carrier of this shape would 404"
        );
        // The default (no linkType) outcome is a redirect to the product page.
        assert!(
            resp.status().is_redirection(),
            "{uri} resolved to {} instead of a redirect",
            resp.status()
        );
    }
}

/// The label's AI 10 and AI 21 travel to the vault, which is what resolves the
/// passport a label was printed for. Dropping them looked the GTIN up alone,
/// and one GTIN has a passport per batch or per unit once a product is recorded
/// at that level.
#[tokio::test]
async fn the_label_s_qualifiers_reach_the_vault() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::extract::Query;

    let gtin = "09506000134352";
    let seen: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::default();
    let vault = {
        let seen = Arc::clone(&seen);
        Router::new().route(
            "/public/dpp/by-gtin/{gtin}",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock().unwrap().push(query);
                    axum::Json(sample_passport_with_gtin())
                }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    let cases: [(String, &[(&str, &str)]); 4] = [
        (format!("/01/{gtin}"), &[]),
        (
            format!("/01/{gtin}/10/LOT-2026-07"),
            &[("batch", "LOT-2026-07")],
        ),
        (format!("/01/{gtin}/21/SN%2F1"), &[("serial", "SN/1")]),
        (
            format!("/01/{gtin}/10/LOT-2026-07/21/SN-1"),
            &[("batch", "LOT-2026-07"), ("serial", "SN-1")],
        ),
    ];
    for (uri, expected) in cases {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(resp.status().is_redirection(), "{uri}: {}", resp.status());

        let query = seen.lock().unwrap().pop().expect("the vault was asked");
        let expected: HashMap<String, String> = expected
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(query, expected, "{uri} forwarded the wrong qualifiers");
    }
}

/// A consumer product variant (AI 22) or a third-party extension (AI 235) is a
/// valid part of a GS1 Digital Link, and a label printed elsewhere may carry
/// either. This node holds no record at either level, so the qualifier takes no
/// part in the lookup and the label resolves through the levels it does model:
/// the vault is asked exactly what it would be asked without it.
#[tokio::test]
async fn a_variant_or_extension_qualifier_takes_no_part_in_the_lookup() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::extract::Query;

    let gtin = "09506000134352";
    let seen: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::default();
    let vault = {
        let seen = Arc::clone(&seen);
        Router::new().route(
            "/public/dpp/by-gtin/{gtin}",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock().unwrap().push(query);
                    axum::Json(sample_passport_with_gtin())
                }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    let cases: [(String, &[(&str, &str)]); 5] = [
        (format!("/01/{gtin}/22/2A"), &[]),
        (format!("/01/{gtin}/22/2A/21/SN-1"), &[("serial", "SN-1")]),
        (
            format!("/01/{gtin}/22/2A/10/LOT-2026-07"),
            &[("batch", "LOT-2026-07")],
        ),
        (
            format!("/01/{gtin}/22/2A/10/LOT-2026-07/21/SN%2F1"),
            &[("batch", "LOT-2026-07"), ("serial", "SN/1")],
        ),
        (format!("/01/{gtin}/235/TPX-9"), &[]),
    ];
    for (uri, expected) in cases {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(resp.status().is_redirection(), "{uri}: {}", resp.status());

        let query = seen.lock().unwrap().pop().expect("the vault was asked");
        let expected: HashMap<String, String> = expected
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(query, expected, "{uri} forwarded the wrong qualifiers");
    }
}

/// A path under `/01/` that is not a valid GS1 Digital Link is a bad request,
/// not a missing product. The qualifiers come in one order, each at most once,
/// and a third-party extension stands alone; anything else fails the resolver
/// standard's validity tests, which it answers `400` (2.4.1). It is not looked
/// up, so the vault must never be asked.
#[tokio::test]
async fn a_path_under_01_that_is_not_a_digital_link_is_a_bad_request() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let gtin = "09506000134352";
    let asked = Arc::new(AtomicUsize::new(0));
    let vault = {
        let asked = Arc::clone(&asked);
        Router::new().route(
            "/public/dpp/by-gtin/{gtin}",
            get(move || {
                let asked = Arc::clone(&asked);
                async move {
                    asked.fetch_add(1, Ordering::SeqCst);
                    axum::Json(sample_passport_with_gtin())
                }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    for uri in [
        // Out of order.
        format!("/01/{gtin}/21/SN-1/10/LOT-1"),
        format!("/01/{gtin}/21/SN-1/22/2A"),
        format!("/01/{gtin}/10/LOT-1/22/2A"),
        // Repeated.
        format!("/01/{gtin}/21/SN-1/21/SN-2"),
        // A third-party extension stands alone.
        format!("/01/{gtin}/235/TPX-9/21/SN-1"),
        format!("/01/{gtin}/22/2A/235/TPX-9"),
        // Not a qualifier of a GTIN, or a qualifier with no value.
        format!("/01/{gtin}/99/x"),
        format!("/01/{gtin}/21/"),
    ] {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem json");
        assert_eq!(
            problem["detail"], "The path is not a valid GS1 Digital Link.",
            "{uri}: {problem}"
        );
    }
    assert_eq!(asked.load(Ordering::SeqCst), 0, "nothing was looked up");

    // The rule is about `/01/` only: a path no route serves elsewhere is still
    // the router's own `404`.
    let app = router::build(test_state(base.clone()));
    let req = Request::builder()
        .uri("/not-a-route")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // And it is about paths no route serves. A wrong method on a mounted route is
    // the `405` it always was, not a fallback answer.
    let app = router::build(test_state(base));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/01/{gtin}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── GS1 Digital Link: signature verification ────────────────────────────────

/// GTIN resolution is a second way to reach the same passport data as the
/// id-based routes, so it must verify the public JWS against the operator DID
/// exactly like they do — not a second, unverified path.
#[tokio::test]
async fn gtin_resolution_verifies_a_valid_signature() {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::generate(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let pub_key_b64 = b64.encode(signing_key.verifying_key().as_bytes());

    let gtin = "09506000134352";
    let passport_id = "00000000-0000-4000-9000-0000000000aa";
    let public_view = json!({ "id": passport_id, "productName": "Signed GTIN Widget" });
    let header = r#"{"alg":"EdDSA","kid":"did:web:valid.example#key-1"}"#;
    let header_b64 = b64.encode(header);
    let payload_b64 = b64.encode(serde_json::to_vec(&public_view).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = b64.encode(sig.to_bytes());
    let valid_jws = format!("{signing_input}.{sig_b64}");

    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:valid.example",
        "verificationMethod": [{
            "id": "did:web:valid.example#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:web:valid.example",
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": pub_key_b64}
        }],
        "assertionMethod": ["did:web:valid.example#key-1"]
    });
    let did_router = {
        let d = did_doc.clone();
        Router::new().route(
            "/.well-known/did.json",
            get(move || {
                let doc = d.clone();
                async move { axum::Json(doc) }
            }),
        )
    };
    let did_port = start_mock_vault(did_router).await;
    let did_url = format!("http://127.0.0.1:{did_port}/.well-known/did.json");

    let passport = json!({
        "id": passport_id,
        "productName": "Signed GTIN Widget",
        "productGroupData": { "productGroup": "electronics", "productIdentifier": { "scheme": "gs1", "gtin": gtin } },
        "publicJwsSignature": valid_jws
    });
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(move || {
            let p = passport.clone();
            async move { axum::Json(p) }
        }),
    );
    let vault_port = start_mock_vault(vault).await;

    let mut state = test_state(format!("http://127.0.0.1:{vault_port}"));
    state.operator_did_url = did_url;
    let app = router::build(state);

    let req = Request::builder()
        .uri(format!("/01/{gtin}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_redirection(),
        "a validly signed passport should resolve, got {}",
        resp.status()
    );
}

/// A passport with no public signature must not resolve by GTIN — the same
/// fail-closed rule the id-based routes already enforce.
#[tokio::test]
async fn gtin_resolution_rejects_a_missing_signature() {
    let gtin = "09506000134352";
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async { axum::Json(sample_passport_with_gtin()) }),
    );
    let vault_port = start_mock_vault(vault).await;

    // A non-empty operator_did_url enables verification; it need not even be
    // reachable, since a passport with no publicJwsSignature is rejected
    // before the DID document is ever fetched.
    let mut state = test_state(format!("http://127.0.0.1:{vault_port}"));
    state.operator_did_url = "http://127.0.0.1:1/.well-known/did.json".into();
    let app = router::build(state);

    let req = Request::builder()
        .uri(format!("/01/{gtin}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "an unsigned passport must not resolve by GTIN"
    );
}

// ---------------------------------------------------------------------------
// Scan telemetry — counting model (terminal views only; QR renders separate)
// ---------------------------------------------------------------------------

/// The whole counting model in one test: a GS1 carrier scan hits `/01/{gtin}`
/// (a redirect, not counted) then the terminal `/dpp/{id}` view (counted once),
/// so one physical scan is one scan — never ×2. The QR-image endpoint is a
/// render, tracked in its own bucket and never folded into scans.
#[tokio::test]
async fn scan_telemetry_counts_terminal_views_and_qr_separately() {
    use std::sync::Arc;

    use dpp_common::scan::ScanVariant;
    use dpp_resolver::infra::scan_counter::ScanCounter;

    let id = "00000000-0000-4000-9000-000000000001";
    let passport = sample_passport_with_gtin();
    let vault = {
        let by_id = passport.clone();
        let by_gtin = passport.clone();
        Router::new()
            .route(
                "/public/dpp/{id}",
                get(move || {
                    let p = by_id.clone();
                    async move { axum::Json(p) }
                }),
            )
            .route(
                "/public/dpp/by-gtin/{gtin}",
                get(move || {
                    let p = by_gtin.clone();
                    async move { axum::Json(p) }
                }),
            )
    };
    let port = start_mock_vault(vault).await;

    let counter = Arc::new(ScanCounter::default());
    // Verification stays disabled (empty operator DID) so the redirect path
    // resolves; the counting logic is what's under test here.
    let mut state = test_state(format!("http://127.0.0.1:{port}"));
    state.scan_counter = Some(counter.clone());
    let app = router::build(state);

    // 1) The GS1 redirect must not count as a scan.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/01/09506000134352")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        counter.drain().is_empty(),
        "the /01 redirect must not be counted as a scan"
    );

    // 2) The terminal JSON view it points to counts exactly once.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/dpp/{id}"))
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3) The QR image is a render, not a scan.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/dpp/{id}/qr"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let batch = counter.drain();
    assert_eq!(batch.scans.len(), 1, "exactly one scan aggregate");
    assert_eq!(batch.scans[0].variant, ScanVariant::Json);
    assert_eq!(batch.scans[0].count, 1);
    assert_eq!(batch.scans[0].dpp_id, id);
    assert_eq!(batch.qr_renders.len(), 1, "qr render tracked separately");
    assert_eq!(batch.qr_renders[0].count, 1);
    assert_eq!(batch.qr_renders[0].dpp_id, id);
}

/// A restricted product-group field must not reach the public JSON view.
///
/// The resolver filters a passport in two passes: the envelope with the
/// passport-level policy, then `productGroupData` — removed from the envelope and
/// handed on as its own root document — with the product group's policy. The
/// second pass has to say that its root is *already inside* the product group,
/// because a payload filtered as an envelope has none of that product group's
/// classes applied and every restricted field in it is served.
///
/// Nothing caught that before this test: the wrong scope compiles, returns 200,
/// and produces a body that looks right unless you know which field should be
/// missing. `cathodeMaterial` is Annex XIII point 2 — withheld from the public —
/// so its presence here is the leak, in the response bytes.
#[tokio::test]
async fn a_restricted_product_group_field_is_absent_from_the_public_view() {
    let mut passport = sample_battery_passport();
    passport["schemaVersion"] = json!("2.6.0");
    passport["productGroupData"]["cathodeMaterial"] = json!("LiFePO4 cathode, 12 kg");

    let vault = {
        let p = passport.clone();
        Router::new().route(
            "/public/dpp/{id}",
            get(move || {
                let pp = p.clone();
                async move { axum::Json(pp) }
            }),
        )
    };
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-9000-000000000002")
        .header("accept", "application/ld+json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    // The inline `@context` defines a term for every field the product group can
    // carry, served or withheld, so the scan reads the document without it.
    let mut doc: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-LD body");
    if let Some(object) = doc.as_object_mut() {
        object.remove("@context");
    }
    let body = doc.to_string();

    assert!(
        !body.contains("cathodeMaterial"),
        "Annex XIII point 2 content reached the public view: {body}"
    );
    // The public half of the same payload is still served — this is a scoping
    // test, not an argument for redacting everything.
    assert!(
        body.contains("batteryChemistry"),
        "point 1 content must survive: {body}"
    );
}

/// A recall must reach the person holding the product.
///
/// The vault branches on status and answers `410 Gone` for a suspended
/// passport. This route folded every non-2xx that was not `404`/`400` into
/// `502 Bad Gateway`, so the one signal a scanner of a recalled product needs
/// arrived as a message about our infrastructure.
#[tokio::test]
async fn a_withdrawn_passport_is_a_recall_not_a_gateway_error() {
    let gtin = "09506000134352";
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async {
            (
                StatusCode::GONE,
                axum::Json(json!({
                    "code": "SUSPENDED",
                    "message": "This passport has been suspended."
                })),
            )
        }),
    );
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    // Every carrier shape, because a printed label may carry any of them and a
    // recall must not depend on how much precision was printed.
    for uri in [
        format!("/01/{gtin}"),
        format!("/01/{gtin}/21/A1B2C3D4E5F6G7H8J9K0"),
        format!("/01/{gtin}/10/LOT-2026-07"),
        format!("/01/{gtin}/10/LOT-2026-07/21/A1B2C3D4E5F6G7H8J9K0"),
    ] {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::GONE,
            "{uri} should report the withdrawal, not an upstream fault"
        );

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem json");
        assert_eq!(
            problem["detail"], "The DPP for this GTIN has been withdrawn.",
            "a withdrawal must not read as a bad label: {problem}"
        );
    }
}

/// The not-found case keeps its own wording — a withdrawal and a GTIN this node
/// never published are different answers and must not converge.
#[tokio::test]
async fn an_unknown_gtin_still_reports_not_found() {
    let gtin = "09506000134352";
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async { StatusCode::NOT_FOUND }),
    );
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri(format!("/01/{gtin}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem json");
    assert_eq!(
        problem["detail"],
        "No published DPP resolves for this GTIN."
    );
}

/// A GTIN that cannot be one is a bad request, not a missing product. The two
/// are different answers, and the person scanning needs to know which: a typo in
/// the code is theirs to retry, an unknown product is not.
#[tokio::test]
async fn a_malformed_gtin_is_a_bad_request_not_a_missing_product() {
    // The vault would say `404` to anything. Getting `400` back therefore shows
    // the resolver refused the value itself.
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async { StatusCode::NOT_FOUND }),
    );
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    for uri in [
        "/01/not-digits",
        "/01/1234567",
        "/01/123456789012345",
        "/01/not-digits/21/SN-1",
        "/01/not-digits/10/LOT-1",
    ] {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem json");
        assert_eq!(
            problem["detail"], "The GTIN in the request is not valid.",
            "{uri}: {problem}"
        );
    }
}

/// A GTIN of the right length with a wrong check digit passes the resolver's
/// own shape test and is refused by the vault with `422`. That is still the
/// caller's malformed request. Reported as a gateway error it read as a fault in
/// this node's infrastructure, sent to the person holding the product.
#[tokio::test]
async fn a_gtin_the_vault_refuses_is_a_bad_request_not_a_bad_gateway() {
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async { StatusCode::UNPROCESSABLE_ENTITY }),
    );
    let port = start_mock_vault(vault).await;
    let base = format!("http://127.0.0.1:{port}");

    // Fourteen digits, so it clears the shape test; the last one is wrong.
    for uri in [
        "/01/09506000134353",
        "/01/09506000134353/21/SN-1",
        "/01/09506000134353/10/LOT-1",
        "/01/09506000134353/10/LOT-1/21/SN-1",
    ] {
        let app = router::build(test_state(base.clone()));
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

/// An upstream that is genuinely broken must still say so, rather than being
/// swept into the withdrawal path by the change above.
#[tokio::test]
async fn a_failing_vault_is_still_a_gateway_error() {
    let gtin = "09506000134352";
    let vault = Router::new().route(
        "/public/dpp/by-gtin/{gtin}",
        get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri(format!("/01/{gtin}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// ---------------------------------------------------------------------------
// What a scan is told when the vault says no, or says nothing it can read
// ---------------------------------------------------------------------------

const PASSPORT_ID: &str = "00000000-0000-4000-9000-000000000001";
const A_GTIN: &str = "09506000134352";

/// A vault that answers every public read, by id or by GTIN, with `status` and
/// `body`.
async fn vault_answering(status: StatusCode, body: &'static str) -> String {
    let vault = Router::new()
        .route(
            "/public/dpp/{id}",
            get(move || async move { (status, body) }),
        )
        .route(
            "/public/dpp/by-gtin/{gtin}",
            get(move || async move { (status, body) }),
        );
    let port = start_mock_vault(vault).await;
    format!("http://127.0.0.1:{port}")
}

/// A vault that answers every request with `200` and `{}`, and counts the requests
/// it was asked.
async fn vault_counting_requests() -> (String, Arc<AtomicUsize>) {
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&asked);
    let vault = Router::new().fallback(move || {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            (StatusCode::OK, "{}")
        }
    });
    let port = start_mock_vault(vault).await;
    (format!("http://127.0.0.1:{port}"), asked)
}

/// A base URL nothing listens on, and the socket that holds its port.
///
/// The port is bound and never listened on, so a connection is refused. Dropping
/// the socket would free the port for another test's mock vault, and the request
/// would then reach it: the caller keeps the socket until the request is done.
fn unreachable_vault() -> (String, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    (format!("http://127.0.0.1:{port}"), socket)
}

/// GET `uri` through a resolver whose vault is at `vault`.
async fn resolve(vault: String, uri: &str, accept: Option<&str>) -> axum::response::Response {
    let app = router::build(test_state(vault));
    let mut req = Request::builder().uri(uri);
    if let Some(accept) = accept {
        req = req.header("accept", accept);
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

async fn text_of(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The three doors a person scanning a code can reach by id. Each answers what the
/// vault said, in its own medium, and none of them turns a refusal into a page.
#[tokio::test]
async fn each_door_reports_what_the_vault_said_in_its_own_medium() {
    let doors: [(&str, String, Option<&str>); 3] = [
        ("html", format!("/dpp/{PASSPORT_ID}"), Some("text/html")),
        (
            "json",
            format!("/dpp/{PASSPORT_ID}"),
            Some("application/ld+json"),
        ),
        ("qr", format!("/dpp/{PASSPORT_ID}/qr"), None),
    ];

    for (door, uri, accept) in &doors {
        for (vault_says, resolver_says) in [
            (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
            (StatusCode::BAD_REQUEST, StatusCode::NOT_FOUND),
            (StatusCode::GONE, StatusCode::GONE),
            (StatusCode::INTERNAL_SERVER_ERROR, StatusCode::BAD_GATEWAY),
            (StatusCode::SERVICE_UNAVAILABLE, StatusCode::BAD_GATEWAY),
        ] {
            let vault = vault_answering(vault_says, "").await;
            let resp = resolve(vault, uri, *accept).await;
            assert_eq!(
                resp.status(),
                resolver_says,
                "{door}: the vault said {vault_says}"
            );
        }
    }
}

#[tokio::test]
async fn each_door_reports_a_vault_that_cannot_be_reached_as_a_bad_gateway() {
    for (door, uri, accept) in [
        ("html", format!("/dpp/{PASSPORT_ID}"), Some("text/html")),
        ("qr", format!("/dpp/{PASSPORT_ID}/qr"), None),
    ] {
        let (vault, _port_held) = unreachable_vault();
        let resp = resolve(vault, &uri, accept).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{door}");
    }
}

/// A `200` that is not JSON is the vault failing, not the passport being absent.
#[tokio::test]
async fn a_vault_answer_that_is_not_json_is_a_bad_gateway_for_the_json_and_qr_doors() {
    for (door, uri, accept) in [
        (
            "json",
            format!("/dpp/{PASSPORT_ID}"),
            Some("application/ld+json"),
        ),
        ("qr", format!("/dpp/{PASSPORT_ID}/qr"), None),
    ] {
        let vault = vault_answering(StatusCode::OK, "this is not json").await;
        let resp = resolve(vault, &uri, accept).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{door}");
    }
}

/// An id that is not a UUID is refused at the resolver's edge, in the medium the
/// caller asked for, without the vault being asked.
#[tokio::test]
async fn an_id_that_is_not_a_uuid_is_not_found_in_each_doors_medium() {
    // A vault that would answer anything: the point is that it is never asked.
    let (vault, asked) = vault_counting_requests().await;

    let resp = resolve(vault.clone(), "/dpp/not-a-uuid", Some("text/html")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );

    let resp = resolve(
        vault.clone(),
        "/dpp/not-a-uuid",
        Some("application/ld+json"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "application/problem+json"
    );

    let resp = resolve(vault.clone(), "/dpp/not-a-uuid/qr", None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "image/png"
    );
    assert!(
        text_of(resp).await.is_empty(),
        "a refused id prints no image"
    );

    assert_eq!(
        asked.load(Ordering::SeqCst),
        0,
        "no door asks the vault about an id that is not a UUID"
    );

    // The count is wired to the vault the resolver reads: an id that is a UUID
    // reaches it.
    resolve(vault, &format!("/dpp/{PASSPORT_ID}"), Some("text/html")).await;
    assert_eq!(asked.load(Ordering::SeqCst), 1);
}

/// The label route's refusals once the vault has been asked: a passport that
/// carries no id, an answer that is not JSON, and a `422` for a GTIN that is
/// well formed to the resolver.
#[tokio::test]
async fn the_label_route_reports_a_vault_answer_it_cannot_use() {
    let uri = format!("/01/{A_GTIN}");

    let vault = vault_answering(StatusCode::OK, r#"{"productName": "No Id"}"#).await;
    let resp = resolve(vault, &uri, None).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(text_of(resp).await.contains("The passport carries no id."));

    let vault = vault_answering(StatusCode::OK, "this is not json").await;
    let resp = resolve(vault, &uri, None).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let vault = vault_answering(StatusCode::UNPROCESSABLE_ENTITY, "").await;
    let resp = resolve(vault, &uri, None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
