//! End-to-end tests for the DPP resolver.
//!
//! Covers functionality not exercised by the inline unit tests in `lib.rs`:
//! - QR PNG generation and cacheability
//! - Content negotiation edge cases (no Accept, wildcard Accept)
//! - HTML rendering with battery and textile sector data
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

use std::sync::OnceLock;

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
        "productCategory": "ELECTRONICS",
        "status": "active",
        "manufacturer": {"name": "E2E Corp", "address": "Berlin, DE"},
        "materials": [{"name": "Copper", "weightKg": 0.3}],
        "schemaVersion": "1.0.0"
    })
}

/// `sample_passport()` plus sector data carrying a GTIN — what a real
/// carrier-bearing product passport looks like, for the QR tests.
fn sample_passport_with_gtin() -> serde_json::Value {
    let mut p = sample_passport();
    p["sectorData"] = json!({ "sector": "electronics", "gtin": "09506000134352" });
    p
}

fn sample_battery_passport() -> serde_json::Value {
    json!({
        "id": "00000000-0000-4000-9000-000000000002",
        "productName": "EcoCell 48V",
        "productCategory": "BATTERY",
        "status": "active",
        "manufacturer": {"name": "GreenCell GmbH", "address": "Munich, DE"},
        "sectorData": {
            "sector": "battery",
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
        "productCategory": "TEXTILE",
        "status": "active",
        "manufacturer": {"name": "FabriqGreen", "address": "Milan, IT"},
        "sectorData": {
            "sector": "textile",
            "countryOfManufacturing": "IT",
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

/// A passport whose sector data carries no GTIN (e.g. an unsold-goods report,
/// or here simply no `sectorData` at all) has no valid GS1 Digital Link
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
// HTML rendering with sector data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn html_includes_battery_sector_data() {
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

/// Every AI combination `dpp_digital_link::build_qr_url` can print must
/// resolve. The publisher emits `/01/{gtin}[/10/{batch}]/21/{serial}`, so a
/// GTIN-only route alone means this node's own printed QR codes 404. All four
/// shapes resolve on the GTIN; batch and serial are accepted and ignored.
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

// ── GS1 Digital Link: signature verification ────────────────────────────────

/// GTIN resolution is a second way to reach the same passport data as the
/// id-based routes, so it must verify the public JWS against the operator DID
/// exactly like they do — not a second, unverified path.
#[tokio::test]
async fn gtin_resolution_verifies_a_valid_signature() {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let pub_key_b64 = b64.encode(signing_key.verifying_key().as_bytes());

    let gtin = "09506000134352";
    let passport_id = "00000000-0000-4000-9000-0000000000aa";
    let public_view = json!({ "id": passport_id, "productName": "Signed GTIN Widget" });
    let header = r#"{"alg":"EdDSA","crv":"Ed25519"}"#;
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
        "sectorData": { "sector": "electronics", "gtin": gtin },
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
