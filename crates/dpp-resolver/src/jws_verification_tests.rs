//! Fail-closed JWS verification integration tests, driven through the fully
//! assembled router (mock vault + mock did:web server), not just the
//! `resolve_json` handler in isolation.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use serde_json::json;
use tower::ServiceExt;

use crate::{infra::cache::Cache, router, state::AppState};

/// State with signature verification disabled (empty operator DID) — for
/// tests that exercise routing/content-negotiation, not verification.
fn test_state(vault_base_url: String) -> AppState {
    test_state_did(vault_base_url, String::new())
}

fn test_state_did(vault_base_url: String, operator_did_url: String) -> AppState {
    AppState {
        vault_base_url,
        operator_did_url,
        resolver_base_url: "https://id.odal-node.io".into(),
        cache: Cache::new_noop(),
        http: reqwest::Client::new(),
    }
}

/// Sign `payload` with a fresh Ed25519 key (compact JWS, dpp-identity format)
/// and return `(jws, did_document_json)` serving the matching public key.
fn sign_jws(payload: &serde_json::Value) -> (String, serde_json::Value) {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let pub_key_b64 = b64.encode(signing_key.verifying_key().as_bytes());
    let header_b64 = b64.encode(r#"{"alg":"EdDSA","crv":"Ed25519"}"#);
    let payload_b64 = b64.encode(serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_b64 = b64.encode(signing_key.sign(signing_input.as_bytes()).to_bytes());
    let jws = format!("{signing_input}.{sig_b64}");
    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:test.resolver.example",
        "verificationMethod": [{
            "id": "did:web:test.resolver.example#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:web:test.resolver.example",
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": pub_key_b64 }
        }],
        "assertionMethod": ["did:web:test.resolver.example#key-1"]
    });
    (jws, did_doc)
}

/// Serve a DID document at `/.well-known/did.json` and return its full URL.
async fn serve_did(did_doc: serde_json::Value) -> String {
    let router = Router::new().route(
        "/.well-known/did.json",
        get(move || {
            let d = did_doc.clone();
            async move { axum::Json(d) }
        }),
    );
    let port = start_mock_vault(router).await;
    format!("http://127.0.0.1:{port}/.well-known/did.json")
}

/// Serve a fixed passport JSON from a mock vault and return its base URL.
async fn serve_vault(passport: serde_json::Value) -> String {
    let router = Router::new().route(
        "/public/dpp/{id}",
        get(move || {
            let p = passport.clone();
            async move { axum::Json(p) }
        }),
    );
    let port = start_mock_vault(router).await;
    format!("http://127.0.0.1:{port}")
}

/// Spawn a minimal mock vault Axum server on a random port.
/// Returns the bound port; the server runs until the test runtime shuts down.
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

#[tokio::test]
async fn returns_404_for_nonexistent_passport() {
    let vault = Router::new().route("/public/dpp/{id}", get(|| async { StatusCode::NOT_FOUND }));
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-000000000001")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn returns_410_for_suspended_passport() {
    let vault = Router::new().route("/public/dpp/{id}", get(|| async { StatusCode::GONE }));
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-000000000002")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn returns_html_for_text_html_accept() {
    let vault = Router::new().route(
        "/public/dpp/{id}",
        get(|| async {
            axum::Json(json!({
                "id": "00000000-0000-4000-8000-000000000003",
                "productName": "Test Widget",
                "status": "active",
                "manufacturer": { "name": "Acme Corp" },
                "productCategory": "electronics"
            }))
        }),
    );
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-000000000003")
        .header("accept", "text/html")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/html"), "expected text/html, got: {ct}");
}

#[tokio::test]
async fn returns_json_ld_for_application_json_accept() {
    let vault = Router::new().route(
        "/public/dpp/{id}",
        get(|| async {
            axum::Json(json!({
                "id": "00000000-0000-4000-8000-000000000003",
                "productName": "Test Widget",
                "status": "active",
                "manufacturer": { "name": "Acme Corp" }
            }))
        }),
    );
    let port = start_mock_vault(vault).await;
    let app = router::build(test_state(format!("http://127.0.0.1:{port}")));

    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-000000000003")
        .header("accept", "application/json")
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
        "expected application/ld+json, got: {ct}"
    );
}

async fn resolve_json_status(vault_url: String, did_url: String, id: &str) -> StatusCode {
    let app = router::build(test_state_did(vault_url, did_url));
    let req = Request::builder()
        .uri(format!("/dpp/{id}"))
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// A clean, correctly-signed passport whose served content matches the
/// signed payload must resolve `200 OK`.
#[tokio::test]
async fn valid_signature_and_matching_content_returns_ok() {
    let signed = json!({"id": "00000000-0000-4000-8000-000000000004", "productName": "Widget", "manufacturer": {"name": "Acme"}});
    let (jws, did_doc) = sign_jws(&signed);
    let did_url = serve_did(did_doc).await;
    let mut served = signed.clone();
    served["status"] = json!("active");
    served["publicJwsSignature"] = json!(jws);
    let vault = serve_vault(served).await;
    assert_eq!(
        resolve_json_status(vault, did_url, "00000000-0000-4000-8000-000000000004").await,
        StatusCode::OK
    );
}

/// A valid proof whose signed `id` does not match the served/requested
/// passport (a replay of another passport's signature) must return
/// `409 Conflict`. Under render-from-payload this id binding is the threat
/// model — tampering the *served* fields is moot, as the resolver renders
/// from the signed payload, never the served JSON.
#[tokio::test]
async fn proof_for_a_different_id_returns_conflict() {
    // The signature is over a payload with id "00000000-0000-4000-8000-000000000005"…
    let signed = json!({"id": "00000000-0000-4000-8000-000000000005", "productName": "Widget", "manufacturer": {"name": "Acme"}});
    let (jws, did_doc) = sign_jws(&signed);
    let did_url = serve_did(did_doc).await;
    // …but it is served (with a valid signature) under id "00000000-0000-4000-8000-000000000006".
    let served = json!({
        "id": "00000000-0000-4000-8000-000000000006",
        "productName": "Widget",
        "manufacturer": {"name": "Acme"},
        "status": "active",
        "publicJwsSignature": jws
    });
    let vault = serve_vault(served).await;
    assert_eq!(
        resolve_json_status(vault, did_url, "00000000-0000-4000-8000-000000000006").await,
        StatusCode::CONFLICT
    );
}

/// A tampered signature must return `409 Conflict`.
#[tokio::test]
async fn tampered_jws_returns_conflict() {
    let signed = json!({"id": "00000000-0000-4000-8000-000000000007", "productName": "Widget"});
    let (jws, did_doc) = sign_jws(&signed);
    let tampered = {
        let mut j = jws.clone();
        let c = j.pop().unwrap();
        j.push(if c == 'A' { 'B' } else { 'A' });
        j
    };
    let did_url = serve_did(did_doc).await;
    let served = json!({"id": "00000000-0000-4000-8000-000000000007", "productName": "Widget", "status": "active", "publicJwsSignature": tampered});
    let vault = serve_vault(served).await;
    assert_eq!(
        resolve_json_status(vault, did_url, "00000000-0000-4000-8000-000000000007").await,
        StatusCode::CONFLICT
    );
}

/// A published passport with no signature must fail closed (`409`), not
/// render as valid.
#[tokio::test]
async fn missing_signature_returns_conflict() {
    let (_jws, did_doc) = sign_jws(&json!({"id": "x"}));
    let did_url = serve_did(did_doc).await;
    let served = json!({"id": "00000000-0000-4000-8000-000000000008", "productName": "Widget", "status": "active"});
    let vault = serve_vault(served).await;
    assert_eq!(
        resolve_json_status(vault, did_url, "00000000-0000-4000-8000-000000000008").await,
        StatusCode::CONFLICT
    );
}

/// When the operator DID is unreachable, verification fails closed with
/// `503` — never serves unverified data as `200`.
#[tokio::test]
async fn unreachable_did_returns_service_unavailable() {
    let signed = json!({"id": "00000000-0000-4000-8000-000000000009", "productName": "Widget"});
    let (jws, _did) = sign_jws(&signed);
    let served = json!({"id": "00000000-0000-4000-8000-000000000009", "productName": "Widget", "status": "active", "publicJwsSignature": jws});
    let vault = serve_vault(served).await;
    // Point the operator DID at a closed port.
    let did_url = "http://127.0.0.1:1/.well-known/did.json".to_owned();
    assert_eq!(
        resolve_json_status(vault, did_url, "00000000-0000-4000-8000-000000000009").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// Regression (red-team ATK-3): the public resolver serves the Public tier
/// only. A consumer-supplied `X-Access-Tier` header must NOT unlock
/// professional/confidential fields.
#[tokio::test]
async fn access_tier_header_cannot_unlock_restricted_fields() {
    let passport = json!({
        "id": "00000000-0000-4000-8000-00000000000a",
        "productName": "Tee",
        "status": "active",
        "manufacturer": { "name": "Acme" },
        "sectorData": {
            "sector": "textile",
            "fibreComposition": [{ "fibre": "cotton", "pct": 100.0 }],
            "svhcSubstances": [{ "casNumber": "117-81-7", "substanceName": "DEHP", "concentrationPct": 0.05 }],
            "disassemblyInstructions": "SECRET REPAIR PROCESS"
        }
    });
    let vault = serve_vault(passport).await;
    // operator_did_url empty → signature verification disabled; this test
    // isolates tier filtering.
    let app = router::build(test_state(vault));

    for tier in ["public", "professional", "confidential"] {
        let req = Request::builder()
            .uri("/dpp/00000000-0000-4000-8000-00000000000a")
            .header("accept", "application/ld+json")
            .header("x-access-tier", tier)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("svhcSubstances") && !s.contains("disassemblyInstructions"),
            "tier header '{tier}' must not unlock restricted fields, got: {s}"
        );
    }
}
