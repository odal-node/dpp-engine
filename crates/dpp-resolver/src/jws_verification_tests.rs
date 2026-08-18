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
        scan_counter: None,
    }
}

/// Sign `payload` with a fresh Ed25519 key (compact JWS, dpp-identity format)
/// and return `(jws, did_document_json)` serving the matching public key.
fn sign_jws(payload: &serde_json::Value) -> (String, serde_json::Value) {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::generate(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng));
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

// ─── AAS door ─────────────────────────────────────────────────────────────────

/// A published battery passport carrying restricted and individual-tier fields.
///
/// Battery is used deliberately: it has the most non-public fields of any
/// product group, and `stateOfHealthPct` is the field that was once served
/// publicly, so it is the strongest fixture for a masking assertion.
fn battery_passport_json() -> serde_json::Value {
    json!({
        "id": "00000000-0000-4000-8000-0000000000aa",
        "productName": "Test Battery",
        "sector": "battery",
        "manufacturer": { "name": "Acme Corp", "address": "1 Main St, Berlin, DE" },
        "materials": [],
        "co2ePerUnit": null,
        "repairabilityScore": null,
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "batteryType": "ev",
            "nominalVoltageV": 3.7,
            "nominalCapacityAh": 50.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 85.0,
            "anodeMaterial": [{ "name": "graphite", "weightPct": 45.0 }],
            "cathodeMaterial": [{ "name": "lithium-iron-phosphate", "weightPct": 30.0 }],
            "electrolyteMaterial": [{ "name": "LiPF6", "weightPct": 12.0 }],
            "criticalRawMaterials": [{ "name": "cobalt", "casNumber": "7440-48-4", "weightGrams": 40.0, "countryOfOrigin": "CD" }],
            "disassemblyInstructionsUrl": "https://acme.example.com/disassembly",
            "dueDiligenceUrl": "https://acme.example.com/due-diligence",
            "sohMethodology": "IEC 62660-1 capacity fade",
            "stateOfHealthPct": 97.5,
            "stateOfHealth": { "parameterSet": "electricVehicle", "socePct": 97.5 },
            "expectedLifetime": {
                "energyThroughputKwh": 12000.0,
                "capacityThroughputAh": 3200.0,
                "fullEquivalentCycles": 850.0,
                "harmfulEvents": {}
            }
        },
        "status": "active",
        "qrCodeUrl": null,
        "jwsSignature": null,
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
        "publishedAt": "2026-01-01T00:00:00Z",
        "schemaVersion": "2.6.0"
    })
}

async fn aas_app_serving(body: serde_json::Value) -> Router {
    let vault = Router::new().route(
        "/public/dpp/{id}",
        get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let port = start_mock_vault(vault).await;
    router::build(test_state(format!("http://127.0.0.1:{port}")))
}

async fn get_aas(app: Router, id: &str) -> axum::response::Response {
    let req = Request::builder()
        .uri(format!("/dpp/{id}"))
        .header("accept", "application/aas+json")
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn aas_accept_returns_an_environment() {
    let app = aas_app_serving(battery_passport_json()).await;
    let resp = get_aas(app, "00000000-0000-4000-8000-0000000000aa").await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(
        ct.contains("application/aas+json"),
        "expected application/aas+json, got: {ct}"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let env: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert!(env["assetAdministrationShells"].is_array());
    assert!(env["submodels"].is_array());
    assert_eq!(
        env["assetAdministrationShells"].as_array().unwrap().len(),
        1
    );

    // `conceptDescriptions` must be **absent**, not an empty array. The AAS
    // metamodel constrains it to `minItems: 1`, so `[]` makes the whole
    // Environment invalid — and this crate coins no concept descriptions, so
    // empty is the only value it could ever have. dpp-core 0.15.0 omits it;
    // before that it emitted `[]`, and this assertion was the wrong way round.
    assert!(
        env.get("conceptDescriptions").is_none(),
        "an empty conceptDescriptions array reached the wire: {env}"
    );

    // The shell carries no `kind`. It is not a member of
    // `AssetAdministrationShell` in the metamodel — `kind` arrives through
    // `HasKind`, which `Submodel` composes and the shell does not. No JSON
    // Schema catches it (IDTA sets `additionalProperties` nowhere), so a strict
    // AAS loader is what would reject the document. Asserted at this door
    // because this is where the bytes actually reach an integrator.
    let shell = &env["assetAdministrationShells"][0];
    assert!(
        shell.get("kind").is_none(),
        "the shell carries a `kind` member, which the metamodel does not define: {shell}"
    );
    assert_eq!(
        shell["assetInformation"]["assetKind"], "Instance",
        "assetKind is the only required member of AssetInformation"
    );
}

/// The merge gate. Every field battery's catalog entry classifies non-public
/// must be absent from a public AAS projection.
#[tokio::test]
async fn aas_door_emits_no_non_public_battery_field() {
    let app = aas_app_serving(battery_passport_json()).await;
    let resp = get_aas(app, "00000000-0000-4000-8000-0000000000aa").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).expect("utf-8");

    // Asserted by name rather than by re-reading the catalog, so that a change
    // to the disclosure map cannot silently change what this test demands. That
    // is working as intended: two fields left this list when `dpp-domain` moved
    // to battery schema v2.6.0, and each had to be checked against the schema's
    // stated basis rather than deleted to make the test pass.
    //
    // - `criticalRawMaterials` is now **public**: Annex XIII point 1(b) lists
    //   critical raw materials alongside chemistry and hazardous substances as
    //   part of the publicly accessible material composition.
    // - `dueDiligenceUrl` is now **public**: Annex XIII point 1(d).
    //
    // Both are widenings, so both deserved the scrutiny. The six below stay
    // non-public — `stateOfHealthPct` is `individual` and the rest `restricted`.
    for field in [
        "anodeMaterial",
        "cathodeMaterial",
        "electrolyteMaterial",
        "disassemblyInstructionsUrl",
        "sohMethodology",
        "stateOfHealthPct",
    ] {
        assert!(
            !body.contains(field),
            "non-public battery field '{field}' appears in the public AAS door's output"
        );
    }

    // And it is not vacuous: the projection still carries its public content.
    assert!(
        body.contains("nominalVoltageV") || body.contains("ProductIdentification"),
        "the public projection carries nothing at all"
    );
}

#[tokio::test]
async fn unacceptable_accept_returns_406_not_a_default_body() {
    let app = aas_app_serving(battery_passport_json()).await;
    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-0000000000aa")
        .header("accept", "application/pdf")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
}

/// `q=0` means "not acceptable", so naming AAS and refusing it must not serve
/// AAS.
///
/// Listing a type and weighting it to zero is the standard way to say *anything
/// but this*. Reading the name and ignoring the weight served the client the one
/// representation it asked not to receive — and left this route inconsistent
/// with `dpp-digital-link`'s own `Accept` parser, which has always honoured `q`.
#[tokio::test]
async fn a_zero_weighted_aas_type_is_refused_not_served() {
    let app = aas_app_serving(battery_passport_json()).await;
    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-0000000000aa")
        .header("accept", "application/aas+json;q=0, application/ld+json")
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
        "a q=0 AAS type was served anyway, got: {ct}"
    );
}

/// `text/*` resolves to HTML rather than `406`.
///
/// Its sibling `application/*` was already honoured; refusing this one was an
/// oversight.
#[tokio::test]
async fn a_text_subtype_wildcard_resolves_to_html() {
    let app = aas_app_serving(battery_passport_json()).await;
    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-0000000000aa")
        .header("accept", "text/*")
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

/// …but it must not take the decision away from a client that also accepts
/// JSON. `Accept: text/*, application/json` resolved to JSON-LD before this
/// route understood `text/*`, and still must.
#[tokio::test]
async fn a_text_wildcard_alongside_json_still_resolves_to_json() {
    let app = aas_app_serving(battery_passport_json()).await;
    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-0000000000aa")
        .header("accept", "text/*, application/json")
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

/// The permissive cases that must keep working, or every existing consumer of
/// this route breaks.
#[tokio::test]
async fn wildcard_and_absent_accept_still_reach_the_json_default() {
    for accept in ["*/*", "application/json", ""] {
        let app = aas_app_serving(battery_passport_json()).await;
        let mut builder = Request::builder().uri("/dpp/00000000-0000-4000-8000-0000000000aa");
        if !accept.is_empty() {
            builder = builder.header("accept", accept);
        }
        let resp = app
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Accept '{accept}' must still resolve, not 406"
        );
    }
}

/// The AAS body is built from the **signed** payload, not the served row.
///
/// Every other AAS test here runs with verification disabled, so none of them
/// can tell the two apart — this is the only one that exercises the path the
/// door actually takes in production. A passport is signed carrying one product
/// name and then served carrying another; the projection must show what was
/// signed. Rendering the live row instead would attach a publish-time proof to
/// a body that can still change afterwards, which is the divergence
/// `public_view.rs` exists to close, reintroduced through a second door.
#[tokio::test]
async fn the_aas_door_projects_the_signed_payload_not_the_live_row() {
    let mut signed = battery_passport_json();
    signed["productName"] = json!("Signed Battery");
    let (jws, did_doc) = sign_jws(&signed);
    let did_url = serve_did(did_doc).await;

    // The row drifts after publish; the proof still covers the original.
    let mut served = signed.clone();
    served["productName"] = json!("Drifted Battery");
    served["publicJwsSignature"] = json!(jws);

    let vault = serve_vault(served).await;
    let app = router::build(test_state_did(vault, did_url));
    let resp = get_aas(app, "00000000-0000-4000-8000-0000000000aa").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).expect("utf-8");

    assert!(
        body.contains("Signed Battery"),
        "the projection does not carry the signed product name: {body}"
    );
    assert!(
        !body.contains("Drifted Battery"),
        "the projection carries the drifted live row rather than the signed payload"
    );
}

// ─── cross-door agreement ─────────────────────────────────────────────────────

/// Every object key in `value`, at any depth.
fn keys_at_any_depth(value: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                out.insert(key.clone());
                keys_at_any_depth(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            items.iter().for_each(|item| keys_at_any_depth(item, out));
        }
        _ => {}
    }
}

/// Every `idShort` in `value`, at any depth — the AAS equivalent of a field name.
fn id_shorts_at_any_depth(value: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(name) = map.get("idShort").and_then(|v| v.as_str()) {
                out.insert(name.to_owned());
            }
            map.values()
                .for_each(|child| id_shorts_at_any_depth(child, out));
        }
        serde_json::Value::Array(items) => {
            items
                .iter()
                .for_each(|item| id_shorts_at_any_depth(item, out));
        }
        _ => {}
    }
}

async fn body_of(app: Router, id: &str, accept: &str) -> serde_json::Value {
    let req = Request::builder()
        .uri(format!("/dpp/{id}"))
        .header("accept", accept)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Accept '{accept}' must resolve"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("a JSON body")
}

/// **The anti-drift gate.** Nothing the JSON-LD door withholds may appear in the
/// AAS door's output.
///
/// The two doors reach the same passport at the same URL through entirely
/// separate code: `resolve_json` applies `filter_by_audience` here in the
/// resolver, while `resolve_aas` delegates field selection to `dpp-aas` in the
/// core library. Each has its own masking test. Until now nothing compared them
/// — which is exactly the shape that drifts, because both tests keep passing
/// while the two definitions of "public" separate.
///
/// The comparison is driven from the *source* passport rather than from a
/// hand-written list of expected names: any key the served passport carries that
/// the JSON-LD door dropped must also be absent from the AAS projection. That
/// needs no allowance for the structural names the AAS invents
/// (`ProductIdentification`, `passportId`, …) — they are not in the source, so
/// they never enter the comparison, and they cannot be used to smuggle one in.
#[tokio::test]
async fn the_aas_door_withholds_everything_the_json_door_withholds() {
    let passport = battery_passport_json();
    let id = "00000000-0000-4000-8000-0000000000aa";
    let app = aas_app_serving(passport.clone()).await;

    let json_ld = body_of(app.clone(), id, "application/ld+json").await;
    let aas = body_of(app, id, "application/aas+json").await;

    let mut source = std::collections::BTreeSet::new();
    keys_at_any_depth(&passport, &mut source);
    let mut public = std::collections::BTreeSet::new();
    keys_at_any_depth(&json_ld, &mut public);
    let mut projected = std::collections::BTreeSet::new();
    id_shorts_at_any_depth(&aas, &mut projected);

    let withheld: Vec<&String> = source.difference(&public).collect();

    // Non-vacuity, anchored to battery's catalog entry rather than to a count:
    // every field the catalog classifies non-public must actually have been
    // withheld here, or the comparison below is being run against a passport
    // that carried nothing worth withholding. Named explicitly so that
    // reclassifying a field shows up as a diff in this list.
    // `dueDiligenceUrl` and `criticalRawMaterials` left this list at battery
    // schema v2.6.0, which reclassified both as public (Annex XIII points 1(d)
    // and 1(b)). The list is named explicitly precisely so that shows up as a
    // diff here rather than as a quietly weaker check.
    for field in [
        "disassemblyInstructionsUrl",
        "cathodeMaterial",
        "anodeMaterial",
        "electrolyteMaterial",
        "sohMethodology",
        "stateOfHealth",
        "stateOfHealthPct",
        "expectedLifetime",
    ] {
        assert!(
            withheld.iter().any(|w| *w == field),
            "'{field}' is non-public in battery's catalog entry but the JSON-LD \
             door did not withhold it — either the fixture stopped carrying it, \
             or the public view has regressed"
        );
    }

    let leaked: Vec<&&String> = withheld
        .iter()
        .filter(|field| projected.contains(**field))
        .collect();
    assert!(
        leaked.is_empty(),
        "the AAS door emits {leaked:?}, which the JSON-LD door withholds from the \
         same passport at the same URL. Two definitions of 'public' have drifted, \
         and this is the direction that leaks."
    );

    // The AAS door must also not be *emptier* by accident — a projection that
    // carried nothing would satisfy the assertion above and be worthless.
    assert!(
        projected.len() > 5,
        "the AAS projection carries almost nothing ({projected:?}); the gate above \
         passed vacuously"
    );
}

/// The AAS response points a verifier at the signed canonical view.
///
/// The body is unsigned and cannot carry the public proof — that signature
/// covers the canonical payload, not this serialisation of it — so the `Link`
/// header is the only thing standing between "here is some AAS" and "here is
/// AAS, and here is the signed thing it derives from".
///
/// End-to-end through the router, on the uncached path. The cache-hit path
/// shares this response constructor and is covered in `resolve_aas`'s own
/// tests, since populating a cache hit here would need a live Redis.
#[tokio::test]
async fn the_aas_response_links_to_the_signed_canonical_view() {
    let app = aas_app_serving(battery_passport_json()).await;
    let resp = get_aas(app, "00000000-0000-4000-8000-0000000000aa").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let link = resp
        .headers()
        .get(axum::http::header::LINK)
        .and_then(|v| v.to_str().ok())
        .expect("a 200 from the AAS door carries a Link header");

    // `test_state` configures this base; the target must be the resolver's own
    // URL for the same passport, not the passport's mutable `qrCodeUrl`.
    assert_eq!(
        link,
        r#"<https://id.odal-node.io/dpp/00000000-0000-4000-8000-0000000000aa>; rel="alternate"; type="application/ld+json""#
    );
}

/// A `406` carries no `Link`.
///
/// There is no representation to link *from*, and advertising an alternate on
/// an error would tell a client the negotiation half-succeeded.
#[tokio::test]
async fn an_unacceptable_request_carries_no_link_header() {
    let app = aas_app_serving(battery_passport_json()).await;
    let req = Request::builder()
        .uri("/dpp/00000000-0000-4000-8000-0000000000aa")
        .header("accept", "application/pdf")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    assert!(
        resp.headers().get(axum::http::header::LINK).is_none(),
        "a 406 must not advertise an alternate representation"
    );
}

/// The same passport yields byte-identical bytes twice, so the response can be
/// cached and compared.
#[tokio::test]
async fn the_aas_body_is_byte_identical_across_requests() {
    let app = aas_app_serving(battery_passport_json()).await;

    let first = get_aas(app.clone(), "00000000-0000-4000-8000-0000000000aa").await;
    let second = get_aas(app, "00000000-0000-4000-8000-0000000000aa").await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    let read = async |resp: axum::response::Response| {
        axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap()
    };
    assert_eq!(
        read(first).await,
        read(second).await,
        "two reads of an unchanged passport produced different bytes"
    );
}

/// Guard: the fixture above must be a genuinely valid passport. Without this,
/// a fixture that silently stopped deserialising would turn every AAS
/// assertion into a vacuous pass against a 502.
#[test]
fn battery_fixture_is_a_valid_passport() {
    let value = battery_passport_json();
    let parsed: Result<dpp_domain::Passport, _> = serde_json::from_value(value);
    if let Err(e) = &parsed {
        panic!("battery fixture is not a valid Passport: {e}");
    }
}
