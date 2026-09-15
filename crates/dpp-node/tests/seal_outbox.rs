//! Full-loop integration test for eIDAS qualified sealing.
//!
//! This is the closest thing to the real thing that exists without eID Easy
//! sandbox credentials. Everything is real except the provider:
//!
//! - real PostgreSQL (testcontainer), with the whole migration set applied;
//! - real Ed25519 signing through `LocalIdentityService` + `KeyStore`;
//! - the real `PassportService::publish` path, which enqueues after commit;
//! - the real `QtspSealAdapter` over the real `EideasyClient` and real HTTP;
//! - the real `seal_drain::drain_once`.
//!
//! The only substitution is the endpoint: a local server that **verifies the
//! HMAC by recomputing it over the bytes it actually received**, exactly as eID
//! Easy does, and returns a response in their documented shape. So this exercises
//! the sign-the-exact-bytes rule over a socket rather than trusting it.
//!
//! What it therefore does *not* prove: that eID Easy accepts our
//! `signature_profile`, that they accept an extensionless `fileName`, or that
//! the returned `.p7s` validates against the EU Trusted List. Those need the
//! provider's sandbox, and no local test can stand in for them.
//!
//! The last test here runs the same loop over the **local** backend instead,
//! which produces genuine detached CAdES rather than a stand-in, and reads
//! `dpp_seal::qualification`'s verdict off the seal that lands in the database.
//! That is the one part of the Trusted List question answerable without a
//! provider: whether anybody issued the certificate at all.
//!
//! Run: `just seal-sim` (or
//! `cargo test -p dpp-node --features integration-tests --test seal_outbox -- --nocapture`)

#![cfg(feature = "integration-tests")]

use std::sync::Arc;
use std::sync::Mutex;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use dpp_dal::pg::{PgAuditRepo, PgPassportRepo, PgSealOutboxRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::compliance::ComplianceRegistry;
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::seal::SealMode;
use dpp_domain::status::PassportStatus;
use dpp_domain::{GhostArchive, GhostRegistrySync};
use dpp_domain::{ports::seal::SealPort, seal::SealConformanceLevel};
use dpp_node::infra::seal_drain::drain_once;
use dpp_seal::QtspSealAdapter;
use dpp_seal::eideasy::client::{ESEAL_PATH, hmac_message};
use dpp_types::SealOutbox;
use dpp_types::api_key::ApiKeyScope;
use dpp_types::auth::AuthContext;
use dpp_vault::domain::service::{OperatorIdentity, PassportService};

type HmacSha256 = Hmac<Sha256>;

/// The sandbox HMAC key stands in for `SEAL_EIDEASY_HMAC_KEY`.
const MOCK_KEY: &str = "simulated-eseal-hmac-key";
const MOCK_CLIENT_ID: &str = "Zn1SIMULATEDclientIDforlocalloop";

// ─── Mock eID Easy ────────────────────────────────────────────────────────────

#[derive(Default)]
struct MockState {
    /// Every request as received, verbatim: (raw body, timestamp, signature).
    requests: Mutex<Vec<(String, String, String)>>,
    /// Requests that failed HMAC verification.
    rejected: Mutex<u32>,
}

/// Stands in for `POST /api/signatures/e-seal`.
///
/// Recomputes the HMAC over the bytes that arrived. If our client re-serialized
/// the body anywhere between signing and sending, this returns 401 — the same
/// failure eID Easy would produce, and indistinguishable from a bad key, which
/// is exactly why it is worth simulating.
async fn eseal(State(state): State<Arc<MockState>>, headers: HeaderMap, body: Bytes) -> Response {
    let raw = String::from_utf8(body.to_vec()).expect("body is utf-8");
    let ts = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let presented = headers
        .get("X-HMAC-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    state
        .requests
        .lock()
        .unwrap()
        .push((raw.clone(), ts.clone(), presented.clone()));

    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(MOCK_KEY.as_bytes()).unwrap();
    mac.update(hmac_message("POST", ESEAL_PATH, ts.parse().unwrap_or(0), &raw).as_bytes());
    let expected = BASE64.encode(mac.finalize().into_bytes());

    if presented != expected {
        *state.rejected.lock().unwrap() += 1;
        return (StatusCode::UNAUTHORIZED, "HMAC mismatch").into_response();
    }

    let req: serde_json::Value = serde_json::from_str(&raw).expect("body is JSON");
    let file_name = req["files"][0]["fileName"].as_str().unwrap_or_default();
    let submitted_digest = req["files"][0]["fileContent"].as_str().unwrap_or_default();

    // A detached CMS is opaque to us, so the stand-in embeds the digest it was
    // taken over. That makes the simulation's output checkable by eye: the seal
    // visibly corresponds to the passport's signature.
    let p7s = BASE64.encode(format!("SIMULATED-CAdES-DETACHED-OVER:{submitted_digest}"));

    axum::Json(serde_json::json!({
        "status": "OK",
        "signatures": [{
            "fileName": format!("{file_name}.p7s"),
            "mimeType": "application/pkcs7-signature",
            "fileContent": p7s,
        }],
    }))
    .into_response()
}

async fn spawn_mock(state: Arc<MockState>) -> String {
    let app = Router::new()
        .route(ESEAL_PATH, post(eseal))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

// ─── Postgres harness ─────────────────────────────────────────────────────────

// ─── Service harness ──────────────────────────────────────────────────────────

fn auth() -> AuthContext {
    AuthContext {
        user_id: "seal-sim".into(),
        scope: ApiKeyScope::Admin,
        key_id: None,
    }
}

fn draft_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: Some("LOT-SEAL-SIM-1".into()),
        serial_number: None,
        product_name: "Seal Simulation Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "Odal Simulation GmbH".into(),
            address: "Skopje, MK".into(),
            registered_trade_name: None,
            electronic_address: None,
            country: None,
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        // A battery passport cannot publish with no product group data at all — the
        // mandatory-content gate refuses it before asking which fields are
        // missing. Portable is outside the Commission guidance's scope, so this
        // carries the schema minimum: the subject here is the seal outbox and
        // its drain, not battery content.
        //
        // Built by deserialising rather than as a struct literal. `BatteryData`
        // derives no `Default` on purpose — a new Annex field should break every
        // literal and force a decision — and this test has no opinion about any
        // of the sixty fields it would then have to name.
        product_group_data: Some(
            serde_json::from_value(serde_json::json!({
                "productGroup": "battery",
                "gtin": "09506000134352",
                "batteryType": "portable",
                "batteryChemistry": "LFP",
                "nominalVoltageV": 3.7,
                "nominalCapacityAh": 2.5,
                "co2ePerUnitKg": 1.8
            }))
            .expect("valid battery product_group data"),
        ),
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        placed_on_market_date: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        derived_from: Vec::new(),
        component_refs: Vec::new(),
        life_status: None,
        retention_until: None,
        product_id: None,
        commodity_code: None,
        // Battery is an in-force product group, so publish refuses without the Annex III
        // registry identity. Set here because the simulation has no operator
        // config to backfill from — the gate itself is correct and stays armed.
        operator_identifier: Some("LEI:529900T8BM49AURSDO55".into()),
        responsible_operator: None,
        facility: Some(dpp_domain::passport::FacilitySnapshot {
            scheme: "gln".into(),
            value: "4035600210708".into(),
            name: "Odal Simulation Plant".into(),
            country: "MK".into(),
            address: Some("Skopje, MK".into()),
        }),
        seal: None,
    }
}

/// The conformance level these tests request.
///
/// Matched to `eideasy_config`'s `signature_profile`, and deliberately **not**
/// the node's production default of `B-LT`. The adapter now refuses a level its
/// backend does not advertise, and this backend advertises whatever its profile
/// names — so asking for `B-LT` here would be refused before the mock server
/// ever saw the request. That refusal is the capability check working; raising
/// this constant to match production would be routing around it.
const TEST_LEVEL: SealConformanceLevel = SealConformanceLevel::BaselineT;

fn eideasy_config(base_url: &str) -> dpp_seal::eideasy::EideasyConfig {
    dpp_seal::eideasy::EideasyConfig {
        base_url: base_url.to_owned(),
        environment: dpp_seal::eideasy::EideasyEnvironment::Sandbox,
        client_id: MOCK_CLIENT_ID.to_owned(),
        hmac_key: zeroize::Zeroizing::new(MOCK_KEY.to_owned()),
        signature_profile: "CAdES_BASELINE_T".to_owned(),
        request_timeout: std::time::Duration::from_secs(10),
    }
}

/// What the composition root resolves for this backend: the provider's own
/// selector value, plus the client the seal is billed to. No backend reads it —
/// it is carried as provenance — but it is built here rather than in the drain
/// so the drain stays provider-agnostic.
fn mock_key_ref() -> dpp_domain::seal::SealCredentialRef {
    dpp_domain::seal::SealCredentialRef {
        qtsp_id: dpp_seal::eideasy::config::PROVIDER.to_owned(),
        credential_id: MOCK_CLIENT_ID.to_owned(),
    }
}

/// The real `SealPort` over the real provider backend, pointed at the mock.
fn eideasy_adapter(cfg: dpp_seal::eideasy::EideasyConfig) -> Arc<dyn SealPort> {
    Arc::new(QtspSealAdapter::new(
        dpp_seal::eideasy::EideasyClient::new(cfg).expect("build adapter"),
    ))
}

// ─── The loop ─────────────────────────────────────────────────────────────────

/// Publish a real passport, let the real drain seal it against the mock, and
/// print every record produced along the way.
#[tokio::test]
async fn publish_then_drain_seals_the_passport_end_to_end() {
    let _pg = start_pg().await;
    let dal = _pg.dal.clone();
    let mock = Arc::new(MockState::default());
    let base_url = spawn_mock(mock.clone()).await;

    // Real signing. The keystore holds an Ed25519 private key even in a test, so
    // it goes in a `tempfile` directory — created with restrictive permissions
    // and removed on drop — rather than a predictable path in the shared temp dir.
    let key_dir = tempfile::tempdir().expect("temp dir");
    let key_path = key_dir.path().join("keystore.json");
    let store = dpp_crypto::keystore::KeyStore::open(&key_path, "test-pass").expect("keystore");
    store.generate_key("root").expect("generate key");
    let identity = Arc::new(dpp_vc::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        "seal-sim.example.com".to_owned(),
    ));

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let seal_outbox = Arc::new(PgSealOutboxRepo::new(dal.clone()));

    let service = PassportService::new(
        passport_repo.clone(),
        identity,
        Arc::new(dpp_domain::PassthroughRegistry::new()) as Arc<dyn ComplianceRegistry>,
        Arc::new(PgAuditRepo::new(dal.clone())),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "MK".to_owned(),
        },
    )
    .with_seal_outbox(seal_outbox.clone());

    // ── 1. Create + publish ──────────────────────────────────────────────────
    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");
    let published = service.publish(id, &auth()).await.expect("publish");

    let jws = published.jws_signature.clone().expect("publish signs");
    let expected_digest = hex::encode(Sha256::digest(jws.as_bytes()));

    println!("\n═══ 1. PUBLISHED PASSPORT ═══");
    println!("passportId      : {id}");
    println!("status          : {:?}", published.status);
    println!("retentionLocked : {}", published.retention_locked);
    println!("jwsSignature    : {jws}");
    println!(
        "seal            : {:?}  <- absent, not faked",
        published.seal
    );

    // ── 2. The outbox row publish created ────────────────────────────────────
    let due = seal_outbox.due(10).await.expect("due");
    assert_eq!(due.len(), 1, "publish must enqueue exactly one seal row");
    println!("\n═══ 2. SEAL OUTBOX ROW (after publish) ═══");
    println!("rowId           : {}", due[0].id);
    println!("passportId      : {}", due[0].passport_id);
    println!("payloadHash     : {}", due[0].payload_hash);
    println!("attempts        : {}", due[0].attempts);
    assert_eq!(
        due[0].payload_hash, expected_digest,
        "the queued digest must be SHA-256 of the compact JWS"
    );

    // ── 3. Drain: the real adapter against the mock ──────────────────────────
    let adapter = eideasy_adapter(eideasy_config(&base_url));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    let stats = drain_once(
        &outbox_dyn,
        &adapter,
        &mock_key_ref(),
        SealMode::ProviderSeal,
        TEST_LEVEL,
        10,
    )
    .await;
    assert_eq!(stats.sealed, 1, "the drain must seal the queued row");
    assert_eq!(stats.retried, 0);

    // ── 4. What actually went over the wire ─────────────────────────────────
    let requests = mock.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "exactly one billable call");
    assert_eq!(*mock.rejected.lock().unwrap(), 0, "HMAC verified first try");
    let (raw_body, ts, sig) = &requests[0];
    println!("\n═══ 3. REQUEST eID EASY RECEIVED ═══");
    println!("POST {base_url}{ESEAL_PATH}");
    println!("X-Timestamp     : {ts}");
    println!("X-HMAC-Signature: {sig}");
    println!("body            : {raw_body}");
    println!("(HMAC recomputed over these exact bytes by the receiver: MATCH)");

    let sent: serde_json::Value = serde_json::from_str(raw_body).unwrap();
    assert_eq!(sent["files"][0]["mimeType"], "application/pdf");
    assert_eq!(sent["signature_form"], "CAdES");
    assert_eq!(
        sent["files"][0]["fileContent"],
        BASE64.encode(hex::decode(&expected_digest).unwrap()),
        "we must submit base64 of the raw 32 digest bytes"
    );
    assert!(
        !sent["files"][0]["fileName"].as_str().unwrap().contains('.'),
        "fileName carries no extension to contradict the declared mimeType"
    );

    // ── 5. The sealed passport ──────────────────────────────────────────────
    let sealed = passport_repo
        .find_by_id(id)
        .await
        .expect("read back")
        .expect("passport exists");
    let seal = sealed.seal.clone().expect("seal landed on the passport");

    println!("\n═══ 4. SEALED PASSPORT (read back from Postgres) ═══");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "passportId": id.to_string(),
            "status": format!("{:?}", sealed.status),
            "retentionLocked": sealed.retention_locked,
            "jwsSignature": sealed.jws_signature,
            "seal": seal,
        }))
        .unwrap()
    );

    assert!(!seal.placeholder, "a provider seal is never a placeholder");
    assert_eq!(seal.format, dpp_domain::seal::SealFormat::Cades);
    // The stand-in embeds the digest it sealed, so the seal is visibly bound to
    // this passport's signature.
    let decoded = String::from_utf8(BASE64.decode(&seal.seal_value).unwrap()).unwrap();
    assert!(
        decoded.contains(&BASE64.encode(hex::decode(&expected_digest).unwrap())),
        "the seal must be over this passport's JWS digest"
    );

    // ── 6. Row closed; a second pass buys nothing ───────────────────────────
    let counts = seal_outbox.status_counts().await.expect("counts");
    println!("\n═══ 5. OUTBOX AFTER DRAIN ═══");
    println!(
        "pending: {}  sealed: {}  exhausted: {}",
        counts.pending, counts.sealed, counts.exhausted
    );
    assert_eq!(counts.sealed, 1);
    assert_eq!(counts.pending, 0);

    let stats2 = drain_once(
        &outbox_dyn,
        &adapter,
        &mock_key_ref(),
        SealMode::ProviderSeal,
        TEST_LEVEL,
        10,
    )
    .await;
    assert_eq!(stats2.sealed, 0, "a closed row must not be re-sealed");
    assert_eq!(
        mock.requests.lock().unwrap().len(),
        1,
        "a second drain pass must not make a second billable call"
    );
    println!("second drain pass: 0 rows, 0 calls — no double billing\n");
}

/// A re-publish re-signs, so it needs its own seal — and the old seal must not
/// silently be taken as covering the new signature.
#[tokio::test]
async fn a_republish_needs_and_gets_its_own_seal() {
    let _pg = start_pg().await;
    let dal = _pg.dal.clone();
    let mock = Arc::new(MockState::default());
    let base_url = spawn_mock(mock.clone()).await;

    let key_dir = tempfile::tempdir().expect("temp dir");
    let key_path = key_dir.path().join("keystore.json");
    let store = dpp_crypto::keystore::KeyStore::open(&key_path, "test-pass").expect("keystore");
    store.generate_key("root").expect("generate key");
    let identity = Arc::new(dpp_vc::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        "seal-sim.example.com".to_owned(),
    ));

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let seal_outbox = Arc::new(PgSealOutboxRepo::new(dal.clone()));
    let service = PassportService::new(
        passport_repo.clone(),
        identity,
        Arc::new(dpp_domain::PassthroughRegistry::new()) as Arc<dyn ComplianceRegistry>,
        Arc::new(PgAuditRepo::new(dal.clone())),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "MK".to_owned(),
        },
    )
    .with_seal_outbox(seal_outbox.clone());

    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");

    let first = service.publish(id, &auth()).await.expect("publish");
    let first_jws = first.jws_signature.clone().unwrap();

    let adapter = eideasy_adapter(eideasy_config(&base_url));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    drain_once(
        &outbox_dyn,
        &adapter,
        &mock_key_ref(),
        SealMode::ProviderSeal,
        TEST_LEVEL,
        10,
    )
    .await;

    // Suspend → publish again: the signing path runs afresh.
    service
        .suspend(
            id,
            &auth(),
            Some("re-publish for the seal simulation".into()),
        )
        .await
        .expect("suspend");
    let second = service.publish(id, &auth()).await.expect("re-publish");
    let second_jws = second.jws_signature.clone().unwrap();
    assert_ne!(first_jws, second_jws, "a re-publish must re-sign");

    let due = seal_outbox.due(10).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "the re-published signature needs its own attestation"
    );
    assert_eq!(
        due[0].payload_hash,
        hex::encode(Sha256::digest(second_jws.as_bytes()))
    );

    drain_once(
        &outbox_dyn,
        &adapter,
        &mock_key_ref(),
        SealMode::ProviderSeal,
        TEST_LEVEL,
        10,
    )
    .await;
    let counts = seal_outbox.status_counts().await.expect("counts");
    assert_eq!(counts.sealed, 2, "one seal per distinct signature");
    assert_eq!(
        mock.requests.lock().unwrap().len(),
        2,
        "exactly two billable calls — one per publish"
    );

    println!("\n═══ RE-PUBLISH ═══");
    println!(
        "first  jws digest : {}",
        hex::encode(Sha256::digest(first_jws.as_bytes()))
    );
    println!(
        "second jws digest : {}",
        hex::encode(Sha256::digest(second_jws.as_bytes()))
    );
    println!(
        "seals bought      : {} (one per signature)\n",
        counts.sealed
    );
}

/// The failure that looks exactly like a bad key: if anything ever re-serializes
/// the body between signing and sending, the provider rejects it. This proves the
/// simulation would actually catch that.
#[tokio::test]
async fn a_wrong_key_is_rejected_and_the_row_stays_pending() {
    let _pg = start_pg().await;
    let dal = _pg.dal.clone();
    let mock = Arc::new(MockState::default());
    let base_url = spawn_mock(mock.clone()).await;

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let seal_outbox = Arc::new(PgSealOutboxRepo::new(dal.clone()));

    let mut passport = draft_passport();
    passport.status = PassportStatus::Published;
    passport.jws_signature = Some("a.b.c".into());
    passport.retention_locked = true;
    passport.published_at = Some(Utc::now());
    let id = passport.id;
    passport_repo.create(passport).await.expect("create");

    let digest = hex::encode(Sha256::digest(b"a.b.c"));
    seal_outbox.enqueue(id, &digest).await.expect("enqueue");

    let mut bad = eideasy_config(&base_url);
    bad.hmac_key = zeroize::Zeroizing::new("the-wrong-key".to_owned());
    let adapter = eideasy_adapter(bad);
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();

    let stats = drain_once(
        &outbox_dyn,
        &adapter,
        &mock_key_ref(),
        SealMode::ProviderSeal,
        TEST_LEVEL,
        10,
    )
    .await;
    assert_eq!(stats.sealed, 0);
    assert_eq!(stats.retried, 1, "a rejected call must back off, not drop");
    assert_eq!(*mock.rejected.lock().unwrap(), 1);

    let counts = seal_outbox.status_counts().await.expect("counts");
    assert_eq!(counts.pending, 1, "the passport stays queued for a retry");

    let unsealed = passport_repo.find_by_id(id).await.unwrap().unwrap();
    assert!(
        unsealed.seal.is_none(),
        "a rejected call must never leave a seal on the passport"
    );
}

/// A real passport's seal says, out of its own bytes, that no provider issued it.
///
/// The question an operator asks before relying on anything: *is this seal worth
/// something?* Until now the only way to answer it was to read the node's
/// configuration — which records what the operator intended, not what came back.
/// `dpp_seal::qualification` answers it from the seal instead.
///
/// Everything here is the real path: real PostgreSQL, real Ed25519 publish, the
/// real outbox and drain, and the real local backend producing genuine detached
/// CAdES. The verdict is then read off the bytes that landed in the database.
///
/// No Trusted List is consulted, and that is deliberate rather than a shortcut —
/// a self-issued certificate is recognised as such before any list is reached, so
/// a node that cannot get to the network still knows its seals carry no legal
/// weight. The list lookups are exercised against real published lists in
/// `dpp_seal::qualification`'s own tests.
#[tokio::test]
async fn a_locally_sealed_passport_reports_that_no_provider_issued_it() {
    use dpp_seal::qualification::{IssuerStanding, qualify};
    use dpp_types::CreationDevice;

    let _pg = start_pg().await;
    let dal = _pg.dal.clone();

    let key_dir = tempfile::tempdir().expect("temp dir");
    let key_path = key_dir.path().join("keystore.json");
    let store = dpp_crypto::keystore::KeyStore::open(&key_path, "test-pass").expect("keystore");
    store.generate_key("root").expect("generate key");
    let identity = Arc::new(dpp_vc::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        "seal-sim.example.com".to_owned(),
    ));

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let seal_outbox = Arc::new(PgSealOutboxRepo::new(dal.clone()));
    let service = PassportService::new(
        passport_repo.clone(),
        identity,
        Arc::new(dpp_domain::PassthroughRegistry::new()) as Arc<dyn ComplianceRegistry>,
        Arc::new(PgAuditRepo::new(dal.clone())),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "MK".to_owned(),
        },
    )
    .with_seal_outbox(seal_outbox.clone())
    // Wired exactly as the composition root wires it, and unconditionally for
    // the same reason: reading a stored seal is not sealing.
    .with_seal_inspector(Arc::new(dpp_seal::CadesInspector::new()))
    // So the dossier an authority is handed can be generated and inspected.
    .with_evidence_store(Arc::new(dpp_dal::pg::PgEvidenceDossierRepo::new(
        dal.clone(),
    )));

    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");
    let published = service.publish(id, &auth()).await.expect("publish");
    let jws = published.jws_signature.clone().expect("publish signs");
    let expected_digest = hex::encode(Sha256::digest(jws.as_bytes()));

    // The local backend: a key and a self-signed certificate generated per node.
    let seal_dir = tempfile::tempdir().expect("temp dir");
    let backend =
        dpp_seal::local::LocalIdentity::load_or_create(seal_dir.path()).expect("identity");
    let adapter: Arc<dyn SealPort> = Arc::new(QtspSealAdapter::new(backend));

    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    let stats = drain_once(
        &outbox_dyn,
        &adapter,
        &dpp_domain::seal::SealCredentialRef {
            qtsp_id: dpp_seal::local::config::PROVIDER.to_owned(),
            credential_id: "node".to_owned(),
        },
        // What this backend actually offers: it seals on its own behalf, at
        // every baseline level.
        SealMode::OperatorSeal,
        SealConformanceLevel::BaselineLta,
        10,
    )
    .await;
    assert_eq!(stats.sealed, 1, "the drain must seal the queued row");

    let sealed = passport_repo
        .find_by_id(id)
        .await
        .expect("read back")
        .expect("passport exists");
    let seal = sealed.seal.clone().expect("seal landed on the passport");
    let der = BASE64
        .decode(&seal.seal_value)
        .expect("the seal is base64 DER");

    // ── The level the bytes actually evidence ───────────────────────────────
    //
    // Not the level that was requested, and not the one recorded on the
    // envelope: what `cades::evidenced_level` finds in the CAdES itself. This
    // is the assertion that makes the local backend a usable stand-in — a
    // sandbox run exercises the structure a provider's seal has, rather than a
    // `B-B` envelope that skips every path above it.
    assert_eq!(
        dpp_seal::cades::evidenced_level(&der).expect("readable"),
        Some(SealConformanceLevel::BaselineLta),
        "the local backend must emit the material an LTA seal carries, not merely claim the level"
    );

    // ── That the seal is bound to THIS passport, from its own bytes ─────────
    //
    // The question a demo has to be able to answer: not "is there a seal on this
    // passport" — anyone can store bytes in a column — but "does this seal
    // actually cover this passport's signature?"
    //
    // Answered here without consulting the outbox row that bought it. The seal
    // states what it covers in its own signed attributes, and the signature over
    // those attributes is checked before they are read, so the answer survives a
    // restore from backup and cannot be forged by editing the claim.
    let inspector = service
        .seal_inspector
        .as_ref()
        .expect("the inspector is wired");
    assert_eq!(
        inspector.binding(&seal, &expected_digest),
        dpp_types::SealBinding::CoversThisSignature,
        "the stored seal must demonstrably cover this passport's current signature"
    );
    // And the node's own record agrees, which is the cross-check: the bytes and
    // the bookkeeping describing the same thing is what makes either believable.
    assert_eq!(
        seal_outbox
            .sealed_digest(id)
            .await
            .expect("record")
            .as_deref(),
        Some(expected_digest.as_str())
    );
    // The level the route will serve, from the bytes rather than the record.
    assert_eq!(
        inspector.evidenced_level(&seal),
        Some(SealConformanceLevel::BaselineLta),
        "requested LTA and the bytes must carry LTA, or the seal route reports a downgrade"
    );
    assert_eq!(
        seal.conformance_level,
        Some(SealConformanceLevel::BaselineLta)
    );

    println!("binding   : coversThisSignature ({expected_digest})");

    // ── And the dossier an authority is actually handed says so ─────────────
    //
    // The dossier serves the seal beside the passport's *current* JWS. Those are
    // the same thing here, and are not always: a passport re-published after
    // sealing carries a seal over the previous signature until the drain catches
    // up. Pairing them silently would hand an authority a seal that does not
    // verify against the document beside it — which reads as tampering rather
    // than as the stale seal it is. So the dossier states the relationship.
    let record = service
        .generate_evidence(id, &auth())
        .await
        .expect("dossier generated");
    let seal_section = record
        .dossier
        .qualified_seal
        .clone()
        .expect("a sealed passport's dossier carries its seal");
    assert_eq!(
        seal_section["payloadHash"].as_str(),
        Some(expected_digest.as_str())
    );
    assert_eq!(
        seal_section["binding"]["result"].as_str(),
        Some("coversThisSignature"),
        "the dossier must say whether the seal covers the JWS it serves beside it: {seal_section}"
    );

    // And verifying that dossier **checks** the claim rather than reading it
    // back. The generator's `binding` says what it believed; the verifier
    // recomputes the digest from `signedOverJws` and opens the seal itself, so
    // this is the whole chain closing on a file that needs no database, no node
    // and no network to check.
    let report = service
        .verify_evidence(record.id)
        .await
        .expect("dossier verifies");
    let seal_check = report
        .checks
        .iter()
        .find(|c| c.name == "qualified_seal")
        .expect("the verifier runs a seal check");
    assert!(
        matches!(seal_check.status, dpp_types::evidence::CheckStatus::Pass),
        "the dossier's own seal must check out: {:?}",
        seal_check.status
    );
    // The two facts that decide whether anything else in that section carries
    // weight, and which used to be recoverable only by parsing the CAdES by hand.
    assert_eq!(
        seal_section["origin"]["selfIssued"].as_bool(),
        Some(true),
        "a dossier must say on its face that its seal was signed by the node itself"
    );
    assert_eq!(
        seal_section["evidencedLevel"].as_str(),
        Some("baseline-lta"),
        "and what the bytes actually carry: {seal_section}"
    );

    // A third party's statement of when this was sealed, checked rather than
    // read: the token's signature holds and its imprint covers this signature.
    let attested = inspector
        .attested_sealing_time(&seal)
        .expect("an LTA seal carries a timestamp this node can check");
    assert!(
        (chrono::Utc::now() - attested).num_seconds().abs() < 300,
        "the attested time should be about now: {attested}"
    );
    assert_eq!(
        seal_section["attestedSealedAt"].as_str().is_some(),
        true,
        "and the dossier must carry it: {seal_section}"
    );
    println!("attested  : {attested}");

    // The archival protection a fresh LTA seal carries, and the date it has to
    // be renewed by. The level alone would say `baseline-lta` for ever.
    let dpp_types::ArchivalFreshness::Current { expires } =
        inspector.archival_freshness(&seal, chrono::Utc::now())
    else {
        panic!("a freshly archived seal is current");
    };
    assert!(expires > chrono::Utc::now());
    assert_eq!(
        seal_section["archival"]["state"].as_str(),
        Some("current"),
        "and the dossier must stamp it: {seal_section}"
    );
    println!("archival  : current until {expires}");

    println!("dossier   : qualified_seal = Pass");

    // ── The verdict, read out of the stored seal ────────────────────────────
    let verdict = qualify(&der, &[], seal.sealed_at).expect("a readable CAdES seal");

    println!("\n═══ QUALIFICATION OF THE STORED SEAL ═══");
    println!("passportId : {id}");
    println!("verdict    : {verdict}");

    let IssuerStanding::SelfIssued { subject } = &verdict.issuer else {
        panic!("the local backend is self-signed: {:?}", verdict.issuer);
    };
    assert!(!subject.is_empty(), "and the certificate names itself");
    assert!(
        !verdict.is_provider_seal(),
        "no provider stands behind this passport's seal"
    );
    assert_eq!(
        verdict.creation_device,
        CreationDevice::NotAQualifiedCertificate,
        "and the certificate makes no Annex III(j) claim about where its key lives"
    );

    // The backend's own verdict says the same thing from the other direction:
    // the bytes check out, and that is the whole of what they prove. The two
    // must not be able to disagree — a seal that verified *and* reported a
    // provider behind it would be the failure this pair exists to make visible.
    let verification = adapter.verify(&seal).await.expect("verifiable");
    assert_eq!(
        verification.checks,
        dpp_domain::seal::SealChecks::SignatureOnly
    );
    assert!(
        !verification.is_qualified_pass(),
        "a self-signed development seal is never a qualified pass"
    );

    // ── What the seal read route will serve ─────────────────────────────────
    //
    // The same finding reached the way the HTTP handler reaches it: off the
    // service's inspector, over the envelope as stored. This pins the service
    // wiring and the value; the response's own shape is pinned by the OpenAPI
    // contract gate, and the handler between them is a single `and_then`.
    let served = service
        .seal_inspector
        .as_ref()
        .expect("the inspector is wired")
        .origin(&seal)
        .expect("a readable CAdES seal");

    assert!(
        served.self_issued,
        "the seal route must report that nothing issued this certificate"
    );
    assert_eq!(served.issuer, served.subject);
    assert_eq!(
        served.creation_device,
        CreationDevice::NotAQualifiedCertificate
    );

    println!(
        "origin    : selfIssued={} issuer={}",
        served.self_issued, served.issuer
    );

    // ── The certificate's own standing, end to end ──────────────────────────
    //
    // Art. 32(1)(b)'s second limb, against a seal this workspace actually
    // produced rather than a fixture. It exercises the whole revocation path:
    // the local backend emits a real, signed, empty CRL under its own name at
    // `B-LTA`, so reaching `notRevoked` means the list was matched to the
    // certificate's issuer *and* its signature verified — a CRL that failed
    // either check would report `unusable`, and one that was absent
    // `notAvailable`.
    let standing = service
        .seal_inspector
        .as_ref()
        .expect("the inspector is wired")
        .certificate_standing(&seal, Utc::now())
        .expect("a readable CAdES seal");

    assert_eq!(
        standing.validity.standing,
        dpp_types::WindowStanding::Inside,
        "a seal made moments ago is inside its certificate's window"
    );
    match standing.revocation {
        dpp_types::RevocationStanding::NotRevoked { as_of } => {
            assert!(
                (Utc::now() - as_of).num_minutes().abs() < 5,
                "the CRL the local backend embeds speaks for right now"
            );
        }
        other => panic!("the local backend's own CRL must be usable, got {other:?}"),
    }

    // And the verdict over all of it. Everything this node can check passes,
    // and the answer is still `indeterminate` — the chain is not validated to a
    // trust anchor, so `TOTAL-PASSED` is not reachable and the type cannot
    // express it. A development seal reporting a pass is exactly the confusion
    // this whole surface is arranged to prevent.
    let binding = service
        .seal_inspector
        .as_ref()
        .expect("the inspector is wired")
        .binding(&seal, &expected_digest);
    let status = dpp_types::SealValidationStatus::of(&binding, Some(&standing));
    assert_eq!(
        status.indication,
        dpp_types::ValidationIndication::Indeterminate
    );
    assert_eq!(
        status.sub_indication, None,
        "nothing failed, so no table 6 value applies"
    );

    println!(
        "certificate: window={:?} revocation={:?}",
        standing.validity.standing, standing.revocation
    );
}

/// **A seal corrupted at rest is found, repaired, and the replacement binds.**
///
/// The whole loop the audit and the repair route exist for, against real
/// Postgres. Corruption at rest is the failure this addresses — a bad restore, a
/// truncated column, a disk that lied — and it is invisible to every count the
/// node reports, because those ask whether a seal is *present* and a corrupt one
/// is.
///
/// The corruption is applied with raw SQL on purpose. Going through
/// `mark_sealed` would write a well-formed envelope and close a row, which is
/// the one thing that cannot produce the state under test; the point is a
/// passport whose stored bytes changed underneath the node.
#[tokio::test]
async fn a_seal_corrupted_at_rest_is_found_and_repaired() {
    use dpp_types::SealInspector as _;

    let _pg = start_pg().await;
    let dal = _pg.dal.clone();

    let key_dir = tempfile::tempdir().expect("temp dir");
    let store =
        dpp_crypto::keystore::KeyStore::open(&key_dir.path().join("keystore.json"), "test-pass")
            .expect("keystore");
    store.generate_key("root").expect("generate key");
    let identity = Arc::new(dpp_vc::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        "seal-sim.example.com".to_owned(),
    ));

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let seal_outbox = Arc::new(PgSealOutboxRepo::new(dal.clone()));
    let service = PassportService::new(
        passport_repo.clone(),
        identity,
        Arc::new(dpp_domain::PassthroughRegistry::new()) as Arc<dyn ComplianceRegistry>,
        Arc::new(PgAuditRepo::new(dal.clone())),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "MK".to_owned(),
        },
    )
    .with_seal_outbox(seal_outbox.clone())
    .with_seal_inspector(Arc::new(dpp_seal::CadesInspector::new()));

    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");
    let published = service.publish(id, &auth()).await.expect("publish");
    let expected_digest = hex::encode(Sha256::digest(
        published.jws_signature.as_ref().expect("signed").as_bytes(),
    ));

    let seal_dir = tempfile::tempdir().expect("temp dir");
    let backend =
        dpp_seal::local::LocalIdentity::load_or_create(seal_dir.path()).expect("identity");
    let adapter: Arc<dyn SealPort> = Arc::new(QtspSealAdapter::new(backend));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    let key_ref = dpp_domain::seal::SealCredentialRef {
        qtsp_id: dpp_seal::local::config::PROVIDER.to_owned(),
        credential_id: "node".to_owned(),
    };
    let drained = drain_once(
        &outbox_dyn,
        &adapter,
        &key_ref,
        SealMode::OperatorSeal,
        SealConformanceLevel::BaselineLta,
        10,
    )
    .await;
    assert_eq!(drained.sealed, 1);

    let inspector = dpp_seal::CadesInspector::new();
    let sound = passport_repo
        .find_by_id(id)
        .await
        .unwrap()
        .unwrap()
        .seal
        .expect("sealed");
    assert_eq!(
        inspector.binding(&sound, &expected_digest),
        dpp_types::SealBinding::CoversThisSignature
    );

    // ── Corrupt it where it lies ────────────────────────────────────────────
    //
    // One byte of the signature flipped, re-encoded. The structure survives, so
    // the seal still parses and reaches the signature check — which is what
    // makes this `broken` rather than `unreadable`, and the two are treated very
    // differently downstream.
    let corrupted = {
        use der::{Decode as _, Encode as _};
        let bytes = BASE64.decode(&sound.seal_value).expect("base64");
        let info = cms::content_info::ContentInfo::from_der(&bytes).expect("CMS");
        let mut sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
        let mut signers = sd.signer_infos.0.as_slice().to_vec();
        let mut sig = signers[0].signature.as_bytes().to_vec();
        let last = sig.len() - 1;
        sig[last] ^= 0xff;
        signers[0].signature = der::asn1::OctetString::new(sig).expect("octets");
        let mut set = der::asn1::SetOfVec::new();
        set.insert(signers.remove(0)).expect("signer");
        sd.signer_infos = cms::signed_data::SignerInfos::from(set);
        BASE64.encode(
            cms::content_info::ContentInfo {
                content_type: info.content_type,
                content: der::Any::encode_from(&sd).expect("encode"),
            }
            .to_der()
            .expect("re-encode"),
        )
    };
    sqlx::query("UPDATE odal.passport SET doc = jsonb_set(doc, '{seal,sealValue}', $1::jsonb) WHERE id = $2")
        .bind(serde_json::to_string(&corrupted).expect("json"))
        .bind(id.0)
        .execute(dal.pool())
        .await
        .expect("corrupt the stored seal");

    // ── Every existing count still calls it healthy ─────────────────────────
    assert_eq!(
        seal_outbox.unsealed_published_count().await.unwrap(),
        0,
        "the count asks whether a seal is present, and a corrupt one is"
    );

    // ── The audit finds it ──────────────────────────────────────────────────
    let (audit, _) =
        dpp_node::infra::seal_drain::audit_seals_once(&outbox_dyn, &inspector, 100, None, None)
            .await;
    assert_eq!(audit.broken, 1, "the audit must see what the counts cannot");
    assert_eq!(audit.broken_passports, vec![id], "and name it");

    // ── Repair: re-arm the sealed row, then drain ───────────────────────────
    //
    // This is the step that spends money, and the one `enqueue` refuses: the row
    // is `sealed`, so the ordinary path leaves it alone.
    seal_outbox
        .enqueue(id, &expected_digest)
        .await
        .expect("enqueue is a no-op here");
    assert_eq!(
        seal_outbox.status_counts().await.unwrap().pending,
        0,
        "enqueue must NOT move a sealed row — that guarantee is what makes the sweep safe"
    );

    assert!(
        seal_outbox
            .rearm_sealed(id, &expected_digest, "test: stored seal did not verify")
            .await
            .expect("rearm"),
        "the repair path does move it"
    );

    let repaired = drain_once(
        &outbox_dyn,
        &adapter,
        &key_ref,
        SealMode::OperatorSeal,
        SealConformanceLevel::BaselineLta,
        10,
    )
    .await;
    assert_eq!(repaired.sealed, 1, "the replacement was bought");

    let after = passport_repo
        .find_by_id(id)
        .await
        .unwrap()
        .unwrap()
        .seal
        .expect("sealed");
    assert_eq!(
        inspector.binding(&after, &expected_digest),
        dpp_types::SealBinding::CoversThisSignature,
        "and it covers the same signature the broken one was meant to"
    );
    assert_ne!(
        after.seal_value, corrupted,
        "the corrupt bytes are gone, not merely re-marked"
    );

    let (clean, _) =
        dpp_node::infra::seal_drain::audit_seals_once(&outbox_dyn, &inspector, 100, None, None)
            .await;
    assert_eq!(clean.broken, 0, "and the audit agrees it is fixed");
}

/// `rearm_sealed` moves **only** `sealed` rows.
///
/// The guard that keeps the repair path from becoming a way to disturb rows the
/// drain owns. A `pending` row re-armed underneath the drain would have its
/// backoff reset on every call, turning a failing row into a hot loop — which is
/// the reasoning `enqueue` already gives for refusing the same thing.
#[tokio::test]
async fn rearm_sealed_leaves_rows_the_drain_owns_alone() {
    let _pg = start_pg().await;
    let outbox = PgSealOutboxRepo::new(_pg.dal.clone());
    // A real passport: `seal_outbox.passport_id` carries a foreign key, so a
    // row cannot be queued for an id nothing owns.
    let passport_repo = PgPassportRepo::new(_pg.dal.clone());
    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");
    let digest = "ab".repeat(32);

    outbox.enqueue(id, &digest).await.expect("queue");
    assert_eq!(outbox.status_counts().await.unwrap().pending, 1);

    assert!(
        !outbox
            .rearm_sealed(id, &digest, "should not apply")
            .await
            .expect("rearm"),
        "a pending row is the drain's, and must not be re-armed underneath it"
    );
    assert_eq!(
        outbox.status_counts().await.unwrap().pending,
        1,
        "and it is still exactly where it was"
    );
}

/// A minimal envelope, to close a row.
///
/// Nothing reads these bytes: the test below is about what the *row* records,
/// and the seal-reading path has its own suites against real CAdES.
fn envelope_for_a_closed_row() -> dpp_domain::seal::SealedEnvelope {
    dpp_domain::seal::SealedEnvelope {
        format: dpp_domain::seal::SealFormat::Cades,
        seal_value: "BASE64-NOT-READ-HERE".into(),
        signing_cert_ref: None,
        conformance_level: None,
        sealed_at: Utc::now(),
        placeholder: false,
    }
}

/// **A re-armed row says why it was re-armed, on the row.**
///
/// This is the one place the node buys a seal for a digest it has already paid
/// for, and the reason is written onto the row rather than only logged. A log
/// line is the wrong home for it: logs rotate, and the question this answers —
/// *why does this passport have two seal rows for one signature* — is asked
/// months later by whoever is reconciling an invoice, against the database.
///
/// It also survives the drain: `message` is what the row carries until an
/// attempt overwrites it, so the record is legible for as long as the repair is
/// outstanding, which is when anyone would look.
#[tokio::test]
async fn a_rearmed_row_records_why_it_was_rearmed() {
    let _pg = start_pg().await;
    let outbox = PgSealOutboxRepo::new(_pg.dal.clone());
    let passport_repo = PgPassportRepo::new(_pg.dal.clone());
    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");
    let digest = "cd".repeat(32);

    outbox.enqueue(id, &digest).await.expect("queue");
    let row = outbox
        .due(10)
        .await
        .expect("due")
        .into_iter()
        .find(|r| r.passport_id == id)
        .expect("the queued row is due");
    outbox
        .mark_sealed(row.id, &envelope_for_a_closed_row())
        .await
        .expect("close the row");

    let reason = "repaired by user-ops: stored seal did not verify";
    assert!(
        outbox
            .rearm_sealed(id, &digest, reason)
            .await
            .expect("rearm"),
        "a sealed row is the one thing this moves"
    );

    let message: Option<String> =
        sqlx::query_scalar("SELECT message FROM odal.seal_outbox WHERE passport_id = $1")
            .bind(id.0)
            .fetch_one(_pg.dal.pool())
            .await
            .expect("read the row back");
    assert_eq!(
        message.as_deref(),
        Some(reason),
        "the row must carry the reason a second seal is being bought"
    );

    // And the retry state was reset, or the replacement would inherit the
    // backoff of a row that had already succeeded.
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM odal.seal_outbox WHERE passport_id = $1")
            .bind(id.0)
            .fetch_one(_pg.dal.pool())
            .await
            .expect("read attempts");
    assert_eq!(attempts, 0);
}

/// **A completed pass survives a restart, and so does an unfinished one.**
///
/// Both halves matter for different reasons. The report is what the operator
/// surface serves, and without it a restart makes the node say "no pass has
/// completed" for a whole walk — hours on a large estate, and indistinguishable
/// from an audit that is not running. The *position* is the one that saves a
/// node whose estate takes longer to walk than it goes between restarts: without
/// it, such a node starts from the beginning for ever and publishes nothing at
/// all, while doing every bit of the work.
#[tokio::test]
async fn an_audit_walk_and_its_last_report_outlive_the_process() {
    use dpp_types::SealAuditStore as _;

    let _pg = start_pg().await;
    let store = dpp_dal::pg::PgSealAuditRepo::new(_pg.dal.clone());

    // A node that has never finished a walk reports neither — the state the
    // route renders as `audit: null`.
    let (progress, report) = store.load().await.expect("load");
    assert!(progress.is_none() && report.is_none());

    let started = Utc::now();
    let id = PassportId::new();
    store
        .save_progress(&dpp_types::SealAuditProgress {
            started_at: started,
            cursor: Some(id),
            checked: 600,
            sound: 598,
            superseded: 1,
            broken: 1,
            certificate_failed: 0,
            unreadable: 0,
            broken_passports: vec![id],
        })
        .await
        .expect("save progress");

    let (progress, report) = store.load().await.expect("load");
    let progress = progress.expect("the walk is still in flight");
    assert_eq!(progress.cursor, Some(id), "a restart resumes, not restarts");
    assert_eq!(progress.checked, 600, "and keeps the totals it had counted");
    assert_eq!(
        progress.started_at.timestamp(),
        started.timestamp(),
        "including the moment the walk began, which bounds what it is about"
    );
    assert!(
        report.is_none(),
        "a walk in flight is not a result — publishing a partial count would read \
         exactly like a complete one"
    );

    // Completing publishes the report and clears the walk.
    let completed = dpp_types::SealAuditReport {
        completed_at: Utc::now(),
        checked: 1200,
        sound: 1198,
        superseded: 1,
        broken: 1,
        certificate_failed: 0,
        unreadable: 0,
        truncated: false,
        broken_passports: vec![id],
    };
    store.complete(&completed).await.expect("complete");

    let (progress, report) = store.load().await.expect("load");
    assert!(
        progress.is_none(),
        "a finished walk must not be resumable, or a restart would 'continue' from \
         its own end and publish a second report having checked nothing"
    );
    let report = report.expect("the completed pass is served after a restart");
    assert_eq!(report.checked, 1200);
    assert_eq!(report.broken_passports, vec![id], "and still names them");
}

/// **A pass describes the seals that existed when it started.**
///
/// Seals land while a walk runs, and which of them a pass happens to see would
/// otherwise depend on where its cursor had reached — so two consecutive passes
/// disagree for reasons that have nothing to do with the seals. The bound makes
/// the population nameable. It costs no coverage: the drain checks a seal's
/// binding before accepting it, so one written mid-walk was verified as it
/// landed, and the next pass covers it anyway.
#[tokio::test]
async fn a_walk_skips_seals_written_after_it_began() {
    let _pg = start_pg().await;
    let outbox = PgSealOutboxRepo::new(_pg.dal.clone());
    let passport_repo = PgPassportRepo::new(_pg.dal.clone());

    // Two sealed passports, both closed through the outbox exactly as the drain
    // closes them.
    let mut ids = Vec::new();
    for _ in 0..2 {
        let draft = draft_passport();
        let id = draft.id;
        passport_repo.create(draft).await.expect("create draft");
        // Published with a signature, or the walk's own query skips it.
        sqlx::query(
            "UPDATE odal.passport SET published_at = now(),
               doc = jsonb_set(doc, '{jwsSignature}', '\"header.payload.sig\"'::jsonb, true)
             WHERE id = $1",
        )
        .bind(id.0)
        .execute(_pg.dal.pool())
        .await
        .expect("publish");
        let digest = dpp_types::digest_for_jws("header.payload.sig");
        outbox.enqueue(id, &digest).await.expect("queue");
        let row = outbox
            .due(10)
            .await
            .expect("due")
            .into_iter()
            .find(|r| r.passport_id == id)
            .expect("queued row is due");
        outbox
            .mark_sealed(row.id, &envelope_for_a_closed_row())
            .await
            .expect("seal");
        ids.push(id);
    }

    let unbounded = outbox
        .sealed_passports(10, None, None)
        .await
        .expect("walk everything");
    assert_eq!(unbounded.len(), 2, "both seals exist");

    // A walk that started before either was sealed sees neither.
    let bounded = outbox
        .sealed_passports(10, None, Some(Utc::now() - chrono::Duration::hours(1)))
        .await
        .expect("bounded walk");
    assert!(
        bounded.is_empty(),
        "seals written after the walk began are not this pass's business"
    );

    // And one that started now sees both, because both predate it.
    let after = outbox
        .sealed_passports(10, None, Some(Utc::now() + chrono::Duration::seconds(1)))
        .await
        .expect("bounded walk");
    assert_eq!(after.len(), 2);

    // A seal that cannot be dated is kept rather than skipped: not knowing when
    // something was sealed is not a reason to stop looking at it.
    //
    // Produced by clearing the row's `sealed_at` rather than removing the row,
    // because the app role deliberately holds no DELETE on this table — the row
    // is the record that a seal was bought. A seal written before the outbox
    // carried timestamps arrives in exactly this state.
    sqlx::query("UPDATE odal.seal_outbox SET sealed_at = NULL WHERE passport_id = $1")
        .bind(ids[0].0)
        .execute(_pg.dal.pool())
        .await
        .expect("undate the seal");
    let orphaned = outbox
        .sealed_passports(10, None, Some(Utc::now() - chrono::Duration::hours(1)))
        .await
        .expect("bounded walk");
    assert_eq!(
        orphaned.len(),
        1,
        "an undateable seal stays in the walk: {orphaned:?}"
    );
    assert_eq!(orphaned[0].passport_id, ids[0]);
}

/// **A seal whose certificate was not valid when it was made is found by the
/// audit, and is not called broken.**
///
/// The condition #329 was filed for. The signature holds and the seal covers its
/// passport perfectly — every count the node reports says healthy — while the
/// certificate that made it had expired before the attested moment, which
/// ETSI EN 319 102-1 reports as `TOTAL-FAILED`.
///
/// The tamper is the cheapest one that produces the state: the seal
/// certificate's validity window is moved into the past. **The CMS signature
/// does not break**, because it covers the signed attributes and not the
/// certificate travelling beside them — the same asymmetry that lets a
/// relabelled issuer through, one field along.
///
/// Counted apart from `broken` on purpose: a broken seal is worth replacing, and
/// this one is not, since the replacement would come from the same certificate.
#[tokio::test]
async fn a_seal_made_under_an_invalid_certificate_is_found_and_not_called_broken() {
    use der::{Decode as _, Encode as _};
    use dpp_types::SealInspector as _;

    let _pg = start_pg().await;
    let dal = _pg.dal.clone();

    let key_dir = tempfile::tempdir().expect("temp dir");
    let store =
        dpp_crypto::keystore::KeyStore::open(&key_dir.path().join("keystore.json"), "test-pass")
            .expect("keystore");
    store.generate_key("root").expect("generate key");
    let identity = Arc::new(dpp_vc::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        "seal-sim.example.com".to_owned(),
    ));

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let seal_outbox = Arc::new(PgSealOutboxRepo::new(dal.clone()));
    let service = PassportService::new(
        passport_repo.clone(),
        identity,
        Arc::new(dpp_domain::PassthroughRegistry::new()) as Arc<dyn ComplianceRegistry>,
        Arc::new(PgAuditRepo::new(dal.clone())),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "MK".to_owned(),
        },
    )
    .with_seal_outbox(seal_outbox.clone())
    .with_seal_inspector(Arc::new(dpp_seal::CadesInspector::new()));

    let draft = draft_passport();
    let id = draft.id;
    passport_repo.create(draft).await.expect("create draft");
    let published = service.publish(id, &auth()).await.expect("publish");
    let expected_digest = hex::encode(Sha256::digest(
        published.jws_signature.as_ref().expect("signed").as_bytes(),
    ));

    let seal_dir = tempfile::tempdir().expect("temp dir");
    let backend =
        dpp_seal::local::LocalIdentity::load_or_create(seal_dir.path()).expect("identity");
    let adapter: Arc<dyn SealPort> = Arc::new(QtspSealAdapter::new(backend));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    let key_ref = dpp_domain::seal::SealCredentialRef {
        qtsp_id: dpp_seal::local::config::PROVIDER.to_owned(),
        credential_id: "node".to_owned(),
    };
    // LTA, so the seal carries a timestamp: without an attested moment the same
    // certificate would be `indeterminate` rather than a finding, which is the
    // distinction the audit relies on.
    assert_eq!(
        drain_once(
            &outbox_dyn,
            &adapter,
            &key_ref,
            SealMode::OperatorSeal,
            SealConformanceLevel::BaselineLta,
            10,
        )
        .await
        .sealed,
        1
    );

    // ── Move the certificate's window into the past ─────────────────────────
    let sound = passport_repo
        .find_by_id(id)
        .await
        .unwrap()
        .unwrap()
        .seal
        .expect("sealed");
    let backdated = {
        let bytes = BASE64.decode(&sound.seal_value).expect("base64");
        let info = cms::content_info::ContentInfo::from_der(&bytes).expect("CMS");
        let mut sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
        let certs = sd.certificates.as_ref().expect("a certificate");
        let mut choices = certs.0.as_slice().to_vec();
        let cms::cert::CertificateChoices::Certificate(cert) = &mut choices[0] else {
            panic!("the local backend embeds an X.509 certificate");
        };
        let secs = |days: i64| {
            std::time::Duration::from_secs(
                u64::try_from(Utc::now().timestamp() - days * 86_400).expect("after 1970"),
            )
        };
        cert.tbs_certificate.validity = x509_cert::time::Validity {
            not_before: x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(secs(730)).expect("a date"),
            ),
            not_after: x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(secs(365)).expect("a date"),
            ),
        };
        let mut set = der::asn1::SetOfVec::new();
        set.insert(choices.remove(0)).expect("certificate");
        sd.certificates = Some(cms::signed_data::CertificateSet(set));
        BASE64.encode(
            cms::content_info::ContentInfo {
                content_type: info.content_type,
                content: der::Any::encode_from(&sd).expect("encode"),
            }
            .to_der()
            .expect("re-encode"),
        )
    };
    sqlx::query("UPDATE odal.passport SET doc = jsonb_set(doc, '{seal,sealValue}', $1::jsonb) WHERE id = $2")
        .bind(serde_json::to_string(&backdated).expect("json"))
        .bind(id.0)
        .execute(dal.pool())
        .await
        .expect("backdate the stored certificate");

    // ── Every existing signal still says healthy ────────────────────────────
    let inspector = dpp_seal::CadesInspector::new();
    let stored = passport_repo
        .find_by_id(id)
        .await
        .unwrap()
        .unwrap()
        .seal
        .expect("sealed");
    assert_eq!(
        inspector.binding(&stored, &expected_digest),
        dpp_types::SealBinding::CoversThisSignature,
        "the signature still holds — that is what makes this invisible"
    );
    assert_eq!(seal_outbox.unsealed_published_count().await.unwrap(), 0);

    // ── The audit sees it, and files it apart from broken ───────────────────
    let (audit, _) =
        dpp_node::infra::seal_drain::audit_seals_once(&outbox_dyn, &inspector, 100, None, None)
            .await;
    assert_eq!(
        audit.certificate_failed, 1,
        "the certificate was not valid at the attested moment"
    );
    assert_eq!(
        audit.broken, 0,
        "and this is not a broken seal: replacing it would buy another from the same certificate"
    );
    assert_eq!(audit.sound, 0, "nor is it sound");

    // ── And the verdict says which, in the standard's words ─────────────────
    let standing = inspector
        .certificate_standing(&stored, Utc::now())
        .expect("readable");
    let status = dpp_types::SealValidationStatus::of(
        &inspector.binding(&stored, &expected_digest),
        Some(&standing),
    );
    assert_eq!(
        status.indication,
        dpp_types::ValidationIndication::TotalFailed
    );
    assert_eq!(
        status.sub_indication,
        Some(dpp_types::ValidationSubIndication::Expired),
        "an attested time proves the seal was made after the window closed"
    );
}
