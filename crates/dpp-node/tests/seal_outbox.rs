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
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use dpp_dal::pg::{PgAuditRepo, PgDal, PgPassportRepo, PgSealOutboxRepo, sqlx};
use dpp_domain::domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::domain::sector::Sector;
use dpp_domain::domain::status::PassportStatus;
use dpp_domain::ports::compliance::ComplianceRegistry;
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::ports::seal::SealPort;
use dpp_domain::{GhostArchive, GhostRegistrySync};
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

    let mut mac = HmacSha256::new_from_slice(MOCK_KEY.as_bytes()).unwrap();
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

async fn start_pg() -> (PgDal, testcontainers::ContainerAsync<GenericImage>) {
    let image = GenericImage::new("postgres", "17")
        .with_exposed_port(ContainerPort::Tcp(5432))
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "test")
        .with_env_var("POSTGRES_DB", "odal");

    let container = image.start().await.expect("start postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let admin_url = format!("postgres://postgres:test@127.0.0.1:{port}/odal");

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("admin connect");
    sqlx::query("CREATE ROLE odal_app LOGIN PASSWORD 'test'")
        .execute(&admin)
        .await
        .expect("create app role");
    PgDal::migrate(&admin_url).await.expect("apply migrations");

    let app_url = format!("postgres://odal_app:test@127.0.0.1:{port}/odal");
    let dal = PgDal::connect(&app_url).await.expect("app connect");
    (dal, container)
}

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
        product_name: "Seal Simulation Battery".into(),
        sector: Sector::Battery,
        manufacturer: ManufacturerInfo {
            name: "Odal Simulation GmbH".into(),
            address: "Skopje, MK".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        sector_data: None,
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        // Battery is an in-force sector, so publish refuses without the Annex III
        // registry identity. Set here because the simulation has no operator
        // config to backfill from — the gate itself is correct and stays armed.
        operator_identifier: Some("LEI:529900T8BM49AURSDO55".into()),
        facility: Some(dpp_domain::domain::passport::FacilitySnapshot {
            scheme: "gln".into(),
            value: "4035600210708".into(),
            name: "Odal Simulation Plant".into(),
            country: "MK".into(),
            address: Some("Skopje, MK".into()),
        }),
        seal: None,
    }
}

fn eideasy_config(base_url: &str) -> dpp_seal::EideasyConfig {
    dpp_seal::EideasyConfig {
        base_url: base_url.to_owned(),
        environment: dpp_seal::EideasyEnvironment::Sandbox,
        client_id: MOCK_CLIENT_ID.to_owned(),
        hmac_key: zeroize::Zeroizing::new(MOCK_KEY.to_owned()),
        signature_profile: "CAdES_BASELINE_T".to_owned(),
        request_timeout: std::time::Duration::from_secs(10),
    }
}

// ─── The loop ─────────────────────────────────────────────────────────────────

/// Publish a real passport, let the real drain seal it against the mock, and
/// print every record produced along the way.
#[tokio::test]
async fn publish_then_drain_seals_the_passport_end_to_end() {
    let (dal, _pg) = start_pg().await;
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
    let adapter: Arc<dyn SealPort> =
        Arc::new(QtspSealAdapter::eideasy(eideasy_config(&base_url)).expect("build adapter"));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    let stats = drain_once(&outbox_dyn, &adapter, MOCK_CLIENT_ID, 10).await;
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
    assert_eq!(seal.format, dpp_domain::ports::seal::SealFormat::Cades);
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

    let stats2 = drain_once(&outbox_dyn, &adapter, MOCK_CLIENT_ID, 10).await;
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
    let (dal, _pg) = start_pg().await;
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

    let adapter: Arc<dyn SealPort> =
        Arc::new(QtspSealAdapter::eideasy(eideasy_config(&base_url)).expect("build adapter"));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();
    drain_once(&outbox_dyn, &adapter, MOCK_CLIENT_ID, 10).await;

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

    drain_once(&outbox_dyn, &adapter, MOCK_CLIENT_ID, 10).await;
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
    let (dal, _pg) = start_pg().await;
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
    let adapter: Arc<dyn SealPort> =
        Arc::new(QtspSealAdapter::eideasy(bad).expect("build adapter"));
    let outbox_dyn: Arc<dyn SealOutbox> = seal_outbox.clone();

    let stats = drain_once(&outbox_dyn, &adapter, MOCK_CLIENT_ID, 10).await;
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
