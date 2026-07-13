//! Smoke tests for `dpp-node` — the assembled single-binary MVP.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-node --features integration-tests -- --nocapture
//! ```
//!
//! Tier 1 — No DB required: health endpoints + auth middleware (no DB access).
//! Tier 2 — Full DPP lifecycle through the assembled node (requires Docker).

#![cfg(feature = "integration-tests")]

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use base64::Engine as _;
use dpp_crypto::identity::LocalIdentityService;
use dpp_crypto::keystore::KeyStore;
use dpp_dal::pg::{
    PgApiKeyRepo, PgAuditRepo, PgDal, PgEvidenceDossierRepo, PgOperatorConfigRepo, PgPassportRepo,
    PgRegistryIdentityRepo, PgTransferRepo, PgWebhookRepo, sqlx,
};
use dpp_domain::domain::passport::PassportRef;
use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync,
    compliance::passthrough_registry::PassthroughRegistry,
};
use dpp_identity_service::state::AppState as IdentityState;
use dpp_integrator::{infra::vault_client::VaultHttpClient, state::AppState as IntegratorState};
use dpp_node::infra::pg_job_store::PgJobStore;
use dpp_types::auth::{AuthContext, AuthError, AuthProvider};
use dpp_vault::domain::verify::{RefUnverifiable, RefVerification, verify_ref};
use dpp_vault::{
    domain::{
        api_key_service::ApiKeyService, operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService, service::PassportService,
        webhook_service::WebhookService,
    },
    state::{AppState as VaultState, DbPing},
};
use sha2::{Digest, Sha256};

/// Test-only auth provider: accepts the unsigned dev JWTs minted by `make_jwt`
/// (structural + `exp` checks only). The shipped node uses real API-key /
/// local-admin auth; this lets the smoke tests drive authenticated routes
/// without seeding keys. Single-tenant: no operator scope.
struct TestAuthProvider;

#[async_trait]
impl AuthProvider for TestAuthProvider {
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(AuthError::Invalid("not a three-part JWT".to_owned()));
        }
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AuthError::Invalid("base64 decode failed".to_owned()))?;
        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| AuthError::Invalid("payload is not valid JSON".to_owned()))?;
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64())
            && chrono::Utc::now().timestamp() > exp
        {
            return Err(AuthError::Invalid("token expired".to_owned()));
        }
        Ok(AuthContext {
            user_id: claims
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("test-user")
                .to_owned(),
            scope: dpp_types::api_key::ApiKeyScope::Admin,
            key_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// DB setup helpers
// ---------------------------------------------------------------------------

async fn start_pg() -> (PgDal, testcontainers::ContainerAsync<GenericImage>) {
    let image = GenericImage::new("postgres", "17")
        .with_exposed_port(ContainerPort::Tcp(5432))
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        // POSTGRES_USER/PASSWORD/DB are the official Postgres image's required
        // env vars for this throwaway testcontainer — NOT the app's
        // DATABASE_POSTGRES_PASS / DATABASE_APP_PASS scheme.
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

// ---------------------------------------------------------------------------
// Node factory helpers
// ---------------------------------------------------------------------------

struct PgPing(PgDal);

#[async_trait]
impl DbPing for PgPing {
    async fn ping(&self) -> anyhow::Result<()> {
        self.0
            .ping()
            .await
            .map_err(|e: DppError| anyhow::anyhow!("{e}"))
    }
}

async fn start_node_with_dal(dal: PgDal) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let audit_repo = Arc::new(PgAuditRepo::new(dal.clone()));
    let operator_repo = Arc::new(PgOperatorConfigRepo::new(dal.clone()));
    // Seed a complete operator so the publish-completeness gate passes. The node
    // smoke tests drive the full lifecycle; none assert the empty default.
    seed_complete_operator(&operator_repo).await;
    let api_key_repo = Arc::new(PgApiKeyRepo::new(dal.clone()));
    let job_store = Arc::new(PgJobStore::new(dal.clone()));

    // In-process signing — the fused node signs via LocalIdentityService exactly
    // as main.rs does; the internal HTTP sign route is intentionally unmounted
    // (ATK-1). The same key store backs both signing and the did:web document.
    let ks_path = std::env::temp_dir().join(format!("node-smoke-ks-{}.json", uuid::Uuid::now_v7()));
    let key_store = Arc::new(KeyStore::open(&ks_path, "test-passphrase").expect("open key store"));
    key_store
        .generate_key("root")
        .expect("provision root issuer key");
    let did_web_base_url = "test.example.com".to_owned();

    let identity = Arc::new(LocalIdentityService::new(
        key_store.clone(),
        "root".to_owned(),
        did_web_base_url.clone(),
    ));
    let compliance = Arc::new(PassthroughRegistry::new());
    let event_bus: Arc<dyn dpp_common::event::EventBus> = Arc::new(dpp_common::event::NoOpEventBus);
    let registry_sync: Arc<dyn dpp_domain::ports::registry_sync::RegistrySyncPort> =
        Arc::new(GhostRegistrySync);
    let service = Arc::new(
        PassportService::new(
            passport_repo,
            identity,
            compliance,
            audit_repo,
            event_bus,
            registry_sync,
            Arc::new(GhostArchive),
            String::new(),
        )
        .with_transfer_store(Arc::new(PgTransferRepo::new(dal.clone())))
        .with_evidence_store(Arc::new(PgEvidenceDossierRepo::new(dal.clone())))
        .with_registry_reader(operator_repo.clone()),
    );
    let operator_service = Arc::new(OperatorService::new(operator_repo));
    let api_key_service = Arc::new(ApiKeyService::new(api_key_repo));
    let registry_identity_service = Arc::new(RegistryIdentityService::new(Arc::new(
        PgRegistryIdentityRepo::new(dal.clone()),
    )));
    let webhook_repo = Arc::new(PgWebhookRepo::new(dal.clone()));
    let webhook_service = Arc::new(WebhookService::new(
        webhook_repo.clone(),
        webhook_repo,
        false,
    ));
    let auth_provider: Arc<dyn dpp_types::auth::AuthProvider> = Arc::new(TestAuthProvider);
    let vault_state = VaultState {
        service,
        operator_service,
        api_key_service,
        registry_identity_service,
        webhook_service,
        db_ping: Arc::new(PgPing(dal)),
        auth_provider,
        cors_allowed_origins: Vec::new(),
    };

    let identity_state = IdentityState {
        store: key_store,
        did_web_base_url,
    };

    let vault_client = Arc::new(VaultHttpClient::new(&format!("{base_url}/vault")));
    let integrator_state = IntegratorState {
        vault_client,
        job_store,
        batch_concurrency: 4,
    };

    let trust = std::sync::Arc::new(dpp_types::trust::NodeTrustReport::new(
        dpp_types::trust::NodeProfile::Development,
        vec![dpp_types::trust::TrustPort {
            port: "registry_sync",
            mode: dpp_types::trust::TrustMode::Ghost,
            required: true,
        }],
    ));
    let ruleset = std::sync::Arc::new(dpp_node::infra::ruleset::ActiveRuleset::baseline());
    let app = dpp_node::router::build(
        vault_state,
        identity_state,
        integrator_state,
        trust,
        ruleset,
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("node server error");
    });

    base_url
}

fn make_jwt(operator_id: &str) -> String {
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let exp = chrono::Utc::now().timestamp() + 3600;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "operator_id": operator_id,
            "sub": format!("user-{operator_id}"),
            "plan": "pro",
            "exp": exp
        })
        .to_string(),
    );
    format!("{header}.{payload}.test-sig-not-verified")
}

/// Seed a *complete* operator so the publish-completeness gate passes. None of
/// the node smoke tests assert the empty default, so this is seeded once in the
/// node factory rather than per test.
async fn seed_complete_operator(repo: &PgOperatorConfigRepo) {
    use dpp_types::operator::{OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID};

    let mut cfg = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
    cfg.legal_name = "Smoke Test Operator GmbH".into();
    cfg.address = "Unter den Linden 1, Berlin".into();
    cfg.country = "DE".into();
    cfg.contact_email = "ops@smoke.example".into();
    cfg.did_web_url = Some("https://test.example.com/.well-known/did.json".into());

    repo.upsert(cfg).await.expect("seed complete operator");
}

// ---------------------------------------------------------------------------
// Tier 1 — health + auth (uses a shared DB container; auth fires before DB)
// ---------------------------------------------------------------------------

async fn start_db_and_node() -> (String, testcontainers::ContainerAsync<GenericImage>) {
    let (dal, container) = start_pg().await;
    let node_url = start_node_with_dal(dal).await;
    (node_url, container)
}

#[tokio::test(flavor = "multi_thread")]
async fn node_health_reports_trust_modes() {
    let (base, _c) = start_db_and_node().await;
    let resp = reqwest::get(format!("{base}/health"))
        .await
        .expect("GET /health failed");
    assert_eq!(resp.status(), 200);
    // Ghost-honesty invariant: /health surfaces each trust port's
    // tier. The dev node here has no registry creds, so registry_sync is a ghost.
    let body: serde_json::Value = resp.json().await.expect("health is JSON");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["profile"], "development");
    assert_eq!(body["trust_mode"]["registry_sync"], "ghost");
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_health_is_mounted_at_vault_prefix() {
    let (base, _c) = start_db_and_node().await;
    let resp = reqwest::get(format!("{base}/vault/health"))
        .await
        .expect("GET /vault/health failed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_health_is_mounted_at_identity_prefix() {
    let (base, _c) = start_db_and_node().await;
    let resp = reqwest::get(format!("{base}/identity/health"))
        .await
        .expect("GET /identity/health failed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn integrator_health_is_mounted_at_integrator_prefix() {
    let (base, _c) = start_db_and_node().await;
    let resp = reqwest::get(format!("{base}/integrator/health"))
        .await
        .expect("GET /integrator/health failed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_vault_request_returns_401() {
    let (base, _c) = start_db_and_node().await;
    let resp = reqwest::get(format!("{base}/vault/api/v1/dpps"))
        .await
        .expect("GET request failed");
    assert_eq!(resp.status(), 401);
}

/// Route-inventory snapshot (`00-INDEX.md`'s "no-regret first step" ahead of
/// an OpenAPI surface): a checked-in list of every (method, path) the
/// assembled node mounts, asserted to resolve — never `404` — through the
/// real router. Catches accidental route loss during future refactors. This
/// list is the reviewed artifact: update it deliberately when a route is
/// added, removed, or renamed; do not regenerate it mechanically.
#[tokio::test(flavor = "multi_thread")]
async fn route_inventory_matches_assembled_router() {
    let (base, _c) = start_db_and_node().await;
    let client = reqwest::Client::new();

    const FAKE_ID: &str = "00000000-0000-4000-8000-000000000000";

    // The two public (unauthenticated) lookup routes run real handler logic —
    // unlike every `/vault/api/v1/*` route below, which 401s on a fake id
    // before ever reaching the handler. A nonexistent id/gtin here would 404
    // for "not found", indistinguishable from "route missing"; publish a real
    // battery passport first so those two checks are unambiguous (the
    // by-gtin lookup only ever matches battery — its QR URL is the only one
    // that embeds the GTIN, see `PgPassportRepo::find_published_by_gtin`).
    // Battery is in-force, so publish also requires a default facility +
    // primary operator identifier (Annex III / Art. 13) — seed both first.
    let token = make_jwt("00000000-0000-0000-0000-000000000088");
    let facility_resp = client
        .post(format!("{base}/vault/api/v1/facilities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Default Plant", "identifierScheme": "gln",
            "identifierValue": "4012345000009", "country": "DE", "isDefault": true
        }))
        .send()
        .await
        .expect("facility seed request failed");
    assert!(
        facility_resp.status().is_success(),
        "facility seed failed: {}",
        facility_resp.status()
    );
    let operator_id_resp = client
        .post(format!("{base}/vault/api/v1/operator-identifiers"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }))
        .send()
        .await
        .expect("operator-identifier seed request failed");
    assert!(
        operator_id_resp.status().is_success(),
        "operator-identifier seed failed: {}",
        operator_id_resp.status()
    );

    let created: serde_json::Value = client
        .post(format!("{base}/vault/api/v1/dpp"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "productName": "Route Inventory Battery",
            "manufacturer": {"name": "SmokeTestCorp", "address": "Berlin, DE"},
            "materials": [],
            "schemaVersion": "1.0.0",
            "sectorData": {
                "sector": "battery",
                "gtin": "09506000134352",
                "batteryChemistry": "LFP",
                "nominalVoltageV": 48.0,
                "nominalCapacityAh": 100.0,
                "expectedLifetimeCycles": 3000,
                "co2ePerUnitKg": 45.2
            }
        }))
        .send()
        .await
        .expect("create request failed")
        .json()
        .await
        .expect("create response must be JSON");
    let real_id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("id missing from create response: {created}"))
        .to_owned();
    let publish_resp = client
        .post(format!("{base}/vault/api/v1/dpp/{real_id}/publish"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("publish request failed");
    let publish_status = publish_resp.status();
    let publish_body = publish_resp.text().await.unwrap_or_default();
    assert!(
        publish_status.is_success(),
        "publish failed setting up the route-inventory test fixture: {publish_status} {publish_body}"
    );
    const REAL_GTIN: &str = "09506000134352";

    let routes: Vec<(reqwest::Method, String)> = vec![
        (reqwest::Method::GET, "/health".into()),
        (reqwest::Method::GET, "/vault/health".into()),
        (reqwest::Method::GET, "/vault/ready".into()),
        (reqwest::Method::GET, "/vault/api/v1/info".into()),
        (reqwest::Method::GET, format!("/vault/public/dpp/{real_id}")),
        (
            reqwest::Method::GET,
            format!("/vault/public/dpp/by-gtin/{REAL_GTIN}"),
        ),
        (reqwest::Method::POST, "/vault/api/v1/dpp".into()),
        (reqwest::Method::GET, "/vault/api/v1/dpps".into()),
        (reqwest::Method::GET, format!("/vault/api/v1/dpp/{FAKE_ID}")),
        (reqwest::Method::PUT, format!("/vault/api/v1/dpp/{FAKE_ID}")),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/dpp/{FAKE_ID}/publish"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/dpp/{FAKE_ID}/suspend"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/dpp/{FAKE_ID}/archive"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/dpp/{FAKE_ID}/eol"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/dpp/{FAKE_ID}/transfer/initiate"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/dpp/{FAKE_ID}/transfer/accept"),
        ),
        (
            reqwest::Method::GET,
            format!("/vault/api/v1/dpp/{FAKE_ID}/history"),
        ),
        (
            reqwest::Method::GET,
            format!("/vault/api/v1/dpp/{FAKE_ID}/verify-tree"),
        ),
        (reqwest::Method::GET, "/vault/api/v1/node/state".into()),
        (reqwest::Method::GET, "/vault/api/v1/operator".into()),
        (reqwest::Method::PATCH, "/vault/api/v1/operator".into()),
        (reqwest::Method::GET, "/vault/api/v1/api-keys".into()),
        (reqwest::Method::POST, "/vault/api/v1/api-keys".into()),
        (
            reqwest::Method::DELETE,
            format!("/vault/api/v1/api-keys/{FAKE_ID}"),
        ),
        (reqwest::Method::GET, "/vault/api/v1/facilities".into()),
        (reqwest::Method::POST, "/vault/api/v1/facilities".into()),
        (
            reqwest::Method::DELETE,
            format!("/vault/api/v1/facilities/{FAKE_ID}"),
        ),
        (
            reqwest::Method::GET,
            format!("/vault/api/v1/facilities/{FAKE_ID}/audit"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/facilities/{FAKE_ID}/default"),
        ),
        (
            reqwest::Method::GET,
            "/vault/api/v1/operator-identifiers".into(),
        ),
        (
            reqwest::Method::POST,
            "/vault/api/v1/operator-identifiers".into(),
        ),
        (
            reqwest::Method::DELETE,
            format!("/vault/api/v1/operator-identifiers/{FAKE_ID}"),
        ),
        (
            reqwest::Method::GET,
            format!("/vault/api/v1/operator-identifiers/{FAKE_ID}/audit"),
        ),
        (
            reqwest::Method::POST,
            format!("/vault/api/v1/operator-identifiers/{FAKE_ID}/primary"),
        ),
        (reqwest::Method::GET, "/identity/health".into()),
        (reqwest::Method::GET, "/identity/ready".into()),
        (
            reqwest::Method::GET,
            "/identity/.well-known/did.json".into(),
        ),
        (reqwest::Method::GET, "/integrator/health".into()),
        (
            reqwest::Method::GET,
            "/integrator/api/v1/templates/battery".into(),
        ),
        (
            reqwest::Method::POST,
            "/integrator/api/v1/import/battery".into(),
        ),
        (
            reqwest::Method::GET,
            format!("/integrator/api/v1/imports/{FAKE_ID}"),
        ),
    ];

    for (method, path) in &routes {
        let resp = client
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{method} {path} request failed: {e}"));
        assert_ne!(
            resp.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{method} {path} returned 404 — route missing from the assembled router"
        );
    }
}

// ---------------------------------------------------------------------------
// Tier 2 — Full DPP lifecycle (requires Docker)
// ---------------------------------------------------------------------------

/// Create + publish a battery passport, optionally citing a parent, returning
/// its id. Battery is in-force, so the caller must have seeded a default
/// facility + primary operator identifier first.
async fn publish_battery(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    gtin: &str,
    product_name: &str,
    parent: Option<&PassportRef>,
) -> String {
    let mut body = serde_json::json!({
        "productName": product_name,
        "manufacturer": {"name": "SmokeTestCorp", "address": "Berlin, DE"},
        "materials": [],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": gtin,
            "batteryChemistry": "LFP",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2
        }
    });
    if let Some(p) = parent {
        body["parentPassportRef"] =
            serde_json::json!({ "uri": p.uri, "publicJwsHash": p.public_jws_hash });
    }
    let created: serde_json::Value = client
        .post(format!("{base}/vault/api/v1/dpp"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("create request failed")
        .json()
        .await
        .expect("create response is JSON");
    let id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("id missing from create response: {created}"))
        .to_owned();
    let publish_resp = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/publish"))
        .bearer_auth(token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("publish request failed");
    let status = publish_resp.status();
    assert!(
        status.is_success(),
        "publish failed: {status} {}",
        publish_resp.text().await.unwrap_or_default()
    );
    id
}

/// Second-life successor: a published passport can cite a cross-operator parent
/// via `parentPassportRef`, the pin verifies against the parent's live public
/// JWS, and the parent ref survives redaction into the public view (so the
/// resolver can advertise the `predecessor` lineage link).
///
/// The SSRF guard forbids citing a private/`http` host, so the successor cites a
/// shape-valid `https://…` URL and `verify_ref` is driven with a fetch closure
/// that bridges that URL to this local node's public view (production wires the
/// SSRF-guarded `fetch_public_json` instead).
#[tokio::test(flavor = "multi_thread")]
async fn second_life_successor_verifies_against_pinned_parent() {
    let (base, _container) = start_db_and_node().await;
    let client = reqwest::Client::new();
    let token = make_jwt("00000000-0000-0000-0000-000000000077");

    // Battery is in-force: publish needs a default facility + primary operator id.
    let facility_resp = client
        .post(format!("{base}/vault/api/v1/facilities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Default Plant", "identifierScheme": "gln",
            "identifierValue": "4012345000009", "country": "DE", "isDefault": true
        }))
        .send()
        .await
        .expect("facility seed request failed");
    assert!(facility_resp.status().is_success(), "facility seed failed");
    let op_id_resp = client
        .post(format!("{base}/vault/api/v1/operator-identifiers"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }))
        .send()
        .await
        .expect("operator-identifier seed request failed");
    assert!(op_id_resp.status().is_success(), "operator-id seed failed");

    // Publish the PARENT, then read the public JWS the successor will pin.
    let parent_id = publish_battery(&client, &base, &token, "09506000134352", "Parent", None).await;
    let parent_public: serde_json::Value = client
        .get(format!("{base}/vault/public/dpp/{parent_id}"))
        .send()
        .await
        .expect("parent public read failed")
        .json()
        .await
        .expect("parent public view is JSON");
    let parent_jws = parent_public["publicJwsSignature"]
        .as_str()
        .expect("a published passport carries a public JWS");
    let pin = hex::encode(Sha256::digest(parent_jws.as_bytes()));

    // Cite a shape-valid https URL (the SSRF guard forbids localhost); verify_ref
    // is bridged to the local node below.
    let cited_uri = format!("https://id.odal-node.io/dpp/{parent_id}");
    let parent_ref = PassportRef {
        uri: cited_uri.clone(),
        public_jws_hash: pin.clone(),
    };

    // Publish the SUCCESSOR citing the parent.
    let successor_id = publish_battery(
        &client,
        &base,
        &token,
        "09506000134369",
        "Successor",
        Some(&parent_ref),
    )
    .await;
    let successor_public: serde_json::Value = client
        .get(format!("{base}/vault/public/dpp/{successor_id}"))
        .send()
        .await
        .expect("successor public read failed")
        .json()
        .await
        .expect("successor public view is JSON");
    assert_eq!(
        successor_public["parentPassportRef"]["uri"].as_str(),
        Some(cited_uri.as_str()),
        "parentPassportRef must survive into the public view"
    );

    // A fetch closure bridging the cited https URL to the local node's parent JSON.
    let bridged = {
        let cited = cited_uri.clone();
        let parent_json = parent_public.clone();
        move |url: String| {
            std::future::ready(if url == cited {
                Ok(parent_json.clone())
            } else {
                Err(())
            })
        }
    };

    // Happy path: the pin matches the parent's live public JWS.
    assert_eq!(
        verify_ref(&parent_ref, &bridged).await,
        RefVerification::Verified
    );

    // Tamper: a wrong pin over the same fetched signature fails closed.
    let wrong = PassportRef {
        uri: cited_uri.clone(),
        public_jws_hash: "0".repeat(64),
    };
    assert_eq!(
        verify_ref(&wrong, &bridged).await,
        RefVerification::Unverifiable(RefUnverifiable::HashMismatch)
    );

    // Unreachable: an unmapped URL fails closed, never false-green.
    let gone = PassportRef {
        uri: "https://gone.example/dpp/x".into(),
        public_jws_hash: pin,
    };
    assert_eq!(
        verify_ref(&gone, &bridged).await,
        RefVerification::Unverifiable(RefUnverifiable::Unreachable)
    );
}

/// Local BOM cycles are refused at the API: if B lists A as a component, A
/// cannot then be updated to list B — that would close an A → B → A cycle.
/// Exercises the service's `guard_component_graph` over real drafts, and
/// confirms `componentRefs` round-trips through create + read.
#[tokio::test(flavor = "multi_thread")]
async fn local_component_cycle_is_rejected() {
    async fn create_draft(
        client: &reqwest::Client,
        base: &str,
        token: &str,
        name: &str,
        component_uris: &[String],
    ) -> String {
        let refs: Vec<serde_json::Value> = component_uris
            .iter()
            .map(|u| serde_json::json!({ "uri": u, "publicJwsHash": "a".repeat(64) }))
            .collect();
        let created: serde_json::Value = client
            .post(format!("{base}/vault/api/v1/dpp"))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "productName": name,
                "manufacturer": {"name": "AssemblyCo", "address": "Berlin, DE"},
                "materials": [],
                "componentRefs": refs
            }))
            .send()
            .await
            .expect("create request failed")
            .json()
            .await
            .expect("create response is JSON");
        created["id"]
            .as_str()
            .unwrap_or_else(|| panic!("id missing: {created}"))
            .to_owned()
    }

    let (base, _container) = start_db_and_node().await;
    let client = reqwest::Client::new();
    let token = make_jwt("00000000-0000-0000-0000-000000000066");

    // A has no components; B lists A (B → A).
    let a_id = create_draft(&client, &base, &token, "Assembly A", &[]).await;
    let ref_to_a = format!("https://id.odal-node.io/dpp/{a_id}");
    let b_id = create_draft(&client, &base, &token, "Assembly B", &[ref_to_a.clone()]).await;

    // componentRefs round-trips through create + read.
    let b: serde_json::Value = client
        .get(format!("{base}/vault/api/v1/dpp/{b_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("read B failed")
        .json()
        .await
        .expect("B is JSON");
    assert_eq!(
        b["componentRefs"][0]["uri"].as_str(),
        Some(ref_to_a.as_str()),
        "componentRefs must round-trip through create + read"
    );

    // Updating A to list B closes the A → B → A cycle → refused with 422.
    let ref_to_b = format!("https://id.odal-node.io/dpp/{b_id}");
    let resp = client
        .put(format!("{base}/vault/api/v1/dpp/{a_id}"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "componentRefs": [{ "uri": ref_to_b, "publicJwsHash": "a".repeat(64) }]
        }))
        .send()
        .await
        .expect("update A request failed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "adding a component that cites back must be refused"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("cycle"),
        "the rejection should name the cycle, got: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn full_dpp_lifecycle_through_assembled_node() {
    let (base, _container) = start_db_and_node().await;

    let operator_id = "00000000-0000-0000-0000-000000000099";
    let token = make_jwt(operator_id);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/vault/api/v1/dpp"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "productName": "Node Smoke Test Battery",
            "productCategory": "BATTERY",
            "manufacturer": {"name": "SmokeTestCorp", "address": "Berlin, DE"},
            "materials": [],
            "schemaVersion": "1.0.0"
        }))
        .send()
        .await
        .expect("create request failed");

    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("response must contain id");
    assert_eq!(created["status"], "draft");
    assert_eq!(created["retentionLocked"], false);

    let resp = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/publish"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("publish request failed");

    assert_eq!(resp.status(), 200);
    let published: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(published["status"], "active");
    assert_eq!(published["retentionLocked"], true);
    assert!(published["qrCodeUrl"].is_string());

    let resp = client
        .get(format!("{base}/vault/api/v1/dpp/{id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("read request failed");

    assert_eq!(resp.status(), 200);
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fetched["id"], id);
    assert_eq!(fetched["retentionLocked"], true);

    let resp = client
        .get(format!("{base}/vault/public/dpp/{id}"))
        .send()
        .await
        .expect("public resolver request failed");

    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "public resolver must return 2xx or 3xx, got {}",
        resp.status()
    );
}

// End-of-life deactivates the passport (retained, not deleted) and records
// the typed EOL reason in the hash-chained audit trail.
#[tokio::test(flavor = "multi_thread")]
async fn eol_declaration_deactivates_and_records_reason() {
    let (base, _container) = start_db_and_node().await;
    let token = make_jwt("00000000-0000-0000-0000-000000000077");
    let client = reqwest::Client::new();

    let created: serde_json::Value = client
        .post(format!("{base}/vault/api/v1/dpp"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "productName": "EOL Test Battery",
            "productCategory": "BATTERY",
            "manufacturer": {"name": "SmokeTestCorp", "address": "Berlin, DE"},
            "materials": [],
            "schemaVersion": "1.0.0"
        }))
        .send()
        .await
        .expect("create request failed")
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().expect("id").to_owned();

    let resp = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/publish"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("publish request failed");
    assert_eq!(resp.status(), 200);

    // Declare EOL: recycled, with a recovered-material summary (Annex XIII).
    let resp = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/eol"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "reason": {"kind": "recycled"},
            "materialRecovery": {"lithiumKg": 0.4}
        }))
        .send()
        .await
        .expect("eol request failed");
    assert_eq!(resp.status(), 200);
    let deactivated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(deactivated["status"], "deactivated");

    // The record is retained (readable), just terminal.
    let fetched: serde_json::Value = client
        .get(format!("{base}/vault/api/v1/dpp/{id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("read request failed")
        .json()
        .await
        .unwrap();
    assert_eq!(fetched["status"], "deactivated");

    // The typed EOL reason is in the (hash-chained) audit trail.
    let history: serde_json::Value = client
        .get(format!("{base}/vault/api/v1/dpp/{id}/history"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("history request failed")
        .json()
        .await
        .unwrap();
    let eol_entry = history
        .as_array()
        .expect("history is an array")
        .iter()
        .find(|e| e["action"] == "deactivated")
        .expect("history must record a deactivated entry");
    assert_eq!(eol_entry["newStatus"], "deactivated");
    assert_eq!(eol_entry["metadata"]["reason"]["kind"], "recycled");
    assert_eq!(eol_entry["metadata"]["materialRecovery"]["lithiumKg"], 0.4);
}

// Full lifecycle close — publish → transfer initiate (outgoing signs) →
// accept (incoming countersigns, verified) → EOL. The dual-signed handover is
// persisted on the passport's transfer chain.
#[tokio::test(flavor = "multi_thread")]
async fn transfer_of_responsibility_dual_signed_then_eol() {
    let (base, _container) = start_db_and_node().await;
    let token = make_jwt("00000000-0000-0000-0000-000000000066");
    let client = reqwest::Client::new();

    let created: serde_json::Value = client
        .post(format!("{base}/vault/api/v1/dpp"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "productName": "Transfer Test Battery",
            "productCategory": "BATTERY",
            "manufacturer": {"name": "SmokeTestCorp", "address": "Berlin, DE"},
            "materials": [],
            "schemaVersion": "1.0.0"
        }))
        .send()
        .await
        .expect("create request failed")
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().expect("id").to_owned();

    assert_eq!(
        client
            .post(format!("{base}/vault/api/v1/dpp/{id}/publish"))
            .bearer_auth(&token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("publish request failed")
            .status(),
        200
    );

    // Outgoing operator initiates and signs the handover.
    let init_resp = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/transfer/initiate"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "fromOperator": {"did":"did:web:acme.example","name":"Acme GmbH","role":"manufacturer","euOperatorId":null,"country":"DE"},
            "toOperator": {"did":"did:web:recycler.example","name":"ReCo","role":"recycler","euOperatorId":null,"country":"DE"},
            "reason": "preparationForReuse"
        }))
        .send()
        .await
        .expect("initiate request failed");
    let init_status = init_resp.status();
    let init: serde_json::Value = init_resp.json().await.unwrap();
    assert_eq!(init_status, 200, "initiate failed: {init}");
    assert!(
        init["fromSignature"].is_string(),
        "outgoing operator signed"
    );
    assert!(init["toSignature"].is_null(), "not yet accepted");

    // Incoming operator accepts — the node verifies the outgoing signature and
    // countersigns, completing the handover.
    let accepted: serde_json::Value = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/transfer/accept"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("accept request failed")
        .json()
        .await
        .unwrap();
    assert!(
        accepted["toSignature"].is_string(),
        "incoming countersigned"
    );
    assert!(accepted["completedAt"].is_string(), "transfer completed");
    assert_eq!(accepted["toOperator"]["did"], "did:web:recycler.example");

    // Close the loop: the recycler declares end-of-life.
    let eol: serde_json::Value = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/eol"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"reason": {"kind": "recycled"}}))
        .send()
        .await
        .expect("eol request failed")
        .json()
        .await
        .unwrap();
    assert_eq!(eol["status"], "deactivated");
}

// ---------------------------------------------------------------------------
// Metrics acceptance test — passport_publish_total counter increments
// ---------------------------------------------------------------------------

fn prometheus_handle() -> &'static PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("failed to install Prometheus recorder")
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_increments_passport_publish_total() {
    let handle = prometheus_handle();
    let (base, _container) = start_db_and_node().await;

    let token = make_jwt("00000000-0000-0000-0000-000000000088");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/vault/api/v1/dpp"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "productName": "Metrics Acceptance Test",
            "productCategory": "BATTERY",
            "manufacturer": {"name": "MetricsCorp", "address": "Berlin, DE"},
            "materials": [],
            "schemaVersion": "1.0.0"
        }))
        .send()
        .await
        .expect("create request failed");
    assert_eq!(resp.status(), 201);

    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .expect("id missing from create response")
        .to_owned();

    let resp = client
        .post(format!("{base}/vault/api/v1/dpp/{id}/publish"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("publish request failed");
    assert_eq!(resp.status(), 200);

    let output = handle.render();
    assert!(
        output.contains("passport_publish_total"),
        "passport_publish_total not found in Prometheus output:\n{output}"
    );
    assert!(
        output.contains(r#"outcome="success""#),
        "passport_publish_total success outcome not found:\n{output}"
    );
}

/// Phase-3 metric: an unauthenticated request must increment
/// `auth_failures_total{reason="missing"}` so credential attacks are observable.
#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_request_increments_auth_failures_total() {
    let handle = prometheus_handle();
    let (base, _container) = start_db_and_node().await;

    let resp = reqwest::get(format!("{base}/vault/api/v1/dpps"))
        .await
        .expect("GET request failed");
    assert_eq!(resp.status(), 401);

    let output = handle.render();
    assert!(
        output.contains("auth_failures_total"),
        "auth_failures_total not found in Prometheus output:\n{output}"
    );
    assert!(
        output.contains(r#"reason="missing""#),
        "auth_failures_total missing-reason not found:\n{output}"
    );
}

/// Phase-3 metric (RT2-1 surface): an import with an unknown sector must increment
/// `import_rejections_total{reason="unknown_sector"}`. A valid multipart
/// content-type is sent so the `Multipart` extractor constructs; the handler's
/// sector check returns 404 before the body is read.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_sector_import_increments_import_rejections_total() {
    let handle = prometheus_handle();
    let (base, _container) = start_db_and_node().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/integrator/api/v1/import/widgets"))
        .header("content-type", "multipart/form-data; boundary=x")
        .body("--x--\r\n")
        .send()
        .await
        .expect("import request failed");
    assert_eq!(resp.status(), 404);

    let output = handle.render();
    assert!(
        output.contains("import_rejections_total"),
        "import_rejections_total not found in Prometheus output:\n{output}"
    );
    assert!(
        output.contains(r#"reason="unknown_sector""#),
        "import_rejections_total unknown_sector-reason not found:\n{output}"
    );
}
