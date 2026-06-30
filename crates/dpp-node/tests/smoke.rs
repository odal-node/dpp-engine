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
    PgApiKeyRepo, PgAuditRepo, PgDal, PgOperatorConfigRepo, PgPassportRepo, PgRegistryIdentityRepo,
    sqlx,
};
use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync,
    compliance::passthrough_registry::PassthroughRegistry,
};
use dpp_identity_service::state::AppState as IdentityState;
use dpp_integrator::{infra::vault_client::VaultHttpClient, state::AppState as IntegratorState};
use dpp_node::infra::pg_job_store::PgJobStore;
use dpp_types::auth::{AuthContext, AuthError, AuthProvider};
use dpp_vault::{
    domain::{
        api_key_service::ApiKeyService, operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService, service::PassportService,
    },
    state::{AppState as VaultState, DbPing},
};

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
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
            if chrono::Utc::now().timestamp() > exp {
                return Err(AuthError::Invalid("token expired".to_owned()));
            }
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
    let service = Arc::new(PassportService::new(
        passport_repo,
        identity,
        compliance,
        audit_repo,
        event_bus,
        registry_sync,
        Arc::new(GhostArchive),
        String::new(),
    ));
    let operator_service = Arc::new(OperatorService::new(operator_repo));
    let api_key_service = Arc::new(ApiKeyService::new(api_key_repo));
    let registry_identity_service = Arc::new(RegistryIdentityService::new(Arc::new(
        PgRegistryIdentityRepo::new(dal.clone()),
    )));
    let auth_provider: Arc<dyn dpp_types::auth::AuthProvider> = Arc::new(TestAuthProvider);
    let vault_state = VaultState {
        service,
        operator_service,
        api_key_service,
        registry_identity_service,
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

    let app = dpp_node::router::build(vault_state, identity_state, integrator_state);

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
async fn node_health_check_returns_ok() {
    let (base, _c) = start_db_and_node().await;
    let resp = reqwest::get(format!("{base}/health"))
        .await
        .expect("GET /health failed");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
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

// ---------------------------------------------------------------------------
// Tier 2 — Full DPP lifecycle (requires Docker)
// ---------------------------------------------------------------------------

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
