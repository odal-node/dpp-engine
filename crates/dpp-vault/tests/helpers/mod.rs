//! Shared test helpers for integration tests.
//!
//! Compiled only when the `integration-tests` feature is enabled.

#![cfg(feature = "integration-tests")]
// Each integration-test binary `mod helpers;`-includes this whole module but uses
// only a subset, so per-binary dead_code warnings are expected and not real debt.
#![allow(dead_code)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;

use dpp_dal::pg::{
    PgApiKeyRepo, PgAuditRepo, PgDal, PgEvidenceDossierRepo, PgOperatorConfigRepo, PgPassportRepo,
    PgRegistryIdentityRepo, PgRegistrySyncRepo, PgRegistryTransferRepo, PgScanTelemetryRepo,
    PgSealOutboxRepo, PgTransferRepo, PgWebhookRepo,
};
use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync, PassthroughRegistry,
    credential::{PassportCredential, PassportCredentialSubject, SignedCredential},
    passport::PassportId,
    ports::identity::IdentityPort,
};
use dpp_types::auth::{AuthContext, AuthError, AuthProvider};
use dpp_vault::{
    domain::{
        api_key_service::ApiKeyService,
        operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService,
        service::{OperatorIdentity, PassportService},
        webhook_service::WebhookService,
    },
    router,
    state::{AppState, DbPing},
};

// ---------------------------------------------------------------------------
// Test auth provider
// ---------------------------------------------------------------------------

/// Test-only auth provider: accepts the unsigned dev JWTs minted by `make_jwt`
/// (structural + `exp` + `operator_suspended` checks only). The shipped node
/// authenticates with real API keys / local-admin Basic auth; this lives here
/// so the HTTP-level integration tests can drive authenticated routes without
/// seeding API keys. Single-tenant: no operator scope.
pub struct TestAuthProvider;

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
        if claims
            .get("operator_suspended")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err(AuthError::Suspended);
        }

        // Honour an optional `scope` claim: tests that omit it get Admin so
        // existing lifecycle/key tests retain full access; `make_jwt_scoped` can
        // mint a least-privilege principal to drive the scope-enforcement PoC.
        let scope = claims
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| dpp_types::api_key::ApiKeyScope::from_scopes(&[s.to_owned()]))
            .unwrap_or(dpp_types::api_key::ApiKeyScope::Admin);

        Ok(AuthContext {
            user_id: claims
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("test-user")
                .to_owned(),
            scope,
            key_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL container
// ---------------------------------------------------------------------------

/// A database ready for use, and whatever is keeping it alive.
///
/// The name is kept because 109 call sites across 27 files use it. What it
/// holds is no longer necessarily a container — see [`start_postgres`].
pub struct PgContainer {
    pub dal: PgDal,
    /// Held so the database outlives the test. On the shared-server path this
    /// owns nothing; on the fallback path it owns the container.
    _pg: dpp_dal::test_harness::TestPg,
}

/// A migrated database with an app-role `PgDal` connected to it.
///
/// Delegates to the shared harness. This used to start its own `postgres:17`
/// per call — a **ninth** copy of a harness that had already been consolidated,
/// missed by `just harness-check` only because it was spelled `start_postgres`
/// rather than `start_pg`. That gate now matches on starting a Postgres
/// container at all, not on a function name.
///
/// The cost was not small: these 109 call sites were the bulk of the 171 tests
/// that consumed 86% of all test time, at 12-16s each. Through the shared
/// harness the same tests take one to two seconds.
pub async fn start_postgres() -> PgContainer {
    let pg = dpp_dal::test_harness::start_pg().await;
    PgContainer {
        dal: pg.dal.clone(),
        _pg: pg,
    }
}

// ---------------------------------------------------------------------------
// Mock identity service
// ---------------------------------------------------------------------------

pub struct MockIdentity;
pub struct FailingIdentity;

#[async_trait]
impl IdentityPort for FailingIdentity {
    async fn sign_passport(
        &self,
        _passport_id: PassportId,
        _payload: &serde_json::Value,
    ) -> Result<SignedCredential, DppError> {
        Err(DppError::Signing("identity service unavailable".into()))
    }

    async fn verify_signature(
        &self,
        _jws: &str,
        _payload: &serde_json::Value,
    ) -> Result<bool, DppError> {
        Err(DppError::Signing("identity service unavailable".into()))
    }

    async fn own_did_document(&self) -> Result<serde_json::Value, DppError> {
        Err(DppError::Signing("identity service unavailable".into()))
    }
}

#[async_trait]
impl IdentityPort for MockIdentity {
    async fn sign_passport(
        &self,
        passport_id: PassportId,
        payload: &serde_json::Value,
    ) -> Result<SignedCredential, DppError> {
        // base64url **without** padding — a compact JWS payload segment is
        // defined that way (RFC 7515 §2), and anything that decodes a real JWS
        // (the public read, the resolver) decodes it that way. Encoding the
        // mock with the padded standard alphabet made it emit a string that is
        // not a JWS, which no test noticed until a caller actually decoded it.
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap_or_default());
        Ok(SignedCredential {
            credential: PassportCredential {
                context: vec![
                    "https://www.w3.org/ns/credentials/v2".into(),
                    "https://schema.odal-node.io/credentials/dpp-passport/v1".into(),
                ],
                credential_type: vec![
                    "VerifiableCredential".into(),
                    "DppPassportCredential".into(),
                ],
                id: format!("urn:uuid:{}", passport_id),
                issuer: "did:web:test.mock".to_owned(),
                valid_from: chrono::Utc::now(),
                credential_subject: PassportCredentialSubject {
                    id: format!("urn:uuid:{}", passport_id),
                    payload_hash: payload_b64.clone(),
                },
            },
            jws: format!("test-header.{payload_b64}.test-sig"),
            issuer_did: "did:web:test.mock".to_owned(),
        })
    }

    async fn verify_signature(
        &self,
        _jws: &str,
        _payload: &serde_json::Value,
    ) -> Result<bool, DppError> {
        Ok(true)
    }

    async fn own_did_document(&self) -> Result<serde_json::Value, DppError> {
        Ok(serde_json::json!({
            "id": "did:web:test.mock",
            "verificationMethod": [],
            "assertionMethod": [],
        }))
    }
}

// ---------------------------------------------------------------------------
// Vault Axum app factory
// ---------------------------------------------------------------------------

pub async fn start_vault(dal: PgDal) -> String {
    start_vault_with_identity(dal, Arc::new(MockIdentity), None).await
}

pub async fn start_vault_failing_signer(dal: PgDal) -> String {
    start_vault_with_identity(dal, Arc::new(FailingIdentity), None).await
}

/// A vault with the credential path **configured** — the audience-scoped route
/// resolves credentials instead of falling through to the public view.
pub async fn start_vault_with_credentials(
    dal: PgDal,
    directory: Arc<dyn dpp_vault::middleware::credential::CredentialDirectory>,
    trust: Arc<dyn dpp_vc::TrustedIssuerRegistry>,
) -> String {
    start_vault_with_identity(dal, Arc::new(MockIdentity), Some((directory, trust))).await
}

type CredentialWiring = (
    Arc<dyn dpp_vault::middleware::credential::CredentialDirectory>,
    Arc<dyn dpp_vc::TrustedIssuerRegistry>,
);

async fn start_vault_with_identity(
    dal: PgDal,
    identity: Arc<dyn IdentityPort>,
    credentials: Option<CredentialWiring>,
) -> String {
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

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let audit_repo = Arc::new(PgAuditRepo::new(dal.clone()));
    let operator_repo = Arc::new(PgOperatorConfigRepo::new(dal.clone()));
    let api_key_repo = Arc::new(PgApiKeyRepo::new(dal.clone()));
    let compliance = Arc::new(PassthroughRegistry::new());
    let event_bus: Arc<dyn dpp_common::event::EventBus> = Arc::new(dpp_common::event::NoOpEventBus);
    let registry_sync: Arc<dyn dpp_domain::ports::registry_sync::RegistrySyncPort> =
        Arc::new(GhostRegistrySync);

    // Mirror production: the registry reader stamps the default facility + primary
    // operator identifier onto new passports, read live from the operator config.
    let service = Arc::new(
        PassportService::new(
            passport_repo,
            identity,
            compliance,
            audit_repo,
            event_bus,
            registry_sync,
            Arc::new(GhostArchive),
            OperatorIdentity {
                legal_name: "Test Operator GmbH".to_owned(),
                country: "DE".to_owned(),
            },
        )
        .with_registry_reader(operator_repo.clone())
        // Mirror production here too: the node wires both registry outboxes, so
        // a harness without them exercises a publish path that does not exist in
        // any real deployment — and reports the registry surface as
        // unconfigured.
        .with_registry_outbox(Arc::new(PgRegistrySyncRepo::new(dal.clone())))
        .with_transfer_outbox(Arc::new(PgRegistryTransferRepo::new(dal.clone())))
        // Same reasoning as the two above: any node with a seal provider
        // selected wires this, so a harness without it reports the sealing
        // surface as unconfigured and cannot exercise it at all.
        .with_seal_outbox(Arc::new(PgSealOutboxRepo::new(dal.clone())))
        // Same reasoning again, and it had already cost something: without a
        // transfer store the seal route's `responsibilityMayHaveTransferred`
        // took its `None => false` branch, so a test asserting the flag was
        // `false` passed because nothing *could* be recorded rather than
        // because nothing was.
        .with_transfer_store(Arc::new(PgTransferRepo::new(dal.clone())))
        .with_evidence_store(Arc::new(PgEvidenceDossierRepo::new(dal.clone()))),
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
    let scan_repo = Arc::new(PgScanTelemetryRepo::new(dal.clone()));

    let state = AppState {
        service,
        operator_service,
        api_key_service,
        registry_identity_service,
        webhook_service,
        db_ping: Arc::new(PgPing(dal)),
        auth_provider,
        local_auth_provider: None,
        credential_directory: credentials.as_ref().map(|(d, _)| d.clone()),
        trusted_issuers: credentials.as_ref().map(|(_, t)| t.clone()),
        cors_allowed_origins: Vec::new(),
        scan_repo,
        plugin_admin: None,
        // These tests exercise the vault in isolation, with no composition
        // root resolving trust ports or a ruleset.
        trust: None,
        ruleset_admin: None,
        // Off by default: these suites exercise handlers, not retry semantics.
        // `dpp-common`'s `idempotency_flow` suite drives the middleware itself.
        idempotency: None,
    };

    let app = router::build(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("vault server error");
    });

    format!("http://127.0.0.1:{}", addr.port())
}

// ---------------------------------------------------------------------------
// Operator seeding
// ---------------------------------------------------------------------------

/// Seed only the operator-config row (the FK parent for facilities / identifiers /
/// passports). Use this in tests that manage facilities or operator identifiers
/// themselves and assert on their counts — it does **not** pre-seed any.
///
/// Writes directly via the operator repo. Deliberately NOT folded into
/// `start_vault`: `operator_config.rs` asserts the empty default on a fresh DB,
/// so seeding must be opt-in, called right after `start_vault`.
pub async fn seed_operator_config(dal: &PgDal) {
    use dpp_types::operator::{OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID};

    let mut cfg = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
    cfg.legal_name = "Test Operator GmbH".into();
    cfg.address = "Unter den Linden 1, Berlin".into();
    cfg.country = "DE".into();
    cfg.contact_email = "ops@test.example".into();
    cfg.did_web_url = Some("https://test.mock/.well-known/did.json".into());

    PgOperatorConfigRepo::new(dal.clone())
        .upsert(cfg)
        .await
        .expect("seed operator config");
}

/// Seed a *complete, publishable* operator: the config plus the Annex III default
/// facility (point (i)) and primary operator identifier (point (k)) that
/// `publish` now requires for in-force product groups. Use in publish-flow tests.
pub async fn seed_complete_operator(dal: &PgDal) {
    use dpp_types::operator::STANDALONE_OPERATOR_ID;
    use dpp_types::registry_identity::{Facility, OperatorIdentifier, RegistryIdentityRepository};

    seed_operator_config(dal).await;

    let repo = PgRegistryIdentityRepo::new(dal.clone());
    repo.add_facility(
        STANDALONE_OPERATOR_ID,
        Facility {
            id: uuid::Uuid::now_v7(),
            name: "Seed Plant".into(),
            identifier_scheme: "gln".into(),
            identifier_value: "4012345000009".into(),
            country: "DE".into(),
            address: None,
            is_default: true,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("seed default facility");
    repo.add_operator_identifier(
        STANDALONE_OPERATOR_ID,
        OperatorIdentifier {
            id: uuid::Uuid::now_v7(),
            scheme: "vat".into(),
            value: "DE123456789".into(),
            label: None,
            is_primary: true,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("seed primary operator identifier");
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

pub fn make_jwt(operator_id: &str) -> String {
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

/// Like [`make_jwt`] but carries a `scope` claim (`"admin"`/`"write"`/`"read"`)
/// so integration tests can drive the scope-enforcement paths.
pub fn make_jwt_scoped(operator_id: &str, scope: &str) -> String {
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let exp = chrono::Utc::now().timestamp() + 3600;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "operator_id": operator_id,
            "sub": format!("user-{operator_id}"),
            "plan": "pro",
            "scope": scope,
            "exp": exp
        })
        .to_string(),
    );
    format!("{header}.{payload}.test-sig-not-verified")
}

pub fn make_expired_jwt(operator_id: &str) -> String {
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let exp = chrono::Utc::now().timestamp() - 3600;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "operator_id": operator_id,
            "sub": "user-expired",
            "plan": "pro",
            "exp": exp
        })
        .to_string(),
    );
    format!("{header}.{payload}.test-sig-not-verified")
}

// ---------------------------------------------------------------------------
// HTTP client helpers
// ---------------------------------------------------------------------------

pub struct TestClient {
    base_url: String,
    token: String,
    inner: reqwest::Client,
}

impl TestClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token: token.into(),
            inner: reqwest::Client::new(),
        }
    }

    pub async fn post_json(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.inner
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .expect("HTTP POST failed")
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.inner
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await
            .expect("HTTP GET failed")
    }

    pub async fn put_json(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.inner
            .put(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .expect("HTTP PUT failed")
    }

    pub async fn patch_json(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.inner
            .patch(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .expect("HTTP PATCH failed")
    }

    pub async fn post_no_auth(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.inner
            .post(format!("{}{path}", self.base_url))
            .json(&body)
            .send()
            .await
            .expect("HTTP POST failed")
    }

    pub async fn post_with_token(
        &self,
        path: &str,
        body: serde_json::Value,
        token: &str,
    ) -> reqwest::Response {
        self.inner
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("HTTP POST failed")
    }

    pub async fn delete(&self, path: &str) -> reqwest::Response {
        self.inner
            .delete(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await
            .expect("HTTP DELETE failed")
    }
}
