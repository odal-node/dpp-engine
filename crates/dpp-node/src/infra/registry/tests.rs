use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chrono::Utc;
use dpp_domain::passport::PassportId;
use dpp_registry::{EuRegistryResponse, RegistryStatusCode};
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_domain::ports::registry_sync::{
    RegistrationGranularity, RegistrationRequest, RegistryStatus, RegistrySyncPort,
};
use dpp_domain::transfer::{OperatorRole, ResponsibleOperator, TransferReason, TransferRecord};

use super::client::EuRegistrySync;
use super::config::EuRegistrySyncConfig;
use super::mapping::{
    extract_gtin_from_gs1_dl, facility_identifier_for, item_id_for, level_for,
    operator_identifier_for,
};
use super::token::CachedToken;
use dpp_registry::StatusResponse;

#[test]
fn sandbox_config_has_correct_defaults() {
    let config = EuRegistrySyncConfig::sandbox("id".into(), "secret".into());
    assert_eq!(config.max_retries, 3);
    // The Commission's test environment is the `acc` host; this asserted
    // `contains("sandbox")` back when the URL was invented.
    assert!(
        config.endpoint.base_url.contains(".acc."),
        "got: {}",
        config.endpoint.base_url
    );
}

#[test]
fn production_config_requires_mtls() {
    let config = EuRegistrySyncConfig::production("id".into(), "secret".into());
    assert!(config.endpoint.mtls_required);
}

#[test]
fn response_to_record_maps_status_correctly() {
    let resp = EuRegistryResponse {
        registry_id: "EU-REG-2026-00001".into(),
        passport_id: Uuid::nil(),
        status: RegistryStatusCode::Registered,
        message: None,
        rejection_reasons: None,
        updated_at: Utc::now(),
    };
    let record = EuRegistrySync::response_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Registered);
    assert_eq!(record.identifiers.registry_id, "EU-REG-2026-00001");
}

#[test]
fn response_to_record_maps_rejected() {
    let resp = EuRegistryResponse {
        registry_id: "EU-REG-2026-00002".into(),
        passport_id: Uuid::nil(),
        status: RegistryStatusCode::Rejected,
        message: Some("invalid data".into()),
        rejection_reasons: Some(vec!["bad GTIN".into()]),
        updated_at: Utc::now(),
    };
    let record = EuRegistrySync::response_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Rejected);
}

#[test]
fn status_to_record_maps_pending() {
    let resp = StatusResponse {
        registry_id: "EU-REG-2026-00003".into(),
        status: RegistryStatusCode::Pending,
        updated_at: Utc::now(),
        message: None,
    };
    let record = EuRegistrySync::status_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Pending);
    assert_eq!(record.identifiers.registry_id, "EU-REG-2026-00003");
}

/// A registration request with realistic non-facility fields. Pair it with a
/// facility snapshot (see [`valid_request`]) for a payload that validates.
///
/// `country_code`, `data_carrier_uri` and `operator_name` were once empty here.
/// That went unnoticed because registration was fail-open: every HTTP-layer
/// register test submitted a payload that did not validate, and the only signal
/// was a `warn!` nobody asserted on.
fn request_with_facility(facility: Option<dpp_domain::FacilitySnapshot>) -> RegistrationRequest {
    RegistrationRequest {
        request_id: Uuid::now_v7(),
        passport_id: PassportId::new(),
        operator_identifier: "did:web:test.example".into(),
        operator_identifier_scheme: "did".into(),
        operator_name: "Test Operator GmbH".into(),
        facility_identifier: "LEGACY-FAC".into(),
        facility,
        product_category: "battery".into(),
        data_carrier_uri: "https://id.example.com/01/09506000134352/21/abc123".into(),
        schema_version: "2.0.0".into(),
        jws_signature: None,
        published_at: None,
        country_code: "DE".into(),
        granularity: RegistrationGranularity::Item,
        model_id: None,
        commodity_code: Some("85076000".into()),
        backup_url: None,
    }
}

/// A request whose payload passes `RegistrationPayload::validate` end to end.
fn valid_request() -> RegistrationRequest {
    request_with_facility(Some(dpp_domain::FacilitySnapshot {
        scheme: "gln".into(),
        value: "4012345000009".into(),
        name: "Default Plant".into(),
        country: "DE".into(),
        address: Some("1 Allee, Berlin".into()),
    }))
}

/// A request whose payload fails validation — an empty country on the operator
/// identifier.
fn invalid_request() -> RegistrationRequest {
    RegistrationRequest {
        country_code: String::new(),
        ..valid_request()
    }
}

#[test]
fn facility_identifier_prefers_full_snapshot() {
    let request = request_with_facility(Some(dpp_domain::FacilitySnapshot {
        scheme: "gln".into(),
        value: "4012345000009".into(),
        name: "Default Plant".into(),
        country: "DE".into(),
        address: Some("1 Allee, Berlin".into()),
    }));
    let fid = facility_identifier_for(&request);
    assert_eq!(fid.scheme, "gln");
    assert_eq!(fid.value, "4012345000009");
    assert_eq!(fid.name.as_deref(), Some("Default Plant"));
    assert_eq!(fid.country, "DE");
    assert_eq!(fid.address.as_deref(), Some("1 Allee, Berlin"));
}

#[test]
fn facility_identifier_falls_back_to_bare_value() {
    let fid = facility_identifier_for(&request_with_facility(None));
    assert_eq!(fid.scheme, "national");
    assert_eq!(fid.value, "LEGACY-FAC");
    assert!(fid.name.is_none());
    assert!(fid.country.is_empty());
}

#[test]
fn extract_gtin_from_valid_gs1_dl() {
    let uri = "https://id.odal-node.io/01/09506000134352/21/abc123";
    assert_eq!(
        extract_gtin_from_gs1_dl(uri),
        Some("09506000134352".to_owned())
    );
}

#[test]
fn extract_gtin_returns_none_for_non_gs1_uri() {
    assert_eq!(
        extract_gtin_from_gs1_dl("https://p.odal-node.io/some-uuid"),
        None
    );
    assert_eq!(
        extract_gtin_from_gs1_dl("https://id.example.com/01/short"),
        None
    );
}

#[test]
fn cached_token_expiry_check() {
    let fresh = CachedToken {
        access_token: "tok".into(),
        expires_at: Instant::now() + Duration::from_secs(3600),
    };
    assert!(!fresh.is_expired());

    let stale = CachedToken {
        access_token: "tok".into(),
        expires_at: Instant::now() + Duration::from_secs(10), // within 30s buffer
    };
    assert!(stale.is_expired());
}

// ---------------------------------------------------------------------------
// HTTP-layer tests: `register`/`check_status`/`notify_transfer` against a mock
// EU registry (real axum server on a random local port). These exercise the
// retry-classification logic (Retryable/Unreachable/Fatal) that the pure
// mapping tests above can't reach.
// ---------------------------------------------------------------------------

mod mock_server {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use axum::{
        Json, Router,
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use serde_json::Value;
    use tokio::sync::Mutex;

    /// Shared state for a mock EU registry: canned response queues per route,
    /// plus a hit counter on `/registrations` for retry-count assertions.
    #[derive(Default)]
    pub(super) struct MockState {
        pub(super) register_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        pub(super) register_hits: AtomicUsize,
        /// Envelopes the registry actually received on `/registrations`.
        /// Asserting on the wire body is the only way to catch a field the
        /// mapping states wrongly — a status-code assertion passes either way.
        pub(super) register_bodies: Mutex<VecDeque<Value>>,
        pub(super) status_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        pub(super) transfer_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        /// Bodies the registry actually received on `/transfer`. Asserting on
        /// the wire body is the only way to catch a field the adapter silently
        /// drops — a status-code assertion passes either way.
        pub(super) transfer_bodies: Mutex<VecDeque<Value>>,
    }

    async fn pop_or_500(queue: &Mutex<VecDeque<(StatusCode, Value)>>) -> Response {
        let (status, body) = queue.lock().await.pop_front().unwrap_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "no mock response queued"}),
        ));
        (status, Json(body)).into_response()
    }

    async fn token_handler() -> Response {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            })),
        )
            .into_response()
    }

    async fn register_handler(
        State(state): State<Arc<MockState>>,
        Json(body): Json<Value>,
    ) -> Response {
        state
            .register_hits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        state.register_bodies.lock().await.push_back(body);
        pop_or_500(&state.register_queue).await
    }

    async fn status_handler(
        State(state): State<Arc<MockState>>,
        Path(_id): Path<String>,
    ) -> Response {
        pop_or_500(&state.status_queue).await
    }

    async fn transfer_handler(
        State(state): State<Arc<MockState>>,
        Path(_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Response {
        state.transfer_bodies.lock().await.push_back(body);
        pop_or_500(&state.transfer_queue).await
    }

    /// Spawns a mock EU registry on a random local port and returns its base URL.
    pub(super) async fn spawn(state: Arc<MockState>) -> String {
        let app = Router::new()
            .route("/token", post(token_handler))
            .route("/registrations", post(register_handler))
            .route("/registrations/{id}/status", get(status_handler))
            .route("/registrations/{id}/transfer", post(transfer_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }
}

use mock_server::MockState;

fn mock_config(base_url: &str) -> EuRegistrySyncConfig {
    EuRegistrySyncConfig {
        endpoint: dpp_registry::RegistryEndpoint {
            authority: dpp_registry::RegistryAuthority::EuSandbox,
            base_url: base_url.to_string(),
            api_version: "1.0".into(),
            mtls_required: false,
            token_endpoint: Some(format!("{base_url}/token")),
        },
        client_id: "test-client".into(),
        client_secret: "test-secret".into(),
        max_retries: 3,
        retry_base_delay: Duration::from_millis(1),
        request_timeout: Duration::from_secs(5),
        allow_invalid_payloads: false,
    }
}

fn registered_response(registry_id: &str) -> serde_json::Value {
    serde_json::json!({
        "registryId": registry_id,
        "passportId": Uuid::now_v7(),
        "status": "registered",
        "updatedAt": Utc::now().to_rfc3339(),
    })
}

#[tokio::test]
async fn register_succeeds_and_maps_response() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-1")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let record = sync
        .register(valid_request())
        .await
        .expect("register should succeed");

    assert_eq!(record.status, RegistryStatus::Registered);
    assert_eq!(record.identifiers.registry_id, "EU-REG-1");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn register_fatal_4xx_does_not_retry() {
    let state = Arc::new(MockState::default());
    state.register_queue.lock().await.push_back((
        axum::http::StatusCode::BAD_REQUEST,
        serde_json::json!({"error": "invalid payload"}),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .register(valid_request())
        .await
        .expect_err("4xx should surface as an error");

    assert_eq!(
        state.register_hits.load(Ordering::SeqCst),
        1,
        "4xx must not be retried"
    );
    assert!(
        err.to_string().contains("registration rejected 400"),
        "got: {err}"
    );
}

#[tokio::test]
async fn register_retries_on_5xx_then_exhausts() {
    let state = Arc::new(MockState::default());
    {
        let mut q = state.register_queue.lock().await;
        for _ in 0..3 {
            q.push_back((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": "boom"}),
            ));
        }
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .register(valid_request())
        .await
        .expect_err("persistent 5xx should exhaust retries");

    assert_eq!(
        state.register_hits.load(Ordering::SeqCst),
        3,
        "must retry exactly max_retries times"
    );
    assert!(
        err.to_string().contains("failed after 3 attempts"),
        "got: {err}"
    );
}

#[tokio::test]
async fn register_retries_on_429_then_succeeds() {
    let state = Arc::new(MockState::default());
    {
        let mut q = state.register_queue.lock().await;
        q.push_back((
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({}),
        ));
        q.push_back((axum::http::StatusCode::OK, registered_response("EU-REG-2")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let record = sync
        .register(valid_request())
        .await
        .expect("should succeed after one retry");

    assert_eq!(record.status, RegistryStatus::Registered);
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn register_unreachable_registration_endpoint_is_not_retried() {
    // Token endpoint is live (so token acquisition succeeds)...
    let state = Arc::new(MockState::default());
    let base_url_alive = mock_server::spawn(state.clone()).await;

    // ...but the registration endpoint itself points at a dead port, so the
    // *second* request (not token acquisition) is what hits Unreachable.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = listener.local_addr().unwrap();
    drop(listener);

    let mut config = mock_config(&base_url_alive);
    config.endpoint.base_url = format!("http://{dead_addr}");
    let sync = EuRegistrySync::new(config).unwrap();

    let err = sync
        .register(valid_request())
        .await
        .expect_err("unreachable registry should error");

    assert!(err.to_string().contains("unreachable"), "got: {err}");
}

#[tokio::test]
async fn check_status_success() {
    let state = Arc::new(MockState::default());
    state.status_queue.lock().await.push_back((
        axum::http::StatusCode::OK,
        serde_json::json!({
            "registryId": "EU-REG-3",
            "status": "pending",
            "updatedAt": Utc::now().to_rfc3339(),
        }),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let record = sync
        .check_status(PassportId::new())
        .await
        .expect("check_status should succeed");

    assert_eq!(record.status, RegistryStatus::Pending);
    assert_eq!(record.identifiers.registry_id, "EU-REG-3");
}

#[tokio::test]
async fn check_status_404_is_fatal_not_found() {
    let state = Arc::new(MockState::default());
    state
        .status_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::NOT_FOUND, serde_json::json!({})));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .check_status(PassportId::new())
        .await
        .expect_err("404 should surface as not-found");

    assert!(
        err.to_string().contains("not found in EU registry"),
        "got: {err}"
    );
}

#[tokio::test]
async fn notify_transfer_success() {
    let state = Arc::new(MockState::default());
    state
        .transfer_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-4")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let record = sync
        .notify_transfer(&completed_transfer(), "EU-REG-4")
        .await
        .expect("notify_transfer should succeed");

    assert_eq!(record.status, RegistryStatus::Registered);
}

// ── Payload validation is fail-closed ───────────────────────────────────────

/// A payload that fails local validation must not reach the registry. A
/// registration is a regulatory submission, and the registry runs its own
/// conformity checks on receipt — submitting a known-bad record buys nothing.
#[tokio::test]
async fn invalid_payload_is_refused_and_never_submitted() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .register(invalid_request())
        .await
        .expect_err("an invalid payload must be refused");

    assert!(
        matches!(err, DppError::Validation(_)),
        "expected a validation error, got: {err:?}"
    );
    assert_eq!(
        state.register_hits.load(Ordering::SeqCst),
        0,
        "the registry was contacted despite the payload failing validation"
    );
}

/// The override exists because our local rules are an interpretation of the
/// spec and may themselves be wrong — a false positive must be workable around
/// without a code change. Setting it restores submission, loudly.
#[tokio::test]
async fn invalid_payload_is_submitted_when_the_override_is_set() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-9")));
    let base_url = mock_server::spawn(state.clone()).await;

    let mut config = mock_config(&base_url);
    config.allow_invalid_payloads = true;
    let sync = EuRegistrySync::new(config).unwrap();

    let record = sync
        .register(invalid_request())
        .await
        .expect("the override must permit submission");

    assert_eq!(record.identifiers.registry_id, "EU-REG-9");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 1);
}

/// The safe behaviour must be the one you get by doing nothing.
#[test]
fn overriding_validation_is_off_by_default() {
    assert!(!EuRegistrySyncConfig::sandbox("id".into(), "secret".into()).allow_invalid_payloads);
    assert!(!EuRegistrySyncConfig::production("id".into(), "secret".into()).allow_invalid_payloads);
}

/// The registration this node builds for a real operator must pass its own
/// validation. Fail-closed is only safe if that is true — otherwise it converts
/// a silent defect into a refusal of every registration.
///
/// This is the assertion the fixture could not make while the port carried no
/// operator legal name: `RegistrationPayload` requires a non-empty
/// `operatorId.name`, so every registration failed validation and the fail-open
/// path was load-bearing.
#[tokio::test]
async fn a_registration_this_node_builds_passes_validation() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-OK")));
    let base_url = mock_server::spawn(state.clone()).await;
    // No override: this must succeed on the fail-closed path.
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let record = sync
        .register(valid_request())
        .await
        .expect("a fully-populated registration must pass local validation");

    assert_eq!(record.identifiers.registry_id, "EU-REG-OK");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 1);
}

/// An operator with no legal name cannot be registered: the registry requires a
/// legal-entity name on the operator identifier.
#[tokio::test]
async fn a_registration_without_an_operator_legal_name_is_refused() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        operator_name: String::new(),
        ..valid_request()
    };
    let err = sync
        .register(request)
        .await
        .expect_err("an operator with no legal name must be refused");

    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 0);
}

// ── Registration level mapping ──────────────────────────────────────────────

/// Item level carries a per-unit identifier; the levels above it do not, since
/// they cover every unit they group.
#[test]
fn only_item_level_registrations_carry_an_item_identifier() {
    let mut request = valid_request();

    request.granularity = RegistrationGranularity::Item;
    assert!(item_id_for(&request).is_some());

    for granularity in [
        RegistrationGranularity::Model,
        RegistrationGranularity::Batch,
    ] {
        request.granularity = granularity;
        assert!(
            item_id_for(&request).is_none(),
            "a {granularity:?} registration covers a group, not one unit"
        );
    }
}

/// An unlinked model must stay absent rather than becoming a blank identifier,
/// which validation refuses.
#[test]
fn an_unlinked_model_is_absent_not_blank() {
    let mut request = valid_request();

    request.model_id = None;
    let level = level_for(&request);
    assert!(level.model_id.is_none());
    assert!(level.validate().is_ok());

    request.model_id = Some("MODEL-7".into());
    assert_eq!(level_for(&request).model_id.as_deref(), Some("MODEL-7"));
}

// ── Transfer notification carries the whole handover ────────────────────────

fn responsible(did: &str, name: &str, country: &str) -> ResponsibleOperator {
    ResponsibleOperator {
        did: did.to_owned(),
        name: name.to_owned(),
        role: OperatorRole::Manufacturer,
        eu_operator_id: None,
        eu_operator_id_scheme: None,
        country: country.to_owned(),
    }
}

/// A transfer both parties have signed and completed.
fn completed_transfer() -> TransferRecord {
    let completed = Utc::now();
    TransferRecord {
        transfer_id: Uuid::now_v7(),
        passport_id: PassportId::new(),
        from_operator: responsible("did:web:old.example", "Old Operator GmbH", "DE"),
        to_operator: responsible("did:web:new.example", "New Operator SARL", "FR"),
        reason: TransferReason::Remanufacturing,
        from_signature: Some("jws-from".to_owned()),
        to_signature: Some("jws-to".to_owned()),
        initiated_at: completed - chrono::Duration::hours(2),
        completed_at: Some(completed),
        rejected_at: None,
        cancelled_at: None,
        notes: None,
    }
}

/// The dual signatures are the evidence that both operators authorised the
/// handover, and both operators must be named. All of it was previously dropped
/// on the floor: the adapter sent empty strings and `None` signatures because
/// the port handed it only the incoming operator's identifier.
#[tokio::test]
async fn transfer_notification_carries_both_operators_and_both_signatures() {
    let state = Arc::new(MockState::default());
    state
        .transfer_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-T1")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let transfer = completed_transfer();
    sync.notify_transfer(&transfer, "EU-REG-T")
        .await
        .expect("a complete transfer must notify successfully");

    let sent = state
        .transfer_bodies
        .lock()
        .await
        .pop_front()
        .expect("the registry must have received a notification");

    assert_eq!(sent["fromOperator"]["name"], "Old Operator GmbH");
    assert_eq!(sent["fromOperator"]["country"], "DE");
    assert_eq!(sent["toOperator"]["name"], "New Operator SARL");
    assert_eq!(sent["toOperator"]["country"], "FR");
    assert_eq!(sent["fromSignature"], "jws-from");
    assert_eq!(sent["toSignature"], "jws-to");
    assert_eq!(
        sent["reason"], "remanufacturing",
        "the reason must travel as its stable wire form, not a hardcoded literal"
    );
}

/// A transfer whose operators are not identified must not reach the registry.
#[tokio::test]
async fn transfer_with_an_unidentified_operator_is_refused() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let mut transfer = completed_transfer();
    transfer.from_operator.name = String::new();

    let err = sync
        .notify_transfer(&transfer, "EU-REG-T")
        .await
        .expect_err("an unidentified outgoing operator must be refused");

    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert!(
        state.transfer_bodies.lock().await.is_empty(),
        "the registry was contacted despite the notification failing validation"
    );
}

/// The handover instant is what the registry is told about — not the moment the
/// notification happened to be sent.
#[tokio::test]
async fn a_pending_transfer_reports_its_initiation_time() {
    let state = Arc::new(MockState::default());
    state
        .transfer_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-T2")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let mut transfer = completed_transfer();
    transfer.completed_at = None;
    transfer.to_signature = None;
    let initiated = transfer.initiated_at;

    sync.notify_transfer(&transfer, "EU-REG-T")
        .await
        .expect("a pending transfer is still notifiable");

    let sent = state.transfer_bodies.lock().await.pop_front().unwrap();
    let reported: chrono::DateTime<Utc> = sent["transferredAt"]
        .as_str()
        .expect("transferredAt must be sent")
        .parse()
        .expect("transferredAt must be a timestamp");
    assert_eq!(
        reported, initiated,
        "a transfer still awaiting acceptance reports when it was initiated"
    );
    assert!(
        sent.get("toSignature").is_none(),
        "an unsigned acceptance must be absent, not an empty string"
    );
}

// ── Operator identifier mapping ─────────────────────────────────────────────

/// The scheme reaches the registry as the operator stated it. This used to be
/// hardcoded `"did"`, so a VAT/LEI/EORI/DUNS identifier was submitted as a DID —
/// a false statement `validate` cannot catch, because `did` is the one scheme
/// accepted without structural verification.
#[tokio::test]
async fn a_vat_operator_is_not_submitted_as_a_did() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-V")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        operator_identifier: "DE811234567".into(),
        operator_identifier_scheme: "vat".into(),
        ..valid_request()
    };
    sync.register(request)
        .await
        .expect("a VAT-scheme operator must register");

    let sent = state
        .register_bodies
        .lock()
        .await
        .pop_front()
        .expect("the registry must have received a payload");
    let operator = &sent["payload"]["operatorId"];
    assert_eq!(operator["scheme"], "vat");
    assert_eq!(operator["value"], "DE811234567");
    assert!(
        operator.get("did").is_none(),
        "a VAT number is not a DID and must not be sent as one: {operator}"
    );
}

/// A genuine DID still travels in the `did` field.
#[tokio::test]
async fn a_did_operator_keeps_its_did_field() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, registered_response("EU-REG-D")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    sync.register(valid_request())
        .await
        .expect("a did-scheme operator must register");

    let sent = state.register_bodies.lock().await.pop_front().unwrap();
    let operator = &sent["payload"]["operatorId"];
    assert_eq!(operator["scheme"], "did");
    assert_eq!(operator["did"], "did:web:test.example");
}

/// An identifier whose scheme could not be established is refused rather than
/// defaulted. This is the fail-closed half of the fix: the publish path leaves
/// the scheme empty when it cannot prove which scheme the stamped value is in.
#[tokio::test]
async fn an_operator_without_a_scheme_is_refused() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        operator_identifier_scheme: String::new(),
        ..valid_request()
    };
    let err = sync
        .register(request)
        .await
        .expect_err("an unscheme'd operator identifier must be refused");

    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 0);
}

/// The counterparty mapping prefers a stated EU identifier over the DID: an
/// EORI or VAT number is what a registry and a customs authority can act on.
#[test]
fn a_counterparty_with_an_eu_identifier_is_named_by_it() {
    let mut op = responsible("did:web:beta.example", "Beta SARL", "FR");
    op.eu_operator_id = Some("FR12345678901".into());
    op.eu_operator_id_scheme = Some("vat".into());

    let mapped = operator_identifier_for(&op);
    assert_eq!(mapped.scheme, "vat");
    assert_eq!(mapped.value, "FR12345678901");
    assert_eq!(
        mapped.did.as_deref(),
        Some("did:web:beta.example"),
        "the DID stays as the in-system handle"
    );
}

/// A value with no scheme is unusable — fall back to the DID rather than
/// guessing what the value is.
#[test]
fn a_counterparty_eu_identifier_without_a_scheme_is_not_used() {
    let mut op = responsible("did:web:beta.example", "Beta SARL", "FR");
    op.eu_operator_id = Some("FR12345678901".into());
    op.eu_operator_id_scheme = None;

    let mapped = operator_identifier_for(&op);
    assert_eq!(mapped.scheme, "did");
    assert_eq!(mapped.value, "did:web:beta.example");
}

/// The common case: no EU identifier held at all.
#[test]
fn a_counterparty_without_an_eu_identifier_falls_back_to_its_did() {
    let mapped = operator_identifier_for(&responsible("did:web:beta.example", "Beta", "FR"));
    assert_eq!(mapped.scheme, "did");
    assert_eq!(mapped.value, "did:web:beta.example");
}

// ── Status fidelity and idempotency ─────────────────────────────────────────

/// A registration the registry has accepted but not yet ruled on must map to
/// `Pending`, not success. Registration is validated asynchronously, so this is
/// the *expected* response to a submission — the drain turning it into
/// `registered` recorded every submission as complete.
#[test]
fn a_pending_response_stays_pending() {
    let resp = EuRegistryResponse {
        registry_id: "EU-REG-P".into(),
        passport_id: Uuid::nil(),
        status: RegistryStatusCode::Pending,
        message: None,
        rejection_reasons: None,
        updated_at: Utc::now(),
    };
    assert_eq!(
        EuRegistrySync::response_to_record(&resp).status,
        RegistryStatus::Pending
    );
}

/// A deactivated record is not a rejected one. Rejection means the submission
/// was defective and can be corrected; deactivation means the record is out of
/// service, which resubmitting does not fix.
#[test]
fn a_deactivated_record_is_not_reported_as_rejected() {
    let resp = EuRegistryResponse {
        registry_id: "EU-REG-D".into(),
        passport_id: Uuid::nil(),
        status: RegistryStatusCode::Deactivated,
        message: None,
        rejection_reasons: None,
        updated_at: Utc::now(),
    };
    let mapped = EuRegistrySync::response_to_record(&resp).status;
    assert_eq!(mapped, RegistryStatus::Deactivated);
    assert_ne!(mapped, RegistryStatus::Rejected);

    let status = StatusResponse {
        registry_id: "EU-REG-D".into(),
        status: RegistryStatusCode::Deactivated,
        updated_at: Utc::now(),
        message: None,
    };
    assert_eq!(
        EuRegistrySync::status_to_record(&status).status,
        RegistryStatus::Deactivated
    );
}

/// The idempotency key is the request's own, carried on the queued payload, so
/// every retry of the same registration presents the same key. Minting one per
/// attempt made a submission the registry had already committed look like a
/// fresh one on the next try.
#[tokio::test]
async fn retrying_a_registration_reuses_its_request_id() {
    let state = Arc::new(MockState::default());
    // Two 5xx then a success: one logical registration, three submissions.
    {
        let mut q = state.register_queue.lock().await;
        for _ in 0..2 {
            q.push_back((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": "upstream"}),
            ));
        }
        q.push_back((axum::http::StatusCode::OK, registered_response("EU-REG-I")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = valid_request();
    let expected = request.request_id;
    sync.register(request)
        .await
        .expect("should succeed after retries");

    let bodies = state.register_bodies.lock().await;
    assert_eq!(
        bodies.len(),
        3,
        "the mock should have seen three submissions"
    );
    for body in bodies.iter() {
        assert_eq!(
            body["requestId"].as_str().unwrap(),
            expected.to_string(),
            "every retry must present the same idempotency key"
        );
    }
}

/// The key is frozen into the queued payload, so it survives a restart: the
/// drain rebuilds the request from JSON and must get the same key back.
#[test]
fn the_request_id_survives_the_outbox_round_trip() {
    let request = valid_request();
    let expected = request.request_id;
    let payload = serde_json::to_value(&request).unwrap();
    let replayed: RegistrationRequest = serde_json::from_value(payload).unwrap();
    assert_eq!(replayed.request_id, expected);
}
