use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chrono::Utc;
use dpp_domain::passport::PassportId;
use dpp_registry::RegistryStatusCode;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_domain::operator::{OperatorRole, ResponsibleOperator};
use dpp_domain::ports::registry_sync::{
    RegistrationGranularity, RegistrationRequest, RegistryStatus, RegistrySyncPort,
    SubmissionAcknowledgement, SubmissionConfirmation, SubmissionLookup, SubmissionReport,
    TransferReport,
};
use dpp_domain::transfer::{TransferReason, TransferRecord};

use super::client::EuRegistrySync;
use super::config::EuRegistrySyncConfig;
use super::mapping::{
    facility_identifier_for, item_id_for, level_for, operator_identifier_for, product_id_for,
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
fn a_status_reply_of_registered_is_a_registered_record() {
    let resp = StatusResponse {
        registry_id: "EU-REG-2026-00001".into(),
        status: RegistryStatusCode::Registered,
        updated_at: Utc::now(),
        message: None,
    };
    let record = EuRegistrySync::status_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Registered);
    assert_eq!(record.registration_id, "EU-REG-2026-00001");
}

/// `rejected` and `pending` were states of a submission, and the port reports
/// those as a [`SubmissionReport`]. A *record* that answers with one has a state
/// the port has no name for, and carries it as the registry said it rather than
/// reading it as one of the three it does name.
#[test]
fn a_status_reply_of_rejected_is_carried_as_the_registry_said_it() {
    let resp = StatusResponse {
        registry_id: "EU-REG-2026-00002".into(),
        status: RegistryStatusCode::Rejected,
        updated_at: Utc::now(),
        message: Some("invalid data".into()),
    };
    let record = EuRegistrySync::status_to_record(&resp);
    assert_eq!(
        record.status,
        RegistryStatus::Unrecognised("rejected".into())
    );
}

#[test]
fn a_status_reply_of_pending_is_carried_as_the_registry_said_it() {
    let resp = StatusResponse {
        registry_id: "EU-REG-2026-00003".into(),
        status: RegistryStatusCode::Pending,
        updated_at: Utc::now(),
        message: None,
    };
    let record = EuRegistrySync::status_to_record(&resp);
    assert_eq!(
        record.status,
        RegistryStatus::Unrecognised("pending".into())
    );
    assert_eq!(record.registration_id, "EU-REG-2026-00003");
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
        batch_id: None,
        item_serial: Some("abc123".into()),
        product_identifier: Some(dpp_domain::ProductIdentifier::gs1(
            dpp_domain::Gtin::parse("09506000134352").unwrap(),
        )),
        service_provider: None,
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
fn a_gs1_identifier_is_registered_as_its_gtin() {
    let product_id = product_id_for(&valid_request()).expect("a GTIN registers");
    assert_eq!(product_id.scheme, "gtin");
    assert_eq!(product_id.value, "09506000134352");
}

/// A passport identified without GS1 has no GTIN anywhere, and its carrier is a
/// `/dpp/{id}` link. It registers under its own identifier, not under a value
/// scraped from the carrier or the internal passport id.
#[test]
fn a_did_identifier_is_registered_as_itself_not_as_the_passport_id() {
    let request = RegistrationRequest {
        product_identifier: Some(
            dpp_domain::ProductIdentifier::did("did:web:passports.example.com:item:0001").unwrap(),
        ),
        data_carrier_uri: "https://id.example.com/dpp/0190a1b2-0000-7000-8000-000000000001".into(),
        ..valid_request()
    };
    let product_id = product_id_for(&request).expect("a DID registers");
    assert_eq!(product_id.value, "did:web:passports.example.com:item:0001");
    assert_ne!(product_id.scheme, "passport_id");
    assert_ne!(product_id.value, request.passport_id.to_string());
}

/// A request queued before registrations carried an identifier is refused
/// before anything is sent, rather than completed with an invented one.
#[tokio::test]
async fn a_registration_without_a_product_identifier_is_refused() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        product_identifier: None,
        ..valid_request()
    };
    let err = sync
        .register(request)
        .await
        .expect_err("a registration with no product identifier must be refused");

    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 0);
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
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use dpp_registry::{
        IDEMPOTENCY_KEY_HEADER, REGISTRATION_PATH, STATUS_PATH_TEMPLATE, TASK_RESULT_PATH_TEMPLATE,
        TASKS_PATH, TRANSFER_PATH_TEMPLATE,
    };
    use serde_json::Value;
    use tokio::sync::Mutex;

    /// Shared state for a mock EU registry: canned response queues per route,
    /// plus a hit counter on the registration route for retry-count assertions.
    #[derive(Default)]
    pub(super) struct MockState {
        pub(super) register_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        pub(super) register_hits: AtomicUsize,
        /// Envelopes the registry actually received on the registration route.
        /// Asserting on the wire body is the only way to catch a field the
        /// mapping states wrongly — a status-code assertion passes either way.
        pub(super) register_bodies: Mutex<VecDeque<Value>>,
        /// The `Idempotency-Key` header of each registration, `None` when the
        /// request carried none. A header is not in the body, so `register_bodies`
        /// cannot see it.
        pub(super) register_keys: Mutex<VecDeque<Option<String>>>,
        pub(super) status_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        /// Pages of the dashboard's task list, one popped per request.
        pub(super) tasks_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        /// Dashboard task results, one popped per request.
        pub(super) task_result_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        /// The task identifier each result was read by, and the `page` each
        /// task-list request asked for.
        pub(super) task_results_read: Mutex<VecDeque<String>>,
        pub(super) task_pages_asked: Mutex<VecDeque<String>>,
        /// Task-list pages by page number. A page named here is answered from
        /// it, whatever order it is asked in; a page not named falls back to
        /// `tasks_queue`. What a long list needs: which page is asked for, and in
        /// what order, is the thing under test.
        pub(super) tasks_by_page: Mutex<std::collections::HashMap<String, (StatusCode, Value)>>,
        /// Task results by task identifier, answered the same way.
        pub(super) results_by_task: Mutex<std::collections::HashMap<String, (StatusCode, Value)>>,
        pub(super) transfer_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        /// The `Idempotency-Key` header of each transfer notification, `None`
        /// when the request carried none.
        pub(super) transfer_keys: Mutex<VecDeque<Option<String>>>,
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
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        state
            .register_hits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        state.register_keys.lock().await.push_back(
            headers
                .get(IDEMPOTENCY_KEY_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        );
        state.register_bodies.lock().await.push_back(body);
        pop_or_500(&state.register_queue).await
    }

    async fn status_handler(
        State(state): State<Arc<MockState>>,
        Path(_id): Path<String>,
    ) -> Response {
        pop_or_500(&state.status_queue).await
    }

    async fn tasks_handler(
        State(state): State<Arc<MockState>>,
        axum::extract::Query(query): axum::extract::Query<
            std::collections::HashMap<String, String>,
        >,
    ) -> Response {
        let page = query.get("page").cloned().unwrap_or_default();
        state.task_pages_asked.lock().await.push_back(page.clone());
        if let Some((status, body)) = state.tasks_by_page.lock().await.get(&page).cloned() {
            return (status, Json(body)).into_response();
        }
        pop_or_500(&state.tasks_queue).await
    }

    async fn task_result_handler(
        State(state): State<Arc<MockState>>,
        Path(id): Path<String>,
    ) -> Response {
        state.task_results_read.lock().await.push_back(id.clone());
        if let Some((status, body)) = state.results_by_task.lock().await.get(&id).cloned() {
            return (status, Json(body)).into_response();
        }
        pop_or_500(&state.task_result_queue).await
    }

    async fn transfer_handler(
        State(state): State<Arc<MockState>>,
        Path(_id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        state.transfer_keys.lock().await.push_back(
            headers
                .get(IDEMPOTENCY_KEY_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        );
        state.transfer_bodies.lock().await.push_back(body);
        pop_or_500(&state.transfer_queue).await
    }

    /// Spawns a mock EU registry on a random local port and returns its base URL.
    pub(super) async fn spawn(state: Arc<MockState>) -> String {
        let app = Router::new()
            .route("/token", post(token_handler))
            // The paths are core's own constants, not literals: a mock that
            // spells them itself agrees with the adapter whatever core says, and
            // that agreement is what let the invented registration path pass.
            // The two templates use `{id}`, which is also axum's capture syntax.
            .route(REGISTRATION_PATH, post(register_handler))
            .route(STATUS_PATH_TEMPLATE, get(status_handler))
            .route(TRANSFER_PATH_TEMPLATE, post(transfer_handler))
            // The dashboard is a separate service of the registry, on its own
            // base URL, and a submission's outcome is read from it.
            .nest(
                "/dashboard",
                Router::new()
                    .route(TASKS_PATH, get(tasks_handler))
                    .route(TASK_RESULT_PATH_TEMPLATE, get(task_result_handler)),
            )
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
            dashboard_base_url: format!("{base_url}/dashboard"),
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

/// What the registry answers a submission with: a handle on the check it will
/// make, never a registration.
fn accepted_response(correlation_id: &str) -> serde_json::Value {
    serde_json::json!({
        "correlationId": correlation_id,
        "outcome": "PROCESSING",
    })
}

/// The acknowledgement a submission under `correlation_id` produces.
fn accepted(correlation_id: &str) -> SubmissionAcknowledgement {
    SubmissionAcknowledgement::Accepted {
        correlation_id: correlation_id.to_owned(),
    }
}

#[tokio::test]
async fn register_succeeds_and_returns_the_correlation_id() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, accepted_response("CORR-1")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let acknowledgement = sync
        .register(valid_request())
        .await
        .expect("register should succeed");

    // A submission is acknowledged with a handle, not registered: the registry
    // rules on it afterwards, and only then generates a registration identifier.
    assert_eq!(acknowledgement, accepted("CORR-1"));
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
        q.push_back((axum::http::StatusCode::OK, accepted_response("CORR-2")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let acknowledgement = sync
        .register(valid_request())
        .await
        .expect("should succeed after one retry");

    assert_eq!(acknowledgement, accepted("CORR-2"));
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
            "status": "registered",
            "updatedAt": Utc::now().to_rfc3339(),
        }),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    // Asked by the registration identifier, which the registry generated: it
    // never received this node's passport id.
    let record = sync
        .check_status("EU-REG-3")
        .await
        .expect("check_status should succeed");

    assert_eq!(record.status, RegistryStatus::Registered);
    assert_eq!(record.registration_id, "EU-REG-3");
}

/// A registration identifier is a URI in the registry's own guide. It is one
/// path segment, so a `/` in it cannot add segments to the route.
#[tokio::test]
async fn a_registration_id_is_escaped_into_one_path_segment() {
    let state = Arc::new(MockState::default());
    state.status_queue.lock().await.push_back((
        axum::http::StatusCode::OK,
        serde_json::json!({
            "registryId": "https://reg.example/dpp/1",
            "status": "registered",
            "updatedAt": Utc::now().to_rfc3339(),
        }),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let record = sync
        .check_status("https://reg.example/dpp/1")
        .await
        .expect("the route matches only if the id stayed one segment");

    assert_eq!(record.registration_id, "https://reg.example/dpp/1");
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
        .check_status("EU-REG-3")
        .await
        .expect_err("404 should surface as not-found");

    assert!(
        err.to_string().contains("status check failed 404"),
        "got: {err}"
    );
}

// ── Reading a submission back ────────────────────────────────────────────────

fn task_page(tasks: serde_json::Value) -> (axum::http::StatusCode, serde_json::Value) {
    (
        axum::http::StatusCode::OK,
        serde_json::json!({ "content": tasks }),
    )
}

fn registration_task(correlation_id: &str, task_id: u64, status: &str) -> serde_json::Value {
    serde_json::json!({
        "taskId": task_id,
        "type": "DPP_REGISTRATION",
        "correlationId": correlation_id,
        "status": status,
    })
}

#[tokio::test]
async fn a_submission_still_being_checked_is_processing_and_reads_no_result() {
    let state = Arc::new(MockState::default());
    state
        .tasks_queue
        .lock()
        .await
        .push_back(task_page(serde_json::json!([registration_task(
            "CORR-1",
            7,
            "PROCESSING"
        )])));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync.check_submission("CORR-1").await.expect("a report");

    assert_eq!(report, SubmissionReport::Processing);
    assert!(
        state.task_results_read.lock().await.is_empty(),
        "an unfinished task has no result worth reading"
    );
}

#[tokio::test]
async fn a_successful_submission_reports_the_registration_identifier_from_its_result() {
    let state = Arc::new(MockState::default());
    state
        .tasks_queue
        .lock()
        .await
        .push_back(task_page(serde_json::json!([
            registration_task("CORR-OTHER", 6, "SUCCESS"),
            registration_task("CORR-1", 7, "SUCCESS"),
        ])));
    state.task_result_queue.lock().await.push_back((
        axum::http::StatusCode::OK,
        serde_json::json!({
            "status": "SUCCESS",
            "resultPayload": { "report": { "itemDetails": [{
                "uniqueProductIdentifier": "https://id.example.com/01/09506000134352/21/abc123",
                "outcome": "ACCEPTED",
                "registrationIdentifier": "EU-REG-7",
            }] } },
        }),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync.check_submission("CORR-1").await.expect("a report");

    assert_eq!(
        report,
        SubmissionReport::Registered {
            registration_id: "EU-REG-7".into()
        }
    );
    assert_eq!(
        state
            .task_results_read
            .lock()
            .await
            .iter()
            .collect::<Vec<_>>(),
        ["7"],
        "the result is read by the task's own identifier, not the correlation id"
    );
}

#[tokio::test]
async fn a_failed_submission_is_refused_with_the_registrys_error_code() {
    let state = Arc::new(MockState::default());
    state
        .tasks_queue
        .lock()
        .await
        .push_back(task_page(serde_json::json!([registration_task(
            "CORR-1", 7, "FAILURE"
        )])));
    state.task_result_queue.lock().await.push_back((
        axum::http::StatusCode::OK,
        serde_json::json!({
            "status": "FAILURE",
            "resultPayload": { "report": { "itemDetails": [{
                "uniqueProductIdentifier": "https://id.example.com/01/09506000134352/21/abc123",
                "outcome": "REJECTED",
                "errorCode": "NOT_RESOLVABLE_UPI",
            }] } },
        }),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let SubmissionReport::Refused { reason } =
        sync.check_submission("CORR-1").await.expect("a report")
    else {
        panic!("a failed submission is refused");
    };
    assert!(reason.contains("NOT_RESOLVABLE_UPI"), "{reason}");
}

/// A submission the list does not show (yet) is not a verdict either way.
#[tokio::test]
async fn a_submission_the_dashboard_does_not_list_is_still_processing() {
    let state = Arc::new(MockState::default());
    state
        .tasks_queue
        .lock()
        .await
        .push_back(task_page(serde_json::json!([registration_task(
            "CORR-ELSE",
            1,
            "SUCCESS"
        )])));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    assert_eq!(
        sync.check_submission("CORR-1").await.expect("a report"),
        SubmissionReport::Processing
    );
}

/// The task is found by paging the list, since no route takes a correlation
/// identifier: a full page that does not hold it means asking for the next.
#[tokio::test]
async fn the_task_list_is_paged_until_the_submission_is_found() {
    let state = Arc::new(MockState::default());
    let full_page: Vec<_> = (0..50)
        .map(|n| registration_task(&format!("CORR-FILL-{n}"), n, "SUCCESS"))
        .collect();
    {
        let mut q = state.tasks_queue.lock().await;
        q.push_back(task_page(serde_json::Value::Array(full_page)));
        q.push_back(task_page(serde_json::json!([registration_task(
            "CORR-1",
            99,
            "PROCESSING"
        )])));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync.check_submission("CORR-1").await.expect("a report");

    assert_eq!(report, SubmissionReport::Processing);
    assert_eq!(
        state
            .task_pages_asked
            .lock()
            .await
            .iter()
            .collect::<Vec<_>>(),
        ["0", "1"]
    );
}

/// The walk is capped, and a task past the cap is not a task that is not listed:
/// the search ran out. It is reported as a state the node cannot rule on, which
/// keeps the poll going and says why, rather than as `Processing`, which would
/// read as the registry still working on it.
#[tokio::test]
async fn a_search_that_runs_out_of_pages_says_so() {
    use super::mapping::MAX_TASK_PAGES;

    let state = Arc::new(MockState::default());
    let full_page = || {
        serde_json::Value::Array(
            (0..50)
                .map(|n| registration_task(&format!("CORR-FILL-{n}"), n, "SUCCESS"))
                .collect(),
        )
    };
    {
        let mut q = state.tasks_queue.lock().await;
        for _ in 0..MAX_TASK_PAGES {
            q.push_back(task_page(full_page()));
        }
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync.check_submission("CORR-1").await.expect("a report");

    assert!(
        matches!(&report, SubmissionReport::Unrecognised { state } if state.contains("not found within")),
        "a search that ran out is not `Processing`: {report:?}"
    );
    assert!(!report.is_terminal(), "and it keeps the poll going");
    assert_eq!(
        state.task_pages_asked.lock().await.len(),
        MAX_TASK_PAGES as usize,
        "the walk stops at the cap"
    );
}

/// A page of the task list that also says how long the list is.
fn task_page_of(
    total: u64,
    tasks: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    (
        axum::http::StatusCode::OK,
        serde_json::json!({ "content": tasks, "totalElements": total }),
    )
}

/// Fifty tasks that are not the one being looked for.
fn filler_page(total: u64, prefix: &str) -> (axum::http::StatusCode, serde_json::Value) {
    task_page_of(
        total,
        serde_json::Value::Array(
            (0..50)
                .map(|n| registration_task(&format!("{prefix}-{n}"), 1_000 + n, "SUCCESS"))
                .collect(),
        ),
    )
}

/// 🚨 A list longer than the cap is read from both ends. The order is not known,
/// and a task just submitted is at the front of a newest-first list and at the
/// back of an oldest-first one; reading only the front never finds it in the
/// second kind once the list outgrows the cap.
#[tokio::test]
async fn a_task_at_the_back_of_a_long_list_is_found() {
    let state = Arc::new(MockState::default());
    {
        let mut pages = state.tasks_by_page.lock().await;
        pages.insert("0".into(), filler_page(5_000, "OLD"));
        // The last of 100 pages: where an oldest-first list puts a new task.
        pages.insert(
            "99".into(),
            task_page_of(
                5_000,
                serde_json::json!([registration_task("CORR-NEW", 4_999, "PROCESSING")]),
            ),
        );
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync.check_submission("CORR-NEW").await.expect("a report");

    assert_eq!(report, SubmissionReport::Processing);
    assert_eq!(
        state
            .task_pages_asked
            .lock()
            .await
            .iter()
            .collect::<Vec<_>>(),
        ["0", "99"],
        "the first page says how long the list is, and the next read is its far end"
    );
}

/// A search that read only the ends of a long list has not shown the task to be
/// unlisted, and says so instead of reporting the registry as still working.
#[tokio::test]
async fn a_long_list_that_does_not_hold_the_task_at_either_end_says_the_search_ran_out() {
    let state = Arc::new(MockState::default());
    {
        let mut pages = state.tasks_by_page.lock().await;
        for page in (0..10).chain(90..100) {
            pages.insert(page.to_string(), filler_page(5_000, &format!("P{page}")));
        }
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync
        .check_submission("CORR-MIDDLE")
        .await
        .expect("a report");

    assert!(
        matches!(&report, SubmissionReport::Unrecognised { state } if state.contains("not found within")),
        "got {report:?}"
    );
    let mut asked: Vec<u32> = state
        .task_pages_asked
        .lock()
        .await
        .iter()
        .map(|p| p.parse().unwrap())
        .collect();
    asked.sort_unstable();
    assert_eq!(
        asked,
        (0..10).chain(90..100).collect::<Vec<u32>>(),
        "ten pages from each end, and none from the middle"
    );
}

// ── Finding a submission whose handle was lost ───────────────────────────────

/// A finished task's result, listing the passports it was about.
fn result_naming(
    upis: &[&str],
    registration: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let items: Vec<_> = upis
        .iter()
        .map(|upi| {
            serde_json::json!({
                "uniqueProductIdentifier": upi,
                "outcome": "ACCEPTED",
                "registrationIdentifier": registration,
            })
        })
        .collect();
    (
        axum::http::StatusCode::OK,
        serde_json::json!({
            "status": "SUCCESS",
            "resultPayload": { "report": { "itemDetails": items } },
        }),
    )
}

const SOMEONE_ELSES: &str = "https://id.example.com/01/09506000134369";

/// 🚨 The handle a replayed key left us without is found again, by the one thing
/// the registry reports each passport against: the identifier it was submitted
/// under.
#[tokio::test]
async fn a_lost_handle_is_found_by_the_identifier_the_passport_was_submitted_under() {
    let request = valid_request();
    let upi = request.data_carrier_uri.clone();

    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([
            registration_task("CORR-A", 1, "SUCCESS"),
            registration_task("CORR-B", 2, "SUCCESS"),
            registration_task("CORR-C", 3, "SUCCESS"),
        ])),
    );
    {
        let mut results = state.results_by_task.lock().await;
        results.insert("1".into(), result_naming(&[SOMEONE_ELSES], Some("REG-A")));
        results.insert(
            "2".into(),
            result_naming(&[upi.as_str()], Some("REG-FOUND")),
        );
        results.insert("3".into(), result_naming(&[SOMEONE_ELSES], Some("REG-C")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let lookup = sync.find_submission(&request).await.expect("a lookup");

    assert_eq!(
        lookup,
        SubmissionLookup::Found {
            correlation_id: "CORR-B".into(),
            report: SubmissionReport::Registered {
                registration_id: "REG-FOUND".into()
            },
        },
        "the handle and the ruling, from the task that reports this identifier"
    );
}

/// 🚨 An identifier is not unique to a passport: a successor can be submitted
/// under its predecessor's. Choosing between two submissions that report it would
/// give a passport another passport's registration, so the lookup does not.
#[tokio::test]
async fn two_submissions_reporting_one_identifier_are_not_chosen_between() {
    let request = valid_request();
    let upi = request.data_carrier_uri.clone();

    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([
            registration_task("CORR-PREDECESSOR", 1, "SUCCESS"),
            registration_task("CORR-SUCCESSOR", 2, "SUCCESS"),
        ])),
    );
    {
        let mut results = state.results_by_task.lock().await;
        results.insert("1".into(), result_naming(&[upi.as_str()], Some("REG-OLD")));
        results.insert("2".into(), result_naming(&[upi.as_str()], Some("REG-NEW")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let lookup = sync.find_submission(&request).await.expect("a lookup");

    assert_eq!(
        lookup,
        SubmissionLookup::Ambiguous {
            candidates: vec!["CORR-PREDECESSOR".into(), "CORR-SUCCESSOR".into()]
        }
    );
}

/// A task still being checked reports no passport, so it may be the one and
/// cannot be told from one that is not. Not finding the identifier while one is
/// on the list does not say the registry holds none.
#[tokio::test]
async fn an_unfinished_task_means_not_finding_the_identifier_proves_nothing() {
    let request = valid_request();

    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([
            registration_task("CORR-A", 1, "SUCCESS"),
            registration_task("CORR-B", 2, "PROCESSING"),
        ])),
    );
    state
        .results_by_task
        .lock()
        .await
        .insert("1".into(), result_naming(&[SOMEONE_ELSES], Some("REG-A")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    assert_eq!(
        sync.find_submission(&request).await.expect("a lookup"),
        SubmissionLookup::NotFound { exhaustive: false }
    );
}

/// With every task finished, read, and none naming the identifier, the lookup can
/// say it looked at all of it.
#[tokio::test]
async fn a_complete_list_without_the_identifier_says_it_was_all_read() {
    let request = valid_request();

    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([registration_task(
            "CORR-A", 1, "SUCCESS"
        )])),
    );
    state
        .results_by_task
        .lock()
        .await
        .insert("1".into(), result_naming(&[SOMEONE_ELSES], Some("REG-A")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    assert_eq!(
        sync.find_submission(&request).await.expect("a lookup"),
        SubmissionLookup::NotFound { exhaustive: true }
    );
}

/// Only registrations are read. A task of another kind has no passport result to
/// look at, and reading it is a request wasted on every pass.
#[tokio::test]
async fn a_task_of_another_kind_is_not_read_looking_for_a_registration() {
    let request = valid_request();

    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([{
            "taskId": 9,
            "type": "OPERATOR_ENROLMENT",
            "correlationId": "CORR-X",
            "status": "SUCCESS",
        }])),
    );
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    sync.find_submission(&request).await.expect("a lookup");

    assert!(state.task_results_read.lock().await.is_empty());
}

/// A finished task's result does not change, so it is read once. Looking for a
/// lost handle repeats every pass until it is found; without this each pass
/// would read every result in the list again.
#[tokio::test]
async fn a_finished_result_is_read_once_however_often_the_lookup_runs() {
    let request = valid_request();

    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([
            registration_task("CORR-A", 1, "SUCCESS"),
            registration_task("CORR-B", 2, "SUCCESS"),
        ])),
    );
    {
        let mut results = state.results_by_task.lock().await;
        results.insert("1".into(), result_naming(&[SOMEONE_ELSES], Some("REG-A")));
        results.insert("2".into(), result_naming(&[SOMEONE_ELSES], Some("REG-B")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    for _ in 0..3 {
        sync.find_submission(&request).await.expect("a lookup");
    }

    assert_eq!(
        state.task_results_read.lock().await.len(),
        2,
        "two tasks, three lookups, two reads"
    );
}

// ── Confirming a handle a person supplied ────────────────────────────────────

/// A registry with one finished submission, `CORR-1`, reporting `upis`.
async fn registry_holding(upis: &[&str]) -> (Arc<MockState>, EuRegistrySync) {
    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([registration_task(
            "CORR-1", 1, "SUCCESS"
        )])),
    );
    state
        .results_by_task
        .lock()
        .await
        .insert("1".into(), result_naming(upis, Some("REG-1")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();
    (state, sync)
}

/// 🚨 A handle is confirmed by what the submission it names reports, never by the
/// person's say-so: this is the check that stops a typo giving a passport another
/// passport's registration.
#[tokio::test]
async fn a_handle_whose_submission_reports_this_identifier_is_confirmed() {
    let request = valid_request();
    let (_, sync) = registry_holding(&[request.data_carrier_uri.as_str()]).await;

    assert_eq!(
        sync.confirm_submission(&request, "CORR-1")
            .await
            .expect("a confirmation"),
        SubmissionConfirmation::Confirmed {
            report: SubmissionReport::Registered {
                registration_id: "REG-1".into()
            }
        },
        "the handle is right, and what it leads to is read in the same step"
    );
}

#[tokio::test]
async fn a_handle_whose_submission_reports_other_identifiers_is_a_mismatch() {
    let request = valid_request();
    let (_, sync) = registry_holding(&[SOMEONE_ELSES]).await;

    assert_eq!(
        sync.confirm_submission(&request, "CORR-1")
            .await
            .expect("a confirmation"),
        SubmissionConfirmation::Mismatch {
            reported: vec![SOMEONE_ELSES.into()]
        },
        "the handle names a real submission, and not this passport's"
    );
}

/// A submission refused before any passport was read reports none. It cannot be
/// shown to be this passport's, which is a mismatch and not a confirmation.
#[tokio::test]
async fn a_submission_that_reports_no_passport_is_a_mismatch_with_none() {
    let request = valid_request();
    let (_, sync) = registry_holding(&[]).await;

    assert_eq!(
        sync.confirm_submission(&request, "CORR-1")
            .await
            .expect("a confirmation"),
        SubmissionConfirmation::Mismatch { reported: vec![] }
    );
}

/// A match is by the identifier and nothing nearer. One that differs only by a
/// trailing slash is another identifier.
#[tokio::test]
async fn an_identifier_that_merely_resembles_this_one_is_not_this_one() {
    let request = valid_request();
    let near = format!("{}/", request.data_carrier_uri);
    let (_, sync) = registry_holding(&[near.as_str()]).await;

    assert!(
        !sync
            .confirm_submission(&request, "CORR-1")
            .await
            .expect("a confirmation")
            .is_confirmed()
    );
}

/// A submission still being checked reports no passport yet. That is not a
/// mismatch, and no result is read for it: there is nothing in it to match.
#[tokio::test]
async fn a_submission_still_being_checked_is_neither_confirmed_nor_a_mismatch() {
    let request = valid_request();
    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([registration_task(
            "CORR-1",
            1,
            "PROCESSING"
        )])),
    );
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    assert_eq!(
        sync.confirm_submission(&request, "CORR-1")
            .await
            .expect("a confirmation"),
        SubmissionConfirmation::StillChecking
    );
    assert!(state.task_results_read.lock().await.is_empty());
}

/// A handle no task carries names nothing, and with every task read that is
/// certain.
#[tokio::test]
async fn a_handle_no_task_carries_names_nothing_when_all_were_read() {
    let request = valid_request();
    let (_, sync) = registry_holding(&[request.data_carrier_uri.as_str()]).await;

    assert_eq!(
        sync.confirm_submission(&request, "CORR-TYPO")
            .await
            .expect("a confirmation"),
        SubmissionConfirmation::Unlisted { exhaustive: true }
    );
}

/// With a list too long to read in full, the same answer is not certain, and says
/// so: the handle may be further on.
#[tokio::test]
async fn a_handle_missing_from_a_long_list_says_not_all_of_it_was_read() {
    let request = valid_request();
    let state = Arc::new(MockState::default());
    {
        let mut pages = state.tasks_by_page.lock().await;
        for page in (0..10).chain(90..100) {
            pages.insert(page.to_string(), filler_page(5_000, &format!("P{page}")));
        }
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    assert_eq!(
        sync.confirm_submission(&request, "CORR-MIDDLE")
            .await
            .expect("a confirmation"),
        SubmissionConfirmation::Unlisted { exhaustive: false }
    );
}

/// Confirming reads the one task the handle names, not every result in the list
/// as a lookup does.
#[tokio::test]
async fn confirming_reads_only_the_submission_the_handle_names() {
    let request = valid_request();
    let state = Arc::new(MockState::default());
    state.tasks_by_page.lock().await.insert(
        "0".into(),
        task_page(serde_json::json!([
            registration_task("CORR-A", 1, "SUCCESS"),
            registration_task("CORR-1", 2, "SUCCESS"),
            registration_task("CORR-B", 3, "SUCCESS"),
        ])),
    );
    state.results_by_task.lock().await.insert(
        "2".into(),
        result_naming(&[request.data_carrier_uri.as_str()], Some("REG-1")),
    );
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    sync.confirm_submission(&request, "CORR-1")
        .await
        .expect("a confirmation");

    assert_eq!(
        state
            .task_results_read
            .lock()
            .await
            .iter()
            .collect::<Vec<_>>(),
        ["2"]
    );
}

#[tokio::test]
async fn an_unreachable_dashboard_cannot_confirm_a_handle() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    sync.confirm_submission(&valid_request(), "CORR-1")
        .await
        .expect_err("a registry that cannot be read confirms nothing");
}

#[tokio::test]
async fn an_unreachable_dashboard_is_an_error_not_a_verdict() {
    let state = Arc::new(MockState::default());
    // Nothing queued: the mock answers 500 on every attempt.
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .check_submission("CORR-1")
        .await
        .expect_err("a registry that cannot be read says nothing about the submission");
    assert!(err.to_string().contains("failed after 3 attempts"), "{err}");
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

    let report = sync
        .notify_transfer(&completed_transfer(), "EU-REG-4")
        .await
        .expect("notify_transfer should succeed");

    // The record stays in service with the handover applied: that is the
    // registry taking the notification, not a status to be passed on.
    assert_eq!(report, TransferReport::Accepted);
}

/// 🚨 The notification is sent under the handover's own identity. Three of the
/// answers end in the drain sending it again, and the key is what makes that the
/// same notification and not a second: it must be the transfer's, and the same
/// on every attempt.
#[tokio::test]
async fn a_transfer_notification_carries_the_transfers_id_as_its_idempotency_key() {
    let state = Arc::new(MockState::default());
    {
        let mut queue = state.transfer_queue.lock().await;
        queue.push_back((axum::http::StatusCode::OK, registered_response("EU-REG-K")));
        queue.push_back((axum::http::StatusCode::OK, registered_response("EU-REG-K")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();
    let transfer = completed_transfer();

    sync.notify_transfer(&transfer, "EU-REG-K").await.unwrap();
    sync.notify_transfer(&transfer, "EU-REG-K").await.unwrap();

    let expected = transfer.transfer_id.to_string();
    assert_eq!(
        state
            .transfer_keys
            .lock()
            .await
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec![Some(expected.clone()), Some(expected)],
        "every attempt presents the same key, and it is the transfer's"
    );
}

/// A different handover is a different notification, so it is a different key.
#[tokio::test]
async fn two_transfers_do_not_share_a_key() {
    let state = Arc::new(MockState::default());
    {
        let mut queue = state.transfer_queue.lock().await;
        queue.push_back((axum::http::StatusCode::OK, registered_response("EU-REG-K")));
        queue.push_back((axum::http::StatusCode::OK, registered_response("EU-REG-K")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    sync.notify_transfer(&completed_transfer(), "EU-REG-K")
        .await
        .unwrap();
    sync.notify_transfer(&completed_transfer(), "EU-REG-K")
        .await
        .unwrap();

    let keys = state.transfer_keys.lock().await;
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
}

/// The registry's answer to a notification is read as an answer to it: whether
/// it took the notification, and not where a registration stands. Each status is
/// its own report, a state nobody has named is carried as it came, and none is
/// read as an acceptance it did not say.
#[tokio::test]
async fn the_registrys_answer_to_a_notification_is_read_as_one() {
    fn reply(status: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::json!({
            "registryId": "EU-REG-R",
            "passportId": Uuid::now_v7(),
            "status": status,
            "updatedAt": Utc::now().to_rfc3339(),
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    }

    let cases = [
        (
            reply("registered", serde_json::json!({})),
            TransferReport::Accepted,
        ),
        (
            reply("pending", serde_json::json!({})),
            TransferReport::Processing,
        ),
        (
            reply(
                "rejected",
                serde_json::json!({"rejectionReasons": ["no such record", "  ", "operator not verified"]}),
            ),
            TransferReport::Refused {
                reason: "no such record; operator not verified".into(),
            },
        ),
        (
            reply(
                "rejected",
                serde_json::json!({"message": "refused by the registry"}),
            ),
            TransferReport::Refused {
                reason: "refused by the registry".into(),
            },
        ),
        (
            reply("rejected", serde_json::json!({})),
            TransferReport::Refused {
                reason: "the registry refused the notification and gave no reason".into(),
            },
        ),
        // A record the registry reports out of service is not a notification
        // taken, or refused: it is a state to show as it came.
        (
            reply("suspended_by_authority", serde_json::json!({})),
            TransferReport::Unrecognised {
                state: "suspended_by_authority".into(),
            },
        ),
        (
            reply("deactivated", serde_json::json!({})),
            TransferReport::Unrecognised {
                state: "deactivated".into(),
            },
        ),
        (
            reply("UNDER_REVIEW", serde_json::json!({})),
            TransferReport::Unrecognised {
                state: "UNDER_REVIEW".into(),
            },
        ),
    ];

    let state = Arc::new(MockState::default());
    {
        let mut queue = state.transfer_queue.lock().await;
        for (body, _) in &cases {
            queue.push_back((axum::http::StatusCode::OK, body.clone()));
        }
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    for (body, expected) in cases {
        let report = sync
            .notify_transfer(&completed_transfer(), "EU-REG-R")
            .await
            .expect("every reply is an answer");
        assert_eq!(report, expected, "for {body}");
    }
}

/// A replayed key is the registry saying it already holds the notification: an
/// earlier attempt got through and its answer was lost, or was one this node
/// could not settle on. Neither a failure nor grounds to send it a third time.
#[tokio::test]
async fn a_replayed_transfer_key_means_the_registry_already_holds_it() {
    let state = Arc::new(MockState::default());
    state
        .transfer_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::CONFLICT, key_reused_body()));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let report = sync
        .notify_transfer(&completed_transfer(), "EU-REG-K")
        .await
        .expect("a replayed key is not a failure");

    assert_eq!(report, TransferReport::AlreadyHeld);
    assert_eq!(
        state.transfer_bodies.lock().await.len(),
        1,
        "a replayed key is not retried"
    );
}

/// Only the one `subCode` is read as "already done". Any other conflict says
/// nothing about whether the notification was taken.
#[tokio::test]
async fn a_transfer_conflict_that_is_not_a_replayed_key_is_still_an_error() {
    let state = Arc::new(MockState::default());
    state.transfer_queue.lock().await.push_back((
        axum::http::StatusCode::CONFLICT,
        serde_json::json!({"subCode": "SOME_OTHER_CONFLICT", "traceId": "trace-x"}),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .notify_transfer(&completed_transfer(), "EU-REG-K")
        .await
        .expect_err("another conflict is a refusal to be seen, not an acceptance");
    assert!(err.to_string().contains("409"), "{err}");
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
        .push_back((axum::http::StatusCode::OK, accepted_response("CORR-9")));
    let base_url = mock_server::spawn(state.clone()).await;

    let mut config = mock_config(&base_url);
    config.allow_invalid_payloads = true;
    let sync = EuRegistrySync::new(config).unwrap();

    let acknowledgement = sync
        .register(invalid_request())
        .await
        .expect("the override must permit submission");

    assert_eq!(acknowledgement, accepted("CORR-9"));
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
        .push_back((axum::http::StatusCode::OK, accepted_response("CORR-OK")));
    let base_url = mock_server::spawn(state.clone()).await;
    // No override: this must succeed on the fail-closed path.
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let acknowledgement = sync
        .register(valid_request())
        .await
        .expect("a fully-populated registration must pass local validation");

    assert_eq!(acknowledgement, accepted("CORR-OK"));
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

/// 🚨 The item is registered under the serial its carrier prints, never under
/// this node's passport id. The id matches no label, so an item registered under
/// it could not be found from the product.
#[test]
fn an_item_is_registered_under_its_carrier_serial_not_the_passport_id() {
    let request = valid_request();
    let item = item_id_for(&request).expect("an item-level request names its unit");
    assert_eq!(item.scheme, "serial");
    assert_eq!(item.value, "abc123");
    assert_ne!(item.value, request.passport_id.to_string());
}

/// An item-level request with no serial is not completed with one made up: it
/// has no item identifier, and validation refuses the payload.
#[tokio::test]
async fn an_item_without_a_serial_is_refused_rather_than_given_one() {
    let request = RegistrationRequest {
        item_serial: None,
        ..valid_request()
    };
    assert!(item_id_for(&request).is_none());

    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();
    let err = sync
        .register(request)
        .await
        .expect_err("an item with no identifier must be refused");
    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 0);
}

/// Art. 8(4) and 8(5) link a batch where one exists; the request carries it at
/// batch and item level.
#[test]
fn the_batch_the_request_carries_is_linked_on_the_level() {
    let mut request = valid_request();
    assert!(level_for(&request).batch_id.is_none());

    request.batch_id = Some("LOT-2026-01".into());
    let level = level_for(&request);
    assert_eq!(level.batch_id.as_deref(), Some("LOT-2026-01"));
    assert!(level.validate().is_ok());
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
        registered_trade_name: None,
        postal_address: None,
        electronic_address: None,
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
        node_acceptance_attestation: Some("jws-to".to_owned()),
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
    assert_eq!(sent["nodeAcceptanceAttestation"], "jws-to");
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
    transfer.node_acceptance_attestation = None;
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
        sent.get("nodeAcceptanceAttestation").is_none(),
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
        .push_back((axum::http::StatusCode::OK, accepted_response("CORR-V")));
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
    let operator = &sent["submission"][0]["operatorId"];
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
        .push_back((axum::http::StatusCode::OK, accepted_response("CORR-D")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    sync.register(valid_request())
        .await
        .expect("a did-scheme operator must register");

    let sent = state.register_bodies.lock().await.pop_front().unwrap();
    let operator = &sent["submission"][0]["operatorId"];
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

/// A deactivated record is not a rejected one. Rejection means the submission
/// was defective and can be corrected; deactivation means the record is out of
/// service, which resubmitting does not fix.
#[test]
fn a_deactivated_record_is_not_reported_as_rejected() {
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
        q.push_back((axum::http::StatusCode::OK, accepted_response("CORR-I")));
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

// ── The registry's observed contract ────────────────────────────────────────

/// What the registry sends back for a replayed idempotency key.
fn key_reused_body() -> serde_json::Value {
    serde_json::json!({
        "subCode": dpp_registry::SUB_CODE_IDEMPOTENCY_KEY_REUSED,
        "traceId": "trace-409",
        "message": "this key was already used",
    })
}

/// The registry's key is a header. The envelope's `requestId` is ours and
/// reaches the registry as ordinary payload, so a replay carrying only that is,
/// to the registry, a new submission — which is how a registration whose reply
/// was lost could be registered twice.
#[tokio::test]
async fn a_registration_carries_its_request_id_as_the_idempotency_key() {
    let state = Arc::new(MockState::default());
    {
        let mut q = state.register_queue.lock().await;
        q.push_back((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "upstream"}),
        ));
        q.push_back((axum::http::StatusCode::OK, accepted_response("CORR-K")));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = valid_request();
    let expected = request.request_id.to_string();
    sync.register(request).await.expect("succeeds on retry");

    let keys = state.register_keys.lock().await;
    assert_eq!(
        keys.iter().cloned().collect::<Vec<_>>(),
        vec![Some(expected.clone()), Some(expected)],
        "every attempt must present the request's own key in the header"
    );
}

/// A replayed key means an earlier attempt reached the registry and its answer
/// never reached us. That submission exists, so this is neither a failure nor
/// grounds to resubmit: the registry holds it and its verdict is outstanding.
#[tokio::test]
async fn a_replayed_key_means_the_registry_already_has_the_submission() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::CONFLICT, key_reused_body()));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let acknowledgement = sync
        .register(valid_request())
        .await
        .expect("a replayed key is not a failure");

    // The registry's reply to a replayed key names the conflict, not the
    // submission, so there is no correlation identifier to report and none may
    // be invented.
    assert_eq!(acknowledgement, SubmissionAcknowledgement::AlreadyHeld);
    assert_eq!(
        state.register_hits.load(Ordering::SeqCst),
        1,
        "a replayed key must not be retried"
    );
}

/// Only the one `subCode` is read as "already done". A conflict that names
/// nothing, or something else, says nothing about whether a submission exists.
#[tokio::test]
async fn a_conflict_that_is_not_a_replayed_key_is_still_a_refusal() {
    for body in [
        serde_json::json!({}),
        serde_json::json!({"subCode": "SOME_OTHER_CONFLICT", "traceId": "trace-x"}),
    ] {
        let state = Arc::new(MockState::default());
        state
            .register_queue
            .lock()
            .await
            .push_back((axum::http::StatusCode::CONFLICT, body.clone()));
        let base_url = mock_server::spawn(state.clone()).await;
        let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

        let err = sync
            .register(valid_request())
            .await
            .expect_err("an unrecognised conflict is a refusal");

        assert!(
            err.to_string().contains("registration rejected 409"),
            "got: {err} for {body}"
        );
    }
}

/// A 2xx whose body this node cannot read is **unknown**, not failed: the
/// registry accepted the request. Reading it as an error is safe only because
/// the retry carries the same key — the registry answers the replay with the
/// conflict above, and the row converges instead of being registered twice or
/// stuck on a body that will never parse.
#[tokio::test]
async fn a_success_body_this_node_cannot_read_resolves_when_the_key_is_replayed() {
    let state = Arc::new(MockState::default());
    {
        let mut q = state.register_queue.lock().await;
        q.push_back((
            axum::http::StatusCode::OK,
            serde_json::json!({"somethingElse": "the registry changed its mind about the shape"}),
        ));
        q.push_back((axum::http::StatusCode::CONFLICT, key_reused_body()));
    }
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let id = Uuid::now_v7();
    let attempt = || RegistrationRequest {
        request_id: id,
        ..valid_request()
    };

    let first = sync
        .register(attempt())
        .await
        .expect_err("an unreadable body must not be recorded as a registration");
    assert!(
        first.to_string().contains("may have been accepted"),
        "the error must say the submission may exist: {first}"
    );

    let second = sync
        .register(attempt())
        .await
        .expect("the replay is recognised, not refused");
    assert_eq!(second, SubmissionAcknowledgement::AlreadyHeld);

    let keys = state.register_keys.lock().await;
    assert_eq!(
        keys.iter().cloned().collect::<Vec<_>>(),
        vec![Some(id.to_string()); 2],
        "the replay must present the key the first attempt did"
    );
}

/// The trace id is the only handle a conversation with the registry's support
/// has. It reaches the operator through the row's `message`, so the message has
/// to lead with it rather than bury it in a raw body.
#[tokio::test]
async fn a_refusal_carries_the_registry_trace_id_and_sub_code() {
    let state = Arc::new(MockState::default());
    state.register_queue.lock().await.push_back((
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        serde_json::json!({
            "subCode": "VALIDATION_FAILED",
            "traceId": "trace-422",
            "message": "the unique product identifier is not accepted",
        }),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let err = sync
        .register(valid_request())
        .await
        .unwrap_err()
        .to_string();

    // The exact wording, not the words: the raw JSON body contains every one of
    // them, so a check on the words passes whether or not the body was read.
    assert!(
        err.contains(
            "registration rejected 422: the unique product identifier is not accepted \
             [VALIDATION_FAILED] (registry trace id trace-422)"
        ),
        "got: {err}"
    );
    assert!(
        !err.contains("traceId"),
        "the raw body must not be passed through when it was readable: {err}"
    );
}

/// A body that is not the registry's error shape — a gateway page, a bare
/// string — is kept verbatim. Nothing is lost by trying to read it.
#[tokio::test]
async fn a_refusal_with_an_unreadable_body_keeps_what_the_registry_said() {
    let state = Arc::new(MockState::default());
    state.register_queue.lock().await.push_back((
        axum::http::StatusCode::BAD_GATEWAY,
        serde_json::json!("upstream gateway down"),
    ));
    let base_url = mock_server::spawn(state.clone()).await;
    let mut config = mock_config(&base_url);
    config.max_retries = 1;
    let sync = EuRegistrySync::new(config).unwrap();

    let err = sync
        .register(valid_request())
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("upstream gateway down"), "got: {err}");
}

/// ESPR Art. 10(4) makes the back-up copy available *through* a service
/// provider, so a declared link with nobody named beside it is refused by core's
/// validation. Nothing here may send it: it was the state every registration of
/// a node serving its snapshots was in, retried hourly, until publish named the
/// provider.
#[tokio::test]
async fn a_backup_link_with_no_provider_is_refused_before_it_is_sent() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        backup_url: Some("https://backup.example.com/dpp/x/public.json".into()),
        service_provider: None,
        ..valid_request()
    };
    let err = sync
        .register(request)
        .await
        .expect_err("a link with no provider must be refused");

    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert!(err.to_string().contains("serviceProvider"), "got: {err}");
    assert_eq!(state.register_hits.load(Ordering::SeqCst), 0);
}

/// The same link with its provider is submitted, and both arrive.
#[tokio::test]
async fn a_backup_link_with_its_provider_is_sent_with_both() {
    let state = Arc::new(MockState::default());
    state
        .register_queue
        .lock()
        .await
        .push_back((axum::http::StatusCode::OK, accepted_response("CORR-B")));
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        backup_url: Some("https://backup.example.com/dpp/x/public.json".into()),
        service_provider: Some(dpp_domain::ports::registry_sync::ServiceProviderRef::named(
            "Example Backup Provider",
        )),
        ..valid_request()
    };
    sync.register(request).await.expect("registers");

    let bodies = state.register_bodies.lock().await;
    let passport = &bodies[0]["submission"][0];
    assert_eq!(
        passport["backupUrl"],
        "https://backup.example.com/dpp/x/public.json"
    );
    assert_eq!(
        passport["serviceProvider"]["name"],
        "Example Backup Provider"
    );
}

/// The registry caps the unique product identifier, and the identifier it
/// checks is the carrier URL. The cap is enforced by core's validation, which
/// this adapter runs before anything leaves the node — the test pins that it is
/// reached from here, so a refused submission cannot be one the registry sees.
#[tokio::test]
async fn a_product_identifier_over_the_registry_cap_is_refused_before_it_is_sent() {
    let state = Arc::new(MockState::default());
    let base_url = mock_server::spawn(state.clone()).await;
    let sync = EuRegistrySync::new(mock_config(&base_url)).unwrap();

    let request = RegistrationRequest {
        data_carrier_uri: format!(
            "https://id.example.com/01/09506000134352/21/{}",
            "a".repeat(dpp_registry::MAX_PRODUCT_IDENTIFIER_CHARS)
        ),
        ..valid_request()
    };
    let err = sync
        .register(request)
        .await
        .expect_err("an identifier over the cap must be refused");

    assert!(matches!(err, DppError::Validation(_)), "got: {err:?}");
    assert_eq!(
        state.register_hits.load(Ordering::SeqCst),
        0,
        "the registry was contacted for an identifier it would refuse"
    );
}
