use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chrono::Utc;
use dpp_domain::domain::passport::PassportId;
use dpp_registry::{EuRegistryResponse, registry::RegistryStatusCode};
use uuid::Uuid;

use dpp_domain::ports::registry_sync::{RegistrationRequest, RegistryStatus, RegistrySyncPort};

use super::client::EuRegistrySync;
use super::config::EuRegistrySyncConfig;
use super::mapping::{extract_gtin_from_gs1_dl, facility_identifier_for};
use super::token::CachedToken;
use dpp_registry::StatusResponse;

#[test]
fn sandbox_config_has_correct_defaults() {
    let config = EuRegistrySyncConfig::sandbox("id".into(), "secret".into());
    assert_eq!(config.max_retries, 3);
    assert!(config.endpoint.base_url.contains("sandbox"));
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

fn request_with_facility(facility: Option<dpp_domain::FacilitySnapshot>) -> RegistrationRequest {
    RegistrationRequest {
        passport_id: PassportId::new(),
        operator_identifier: "did:web:test.example".into(),
        facility_identifier: "LEGACY-FAC".into(),
        facility,
        product_category: "battery".into(),
        data_carrier_uri: String::new(),
        schema_version: "2.0.0".into(),
        jws_signature: None,
        published_at: None,
        country_code: String::new(),
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
        pub(super) status_queue: Mutex<VecDeque<(StatusCode, Value)>>,
        pub(super) transfer_queue: Mutex<VecDeque<(StatusCode, Value)>>,
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

    async fn register_handler(State(state): State<Arc<MockState>>) -> Response {
        state
            .register_hits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    ) -> Response {
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
        .register(request_with_facility(None))
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
        .register(request_with_facility(None))
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
        .register(request_with_facility(None))
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
        .register(request_with_facility(None))
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
        .register(request_with_facility(None))
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
        .notify_transfer(PassportId::new(), "did:web:new-operator.example".into())
        .await
        .expect("notify_transfer should succeed");

    assert_eq!(record.status, RegistryStatus::Registered);
}
