//! End-to-end behaviour of the idempotency middleware, driven through a real
//! axum router against an in-memory store.
//!
//! The unit tests beside the middleware cover the pieces — redaction, the
//! replay header, the problem-type catalogue. This covers the thing those
//! cannot: that a second request with the same key does not reach the handler,
//! and that the handler's side effect therefore happens once.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use dpp_common::idempotency::{
    Claim, IdempotencyError, IdempotencyLayerState, IdempotencyStore, RequestKey, StoredResponse,
    idempotency_middleware,
};
use tower::ServiceExt;

/// An in-memory stand-in for the Postgres store, implementing the same
/// claim/complete/release contract. Its correctness is not what is under test —
/// the pg suite covers that — it is here so the middleware's decisions can be
/// observed without a container.
#[derive(Default)]
struct MemStore {
    rows: Mutex<HashMap<String, Row>>,
}

struct Row {
    fingerprint: String,
    completed: Option<StoredResponse>,
}

fn id(key: &RequestKey) -> String {
    format!("{}|{}|{}|{}", key.principal, key.method, key.path, key.key)
}

#[async_trait]
impl IdempotencyStore for MemStore {
    async fn claim(
        &self,
        key: &RequestKey,
        fingerprint: &str,
        _: Duration,
        _: Duration,
    ) -> Result<Claim, IdempotencyError> {
        let mut rows = self.rows.lock().unwrap();
        match rows.get(&id(key)) {
            None => {
                rows.insert(
                    id(key),
                    Row {
                        fingerprint: fingerprint.to_owned(),
                        completed: None,
                    },
                );
                Ok(Claim::Claimed)
            }
            Some(row) if row.fingerprint != fingerprint => Ok(Claim::FingerprintMismatch),
            Some(row) => match &row.completed {
                Some(stored) => Ok(Claim::Replay(stored.clone())),
                None => Ok(Claim::InFlight),
            },
        }
    }

    async fn complete(
        &self,
        key: &RequestKey,
        response: &StoredResponse,
    ) -> Result<(), IdempotencyError> {
        if let Some(row) = self.rows.lock().unwrap().get_mut(&id(key)) {
            row.completed = Some(response.clone());
        }
        Ok(())
    }

    async fn release(&self, key: &RequestKey) -> Result<(), IdempotencyError> {
        self.rows.lock().unwrap().remove(&id(key));
        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, IdempotencyError> {
        Ok(0)
    }
}

/// A store that is simply down, for the fail-closed case.
struct DeadStore;

#[async_trait]
impl IdempotencyStore for DeadStore {
    async fn claim(
        &self,
        _: &RequestKey,
        _: &str,
        _: Duration,
        _: Duration,
    ) -> Result<Claim, IdempotencyError> {
        Err(IdempotencyError::Unavailable("down".into()))
    }
    async fn complete(&self, _: &RequestKey, _: &StoredResponse) -> Result<(), IdempotencyError> {
        Err(IdempotencyError::Unavailable("down".into()))
    }
    async fn release(&self, _: &RequestKey) -> Result<(), IdempotencyError> {
        Err(IdempotencyError::Unavailable("down".into()))
    }
    async fn purge_expired(&self) -> Result<u64, IdempotencyError> {
        Err(IdempotencyError::Unavailable("down".into()))
    }
}

/// Counts handler entries, so "did the second request run?" is a fact and not
/// an inference from the response body.
#[derive(Clone)]
struct Calls(Arc<AtomicUsize>);

/// Build a router mirroring the real assembly: a keyed create and an unkeyed
/// transition, both under the vault's nesting, with the middleware as a
/// `route_layer`.
fn app(store: Arc<dyn IdempotencyStore>, calls: Calls) -> Router {
    let created = calls.clone();
    let published = calls.clone();

    let inner = Router::new()
        .route(
            "/dpp",
            post(move || {
                let created = created.clone();
                async move {
                    let n = created.0.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::CREATED,
                        [("content-type", "application/json")],
                        format!(r#"{{"id":"passport-{n}"}}"#),
                    )
                }
            }),
        )
        .route(
            "/dpp/{dppId}/publish",
            post(move || {
                let published = published.clone();
                async move {
                    published.0.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                }
            }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            IdempotencyLayerState {
                store,
                principal: Arc::new(|_| Some("operator@example.com".to_owned())),
            },
            idempotency_middleware,
        ));

    Router::new().nest("/vault", Router::new().nest("/api/v1", inner))
}

fn create(key: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::post("/vault/api/v1/dpp").header("content-type", "application/json");
    if let Some(k) = key {
        b = b.header("idempotency-key", k);
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

async fn body_of(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The whole point: a retried create returns the first outcome and creates
/// nothing new.
#[tokio::test]
async fn a_retry_replays_the_first_outcome_and_the_handler_runs_once() {
    let store = Arc::new(MemStore::default());
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    let first = app(store.clone(), calls.clone())
        .oneshot(create(Some("k-1"), r#"{"productName":"n"}"#))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert!(first.headers().get("idempotency-replayed").is_none());
    let first_body = body_of(first).await;

    let second = app(store.clone(), calls.clone())
        .oneshot(create(Some("k-1"), r#"{"productName":"n"}"#))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(
        second.headers().get("idempotency-replayed").unwrap(),
        "true"
    );
    assert_eq!(body_of(second).await, first_body);

    assert_eq!(
        calls.0.load(Ordering::SeqCst),
        1,
        "the handler must not have run a second time"
    );
}

/// The interesting failure. Same key, different body: neither replaying nor
/// executing is right, so it is refused.
#[tokio::test]
async fn the_same_key_with_a_different_body_is_refused() {
    let store = Arc::new(MemStore::default());
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    app(store.clone(), calls.clone())
        .oneshot(create(Some("k-1"), r#"{"productName":"a"}"#))
        .await
        .unwrap();

    let clash = app(store.clone(), calls.clone())
        .oneshot(create(Some("k-1"), r#"{"productName":"b"}"#))
        .await
        .unwrap();

    assert_eq!(clash.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_of(clash).await;
    assert!(
        body.contains("idempotency-key-reuse"),
        "the refusal must carry its own problem type, not the generic 422 one: {body}"
    );
    assert_eq!(
        calls.0.load(Ordering::SeqCst),
        1,
        "a refused request must not have run"
    );
}

/// Refused, not ignored. Silently accepting the header here would tell a client
/// its retry is protected on a route where nothing records it.
#[tokio::test]
async fn a_key_on_an_unkeyed_route_is_refused() {
    let store = Arc::new(MemStore::default());
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    let response = app(store, calls.clone())
        .oneshot(
            Request::post("/vault/api/v1/dpp/abc/publish")
                .header("idempotency-key", "k-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(calls.0.load(Ordering::SeqCst), 0);
}

/// The header is opt-in. A caller that sends none is unaffected, on a keyed
/// route as much as anywhere else.
#[tokio::test]
async fn no_key_means_no_change_in_behaviour() {
    let store = Arc::new(MemStore::default());
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    for _ in 0..2 {
        let response = app(store.clone(), calls.clone())
            .oneshot(create(None, r#"{"productName":"n"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().get("idempotency-replayed").is_none());
    }
    assert_eq!(
        calls.0.load(Ordering::SeqCst),
        2,
        "without a key both requests must execute, exactly as before"
    );
}

/// Fail closed. Running the write with no record would produce precisely the
/// outcome the caller asked to be protected from.
#[tokio::test]
async fn an_unavailable_store_refuses_the_write_rather_than_running_it() {
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    let response = app(Arc::new(DeadStore), calls.clone())
        .oneshot(create(Some("k-1"), r#"{"productName":"n"}"#))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        calls.0.load(Ordering::SeqCst),
        0,
        "the handler must not run when the claim could not be recorded"
    );
}

/// A concurrent duplicate is told to wait rather than allowed to double-execute.
#[tokio::test]
async fn a_claim_still_in_flight_answers_409_with_retry_after() {
    let store = Arc::new(MemStore::default());
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    // Claim without completing, as a crashed or still-running first attempt
    // would leave it.
    store
        .claim(
            &RequestKey {
                principal: "operator@example.com".into(),
                method: "POST".into(),
                path: "/vault/api/v1/dpp".into(),
                key: "k-1".into(),
            },
            &dpp_common::idempotency::fingerprint(br#"{"productName":"n"}"#),
            Duration::from_secs(60),
            Duration::from_secs(86_400),
        )
        .await
        .unwrap();

    let response = app(store, calls.clone())
        .oneshot(create(Some("k-1"), r#"{"productName":"n"}"#))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers().get("retry-after").unwrap(), "1");
    assert_eq!(calls.0.load(Ordering::SeqCst), 0);
}

/// Keys are scoped to the caller, so one principal's key can neither collide
/// with nor reveal another's.
#[tokio::test]
async fn a_key_is_scoped_to_its_principal() {
    let store = Arc::new(MemStore::default());
    let calls = Calls(Arc::new(AtomicUsize::new(0)));

    let one = |principal: &'static str| {
        let store: Arc<dyn IdempotencyStore> = store.clone();
        let calls = calls.clone();
        let inner = Router::new()
            .route(
                "/dpp",
                post(move || {
                    let calls = calls.clone();
                    async move {
                        calls.0.fetch_add(1, Ordering::SeqCst);
                        (StatusCode::CREATED, "{}")
                    }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                IdempotencyLayerState {
                    store,
                    principal: Arc::new(move |_| Some(principal.to_owned())),
                },
                idempotency_middleware,
            ));
        Router::new().nest("/vault", Router::new().nest("/api/v1", inner))
    };

    for principal in ["alice", "bob"] {
        let response = one(principal)
            .oneshot(create(Some("same-key"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(
            response.headers().get("idempotency-replayed").is_none(),
            "{principal} must not have been served another caller's stored response"
        );
    }
    assert_eq!(calls.0.load(Ordering::SeqCst), 2);
}
