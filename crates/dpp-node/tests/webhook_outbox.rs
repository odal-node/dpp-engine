//! Integration test: the signed-webhook delivery **outbox**.
//!
//! Proves the sentences in `ops/pg/0022_webhooks.sql` and the drain module:
//!
//!   (a) enqueue fans out one `pending` delivery per *active, matching*
//!       subscription — the subject filter (and `*` wildcard) is honoured;
//!   (b) the drain POSTs a **valid HMAC signature** with the documented headers,
//!       and marks the row `delivered` on a 2xx;
//!   (c) a receiver 5xx backs off (attempts++, pushed into the future, still
//!       `pending`), and reaching the attempt cap marks the row `exhausted`;
//!   (d) a killed node loses nothing — a reconstructed outbox redelivers the
//!       still-`pending` row;
//!   (e) the signature is bound to the exact body — a tampered body fails
//!       receiver-side verification.
//!
//! Run: `cargo test -p dpp-node --features integration-tests --test webhook_outbox`

#![cfg(feature = "integration-tests")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::{Router, extract::State, http::HeaderMap, http::StatusCode, routing::post};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use dpp_dal::pg::{PgDal, PgWebhookRepo, sqlx};
use dpp_node::infra::webhook_drain::{MAX_ATTEMPTS, drain_once};
use dpp_types::{
    NewWebhookSubscription, WebhookDeliveryRow, WebhookOutbox, WebhookSubscriptionStore,
};

type HmacSha256 = Hmac<Sha256>;

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

// ─── Mock receiver ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Received {
    signature: String,
    delivery: String,
    event: String,
    body: String,
}

#[derive(Clone)]
struct ReceiverState {
    received: Arc<std::sync::Mutex<Vec<Received>>>,
    fail: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
}

async fn receive_hook(
    State(st): State<ReceiverState>,
    headers: HeaderMap,
    body: String,
) -> StatusCode {
    st.hits.fetch_add(1, Ordering::SeqCst);
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    st.received.lock().unwrap().push(Received {
        signature: h("X-Odal-Signature"),
        delivery: h("X-Odal-Delivery"),
        event: h("X-Odal-Event"),
        body,
    });
    if st.fail.load(Ordering::SeqCst) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

/// Start a local receiver on 127.0.0.1, returning its `/hook` URL and state.
async fn start_receiver() -> (String, ReceiverState) {
    let state = ReceiverState {
        received: Arc::new(std::sync::Mutex::new(Vec::new())),
        fail: Arc::new(AtomicBool::new(false)),
        hits: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/hook", post(receive_hook))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("receiver serve");
    });
    (format!("http://127.0.0.1:{}/hook", addr.port()), state)
}

/// Verify an `X-Odal-Signature: t=<ts>,v1=<hex>` header against a body + secret.
fn signature_valid(secret: &str, header: &str, body: &str) -> bool {
    let mut t = None;
    let mut v1 = None;
    for part in header.split(',') {
        if let Some(x) = part.strip_prefix("t=") {
            t = Some(x.to_owned());
        }
        if let Some(x) = part.strip_prefix("v1=") {
            v1 = Some(x.to_owned());
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.{body}").as_bytes());
    hex::encode(mac.finalize().into_bytes()) == v1
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async fn subscribe(store: &PgWebhookRepo, url: &str, events: &[&str]) -> String {
    let sub = store
        .create(
            &NewWebhookSubscription {
                url: url.to_owned(),
                events: events.iter().map(|s| s.to_string()).collect(),
                description: None,
            },
            "whsec_test_secret_value",
        )
        .await
        .expect("create subscription");
    sub.id.to_string()
}

async fn one_due(outbox: &Arc<dyn WebhookOutbox>) -> WebhookDeliveryRow {
    let due = outbox.due(50).await.expect("due query");
    assert_eq!(due.len(), 1, "expected exactly one due delivery");
    due.into_iter().next().unwrap()
}

// ─── (a) fan-out + subject filter, (b) signed delivery, (e) tamper detection ──

#[tokio::test(flavor = "multi_thread")]
async fn delivers_signed_and_honours_subject_filter() {
    let (dal, _c) = start_pg().await;
    let store = PgWebhookRepo::new(dal.clone());
    let outbox: Arc<dyn WebhookOutbox> = Arc::new(PgWebhookRepo::new(dal.clone()));
    let (url, receiver) = start_receiver().await;
    let client = reqwest::Client::new();
    let secret = "whsec_test_secret_value";

    // Two subscriptions: one wildcard, one filtered to a *different* subject.
    let wildcard_id = subscribe(&store, &url, &["*"]).await;
    let _other = subscribe(&store, &url, &["dpp.passport.suspended"]).await;

    // Enqueue a `published` event — only the wildcard sub matches.
    let body = r#"{"eventType":"dpp.passport.published","data":{"passportId":"p-1"}}"#;
    let enqueued = outbox
        .enqueue("dpp.passport.published", body)
        .await
        .expect("enqueue");
    assert_eq!(enqueued, 1, "only the wildcard subscription matches");

    let row = one_due(&outbox).await;
    let delivery_id = row.delivery_id.to_string();

    // Drain against the live receiver (allow_private → 127.0.0.1 is fine).
    let stats = drain_once(&outbox, &client, 50, true).await;
    assert_eq!(stats.delivered, 1);
    assert!(
        outbox.due(50).await.unwrap().is_empty(),
        "row no longer due"
    );

    // The receiver saw exactly one request with the documented headers…
    let got = receiver.received.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    let d = &got[0];
    assert_eq!(d.event, "dpp.passport.published");
    assert_eq!(d.delivery, delivery_id, "X-Odal-Delivery is the row id");
    assert_eq!(d.body, body, "body delivered verbatim");

    // …and a signature valid for the exact body it received…
    assert!(
        signature_valid(secret, &d.signature, &d.body),
        "signature must verify against the delivered body"
    );
    // …that a tampered body would NOT satisfy (e).
    assert!(
        !signature_valid(secret, &d.signature, r#"{"tampered":true}"#),
        "signature must not verify against a modified body"
    );

    // Idempotent-ish: the wildcard sub was the only match; the filtered sub for
    // `suspended` never received the `published` event.
    let counts = outbox.status_counts().await.unwrap();
    assert_eq!(counts.delivered, 1);
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.exhausted, 0);
    let _ = wildcard_id;
}

// ─── (c) transient backoff → exhaust, (d) survives restart ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn retries_then_exhausts_then_reconstructed_outbox_redelivers() {
    let (dal, _c) = start_pg().await;
    let store = PgWebhookRepo::new(dal.clone());
    let outbox: Arc<dyn WebhookOutbox> = Arc::new(PgWebhookRepo::new(dal.clone()));
    let (url, receiver) = start_receiver().await;
    let client = reqwest::Client::new();

    // (c) transient failure: receiver returns 500 → attempt fails, backs off.
    receiver.fail.store(true, Ordering::SeqCst);
    let failing_id = subscribe(&store, &url, &["*"]).await;
    outbox
        .enqueue("dpp.passport.published", r#"{"n":1}"#)
        .await
        .unwrap();
    let stats = drain_once(&outbox, &client, 50, true).await;
    assert_eq!(stats.retried, 1);
    assert!(
        outbox.due(50).await.unwrap().is_empty(),
        "backed-off row is not immediately due again"
    );

    // Reaching the attempt cap marks the row `exhausted`. Rather than wait out
    // the exponential backoff, fast-forward the row to one-below-cap and due now.
    let did = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM odal.webhook_delivery WHERE subscription_id = $1",
    )
    .bind(uuid::Uuid::parse_str(&failing_id).unwrap())
    .fetch_one(dal.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE odal.webhook_delivery SET attempts = $2, next_attempt_at = now() WHERE id = $1",
    )
    .bind(did)
    .bind(MAX_ATTEMPTS - 1)
    .execute(dal.pool())
    .await
    .unwrap();
    let stats = drain_once(&outbox, &client, 50, true).await;
    assert_eq!(stats.exhausted, 1);
    let counts = outbox.status_counts().await.unwrap();
    assert_eq!(counts.exhausted, 1);
    assert_eq!(counts.pending, 0);

    // (d) survives a restart: with the receiver now healthy, enqueue a fresh
    // delivery to the same (still-active) subscription, then *drop* the outbox
    // and reconstruct it (simulating a node restart). The row persisted in the
    // DB is redelivered by the new outbox.
    receiver.fail.store(false, Ordering::SeqCst);
    let enq = outbox
        .enqueue("dpp.passport.published", r#"{"n":2}"#)
        .await
        .unwrap();
    assert_eq!(enq, 1, "one active subscription → one fresh delivery");
    drop(outbox);

    let reborn: Arc<dyn WebhookOutbox> = Arc::new(PgWebhookRepo::new(dal.clone()));
    let stats = drain_once(&reborn, &client, 50, true).await;
    assert_eq!(
        stats.delivered, 1,
        "reconstructed outbox redelivers the pending row"
    );
}
