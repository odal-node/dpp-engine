//! Integration test: the registry-sync **transactional outbox**.
//!
//! Proves the sentence in `ops/pg/0006_registry_sync.sql` — "written in the
//! publish transaction; drained with backoff" — is now true in code:
//!
//!   (a) publish enqueues atomically: a Published passport always has a
//!       `pending` outbox row, and the API caller sees no registry error;
//!   (b) a killed node loses nothing — the row drains exactly once on the next
//!       pass (idempotency via `passport_id UNIQUE`);
//!   (c) a transient registry failure backs off (attempts++ , future retry),
//!       keeping the row `pending`;
//!   (d) a terminal rejection marks the row `rejected` (alarm), never dropped;
//!   (e) suspend/archive enqueue a durable status intent.
//!
//! Run: `cargo test -p dpp-node --features integration-tests --test registry_outbox`

#![cfg(feature = "integration-tests")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::Utc;
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use dpp_dal::pg::{PgDal, PgPassportRepo, PgRegistrySyncRepo, sqlx};
use dpp_domain::{
    DppError,
    domain::{
        passport::{ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
    },
    ports::{
        passport_repo::PassportRepository,
        registry_sync::{
            RegistrationRequest, RegistryIdentifiers, RegistryRecord, RegistryStatus,
            RegistrySyncPort,
        },
    },
};
use dpp_node::infra::registry_drain::drain_once;
use dpp_types::{RegistrySyncOutbox, RegistrySyncStatus};

// ─── Harness ────────────────────────────────────────────────────────────────

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

fn draft_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: Some("LOT-OUTBOX-1".into()),
        product_name: "Outbox Battery".into(),
        sector: Sector::Battery,
        product_category: None,
        manufacturer: ManufacturerInfo {
            name: "TestCorp GmbH".into(),
            address: "Berlin, DE".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        sector_data: None,
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        retention_until: None,
        product_id: None,
        operator_identifier: Some("did:web:test.example".into()),
        facility: None,
    }
}

/// Create a draft then publish it through the transactional outbox, returning
/// the passport id. Mirrors `PassportService::publish`'s commit step.
async fn create_and_publish(dal: &PgDal, outbox: &Arc<dyn RegistrySyncOutbox>) -> PassportId {
    let repo = PgPassportRepo::new(dal.clone());
    let mut p = draft_passport();
    repo.create(p.clone()).await.expect("create draft");
    p.status = PassportStatus::Published;
    p.published_at = Some(Utc::now());
    let payload =
        serde_json::to_value(RegistrationRequest::from_published_passport(&p, "DE")).unwrap();
    outbox
        .commit_publish(&p, payload)
        .await
        .expect("commit_publish must persist passport + enqueue row atomically");
    p.id
}

async fn outbox_row_count(dal: &PgDal, id: PassportId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM odal.registry_sync WHERE passport_id = $1")
        .bind(id.0)
        .fetch_one(dal.pool())
        .await
        .expect("count query")
}

// ─── Mock registry port ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Outcome {
    Registered,
    Transient,
    Rejected,
}

struct MockPort {
    outcome: Outcome,
    calls: Arc<AtomicUsize>,
}

fn record(status: RegistryStatus, registry_id: &str) -> RegistryRecord {
    RegistryRecord {
        identifiers: RegistryIdentifiers {
            product_id: "PROD".into(),
            operator_id: "OP".into(),
            facility_id: "FAC".into(),
            registry_id: registry_id.into(),
        },
        status,
        registered_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[async_trait]
impl RegistrySyncPort for MockPort {
    async fn register(&self, _req: RegistrationRequest) -> Result<RegistryRecord, DppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            Outcome::Registered => Ok(record(RegistryStatus::Registered, "EU-REG-TEST-0001")),
            Outcome::Transient => Err(DppError::Internal("EU registry transient failure".into())),
            Outcome::Rejected => Ok(record(RegistryStatus::Rejected, "")),
        }
    }

    async fn check_status(&self, _pid: PassportId) -> Result<RegistryRecord, DppError> {
        unimplemented!("not exercised")
    }

    async fn notify_transfer(
        &self,
        _pid: PassportId,
        _op: String,
    ) -> Result<RegistryRecord, DppError> {
        unimplemented!("not exercised")
    }
}

fn mock(outcome: Outcome) -> (Arc<dyn RegistrySyncPort>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let port: Arc<dyn RegistrySyncPort> = Arc::new(MockPort {
        outcome,
        calls: calls.clone(),
    });
    (port, calls)
}

// ─── (a) atomic publish + idempotency + (b) drains exactly once ───────────────

#[tokio::test(flavor = "multi_thread")]
async fn publish_is_atomic_idempotent_and_drains_exactly_once() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let repo = PgPassportRepo::new(dal.clone());

    let id = create_and_publish(&dal, &outbox).await;

    // (a) passport is Published (served publicly) AND a pending row exists.
    assert!(
        repo.find_published_by_id(id).await.unwrap().is_some(),
        "passport must be Published after commit_publish"
    );
    let row = outbox.pending_for(id).await.unwrap().expect("outbox row");
    assert_eq!(row.status, RegistrySyncStatus::Pending);
    assert!(
        row.payload.is_some(),
        "row carries the registration payload"
    );

    // Idempotency: a re-published passport does not create a second row.
    let mut again = draft_passport();
    again.id = id;
    again.status = PassportStatus::Published;
    let payload =
        serde_json::to_value(RegistrationRequest::from_published_passport(&again, "DE")).unwrap();
    outbox.commit_publish(&again, payload).await.unwrap();
    assert_eq!(outbox_row_count(&dal, id).await, 1, "still exactly one row");

    // (b) drain once with a healthy port → registered; a second pass is a no-op,
    // so the registry is called exactly once across the (simulated) restart.
    let (port, calls) = mock(Outcome::Registered);
    let s1 = drain_once(&outbox, &port, 50).await;
    assert_eq!(s1.registered, 1);
    let after = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(after.status, RegistrySyncStatus::Registered);
    assert_eq!(after.registry_id.as_deref(), Some("EU-REG-TEST-0001"));

    assert!(
        outbox.due(50).await.unwrap().is_empty(),
        "registered row not due"
    );
    let s2 = drain_once(&outbox, &port, 50).await;
    assert_eq!(s2.registered, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "registered exactly once");
}

// ─── (c) transient backoff and (d) terminal rejection ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn drain_backs_off_on_transient_and_marks_terminal_rejection() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    // (c) transient failure → attempts++, still pending, pushed into the future.
    let transient_id = create_and_publish(&dal, &outbox).await;
    let (port_t, _) = mock(Outcome::Transient);
    let st = drain_once(&outbox, &port_t, 50).await;
    assert_eq!(st.retried, 1);
    let row = outbox.pending_for(transient_id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Pending);
    assert_eq!(row.attempts, 1);
    assert!(
        row.next_attempt_at > Utc::now(),
        "backoff pushed retry into the future"
    );
    assert!(
        outbox.due(50).await.unwrap().is_empty(),
        "backed-off row is not immediately due again"
    );

    // (d) terminal rejection → row rejected (kept for a human, never dropped).
    let rejected_id = create_and_publish(&dal, &outbox).await;
    let (port_r, _) = mock(Outcome::Rejected);
    let sr = drain_once(&outbox, &port_r, 50).await;
    assert_eq!(sr.rejected, 1);
    let row = outbox.pending_for(rejected_id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Rejected);
}

// ─── (e) suspend enqueues a durable status intent + counts ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn suspend_enqueues_status_intent_and_counts_reflect_state() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    let id = create_and_publish(&dal, &outbox).await;
    outbox
        .enqueue_status(id, RegistrySyncStatus::Suspended)
        .await
        .unwrap();

    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Suspended);

    let counts = outbox.status_counts(8).await.unwrap();
    assert_eq!(counts.status_intents, 1);
    assert_eq!(counts.pending, 0);
}
