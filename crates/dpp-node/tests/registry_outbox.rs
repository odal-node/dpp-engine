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
//! And that a status intent is kept strictly out of the registration queue
//! state (`ops/pg/0024`), since conflating them silently dropped registrations:
//!
//!   (f) suspending before the drain runs leaves the registration due;
//!   (g) re-publishing clears a now-obsolete suspend intent;
//!   (h) archiving a never-published draft creates no row, so it raises no
//!       registration alarm;
//!   plus: 0024 restores registrations already lost to the old write path.
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
use dpp_types::{RegistryStatusIntent, RegistrySyncOutbox, RegistrySyncStatus};

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
        lint_result: None,
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
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        operator_identifier: Some("did:web:test.example".into()),
        facility: None,
        seal: None,
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

// ─── 0024 heals rows the old write path already clobbered ─────────────────────

/// Bring a fresh database up to the pre-0024 schema by applying every migration
/// before it, so the damaged state can be reproduced and the repair exercised.
/// Returns the privileged URL.
async fn start_pg_before_0024() -> (String, testcontainers::ContainerAsync<GenericImage>) {
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

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ops/pg");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("read ops/pg")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with("0024_") {
            break; // stop at the migration under test
        }
        let sql = std::fs::read_to_string(&path).expect("read migration");
        sqlx::raw_sql(&sql)
            .execute(&admin)
            .await
            .unwrap_or_else(|e| panic!("apply {name}: {e}"));
    }
    admin.close().await;
    (admin_url, container)
}

/// Insert a passport plus a `registry_sync` row in the shape the old
/// `enqueue_status` left behind — an intent sitting in the `status` column.
async fn insert_clobbered_row(
    pool: &sqlx::PgPool,
    status: &str,
    registry_id: Option<&str>,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO odal.passport (id, sector, status, schema_version, doc)
           VALUES ($1, 'battery', 'suspended', '2.0.0', '{}'::jsonb)"#,
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert passport");
    sqlx::query(
        r#"INSERT INTO odal.registry_sync (passport_id, status, registry_id, payload)
           VALUES ($1, $2, $3, '{}'::jsonb)"#,
    )
    .bind(id)
    .bind(status)
    .bind(registry_id)
    .execute(pool)
    .await
    .expect("insert clobbered registry_sync row");
    id
}

/// The repair in 0024 uses `registry_id` as the witness of what `status` held
/// before the overwrite: set only by `mark_registered`, so its absence means the
/// row was still `pending` and its registration was never sent. Those rows must
/// come back to `pending` — that is what recovers the already-lost Art. 13
/// registrations in an existing deployment.
#[tokio::test(flavor = "multi_thread")]
async fn migration_0024_restores_registrations_lost_before_the_fix() {
    let (admin_url, _c) = start_pg_before_0024().await;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("admin connect");

    // Never registered — the registration is still owed.
    let lost = insert_clobbered_row(&admin, "suspended", None).await;
    // Already registered before the intent overwrote the column.
    let registered = insert_clobbered_row(&admin, "deactivated", Some("EU-REG-EXISTING")).await;
    // An untouched pending row must be left exactly as it is.
    let untouched = insert_clobbered_row(&admin, "pending", None).await;

    // Apply the migration under test straight from its file. (The other tests
    // in this suite go through `PgDal::migrate`, which proves the runner picks
    // 0024 up; here the manual 0001–0023 run leaves `_sqlx_migrations` empty, so
    // the runner would try to replay them.)
    let sql = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ops/pg/0024_registry_sync_status_intent.sql"
    ))
    .expect("read 0024");
    sqlx::raw_sql(&sql)
        .execute(&admin)
        .await
        .expect("apply 0024");
    admin.close().await;

    let dal = PgDal::connect(&admin_url).await.expect("connect");
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    // Assert on the raw columns, not the parsed enum: `RegistrySyncStatus::from_db`
    // falls back to `Pending` for unrecognised values, so an unhealed 'suspended'
    // row would read back as `Pending` and pass a typed assertion spuriously.
    async fn raw(dal: &PgDal, id: uuid::Uuid) -> (String, Option<String>) {
        sqlx::query_as(
            "SELECT status, status_intent FROM odal.registry_sync WHERE passport_id = $1",
        )
        .bind(id)
        .fetch_one(dal.pool())
        .await
        .expect("read row")
    }

    assert_eq!(
        raw(&dal, lost).await,
        ("pending".into(), Some("suspended".into())),
        "an unsent registration must be restored to the due set"
    );
    assert_eq!(
        raw(&dal, registered).await,
        ("registered".into(), Some("deactivated".into())),
        "a row that had reached the registry must not be re-queued"
    );
    assert_eq!(
        raw(&dal, untouched).await,
        ("pending".into(), None),
        "an untouched pending row is left exactly as it was"
    );

    // The recovered registration is actually drainable again.
    assert!(
        outbox
            .due(50)
            .await
            .unwrap()
            .iter()
            .any(|r| r.passport_id.0 == lost),
        "recovered row is due for drain"
    );
}

// ─── (f) a status intent must not dequeue an unsent registration ──────────────

/// Publish, then suspend before the drain has run. The Art. 13 registration was
/// never sent, so it is still owed — recording the suspend intent must not take
/// it off the queue.
///
/// The window is wide, not a race: the drain runs every 30s, backoff pushes a
/// retrying row out to an hour, and against the current `GhostRegistrySync` stub
/// a row can stay pending indefinitely.
#[tokio::test(flavor = "multi_thread")]
async fn suspend_before_drain_must_not_drop_the_pending_registration() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    let id = create_and_publish(&dal, &outbox).await;

    // Precondition: the publish transaction queued the registration.
    let due = outbox.due(50).await.unwrap();
    assert!(
        due.iter().any(|r| r.passport_id.0 == id.0),
        "publish must leave the registration due for drain"
    );

    // Operator suspends the passport before the drain's next pass.
    outbox
        .enqueue_status(id, RegistryStatusIntent::Suspended)
        .await
        .unwrap();

    let due_after = outbox.due(50).await.unwrap();
    assert!(
        due_after.iter().any(|r| r.passport_id.0 == id.0),
        "recording a suspend intent must not dequeue the unsent registration"
    );

    // And the loss is real, not just a state-machine detail: the registry is
    // never called for this passport.
    let (port, calls) = mock(Outcome::Registered);
    drain_once(&outbox, &port, 50).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the owed registration must still reach the EU registry"
    );
}

// ─── (e) suspend enqueues a durable status intent + counts ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn suspend_enqueues_status_intent_and_counts_reflect_state() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    let id = create_and_publish(&dal, &outbox).await;
    outbox
        .enqueue_status(id, RegistryStatusIntent::Suspended)
        .await
        .unwrap();

    // The intent is recorded *alongside* the queue state, not over it.
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status_intent, Some(RegistryStatusIntent::Suspended));
    assert_eq!(row.status, RegistrySyncStatus::Pending);

    let counts = outbox.status_counts(8).await.unwrap();
    assert_eq!(counts.status_intents, 1);
    assert_eq!(
        counts.pending, 1,
        "the registration is still owed and still counted"
    );
}

// ─── (h) a passport that was never published owes no registration ─────────────

/// `Draft -> Archived` is a legal transition, so `archive` reaches
/// `enqueue_status` for passports that never published and therefore have no
/// outbox row. Recording an intent must not invent one: a fabricated row has no
/// payload, so the drain would mark it `rejected` and raise an Art. 13 alarm for
/// a passport that never owed a registration. The outbox row is created by the
/// publish transaction and by nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn archiving_an_unpublished_draft_creates_no_outbox_row() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let repo = PgPassportRepo::new(dal.clone());

    // A draft that is archived without ever being published.
    let draft = draft_passport();
    let id = draft.id;
    repo.create(draft).await.expect("create draft");
    outbox
        .enqueue_status(id, RegistryStatusIntent::Deactivated)
        .await
        .expect("recording an intent for a never-published passport must not error");

    assert_eq!(
        outbox_row_count(&dal, id).await,
        0,
        "no registration was ever queued, so there is no row to annotate"
    );

    // Nothing to drain, and no false rejection raised.
    let (port, calls) = mock(Outcome::Registered);
    let stats = drain_once(&outbox, &port, 50).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "registry not called");
    assert_eq!(
        (stats.rejected, stats.skipped),
        (0, 0),
        "an unpublished passport must not raise a registration alarm"
    );
    assert_eq!(outbox.status_counts(8).await.unwrap().rejected, 0);
}

// ─── (g) re-publishing clears a now-obsolete suspend intent ───────────────────

/// `Suspended -> Published` is a legal transition, so a recorded `suspended`
/// intent goes stale the moment a passport is re-published. Clearing it on
/// re-publish keeps the future status-sync path from pushing a suspension for a
/// passport that is live again.
#[tokio::test(flavor = "multi_thread")]
async fn republish_clears_a_stale_suspend_intent() {
    let (dal, _c) = start_pg().await;
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    let id = create_and_publish(&dal, &outbox).await;

    // Drain the registration, then suspend.
    let (port, _) = mock(Outcome::Registered);
    drain_once(&outbox, &port, 50).await;
    outbox
        .enqueue_status(id, RegistryStatusIntent::Suspended)
        .await
        .unwrap();
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status_intent, Some(RegistryStatusIntent::Suspended));

    // Operator re-publishes the suspended passport.
    let mut again = draft_passport();
    again.id = id;
    again.status = PassportStatus::Published;
    let payload =
        serde_json::to_value(RegistrationRequest::from_published_passport(&again, "DE")).unwrap();
    outbox.commit_publish(&again, payload).await.unwrap();

    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status_intent, None, "stale suspend intent cleared");
    assert_eq!(
        row.status,
        RegistrySyncStatus::Registered,
        "an already-registered row stays registered"
    );
}
