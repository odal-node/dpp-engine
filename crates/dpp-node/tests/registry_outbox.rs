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
//!   (e) suspend/retire enqueue a durable status intent.
//!
//! And that a status intent is kept strictly out of the registration queue
//! state (`ops/pg/0024`), since conflating them silently dropped registrations:
//!
//!   (f) suspending before the drain runs leaves the registration due;
//!   (g) re-publishing clears a now-obsolete suspend intent;
//!   (h) retiring a never-published draft creates no row, so it raises no
//!       registration alarm;
//!   plus: 0024 restores registrations already lost to the old write path.
//!
//! Run: `cargo test -p dpp-node --features integration-tests --test registry_outbox`

#![cfg(feature = "integration-tests")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::Utc;

use dpp_dal::pg::{PgDal, PgPassportRepo, PgRegistrySyncRepo, sqlx};
use dpp_dal::test_harness::{start_pg, start_pg_before};
use dpp_domain::{
    DppError,
    passport::{ManufacturerInfo, Passport, PassportId},
    ports::passport_repo::PassportRepository,
    ports::registry_sync::{
        RegisteringOperator, RegistrationGranularity, RegistrationRequest, RegistryRecord,
        RegistrySyncPort, SubmissionAcknowledgement, SubmissionLookup, SubmissionReport,
        TransferReport,
    },
    product_group::{ProductGroup, ProductGroupData},
    status::PassportStatus,
};
use dpp_node::infra::registry_drain::drain_once;

/// The operator identity these tests register under. Matches what the node
/// builds from operator config at boot.
fn test_operator() -> RegisteringOperator<'static> {
    RegisteringOperator {
        legal_name: "Test Operator GmbH",
        country: "DE",
        identifier_scheme: "did",
    }
}
use dpp_types::{RegistryStatusIntent, RegistrySyncOutbox, RegistrySyncStatus};

// ─── Harness ────────────────────────────────────────────────────────────────

fn draft_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: Some("LOT-OUTBOX-1".into()),
        serial_number: None,
        product_name: "Outbox Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "TestCorp GmbH".into(),
            address: "Berlin, DE".into(),
            registered_trade_name: None,
            electronic_address: None,
            country: None,
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        // What `RegistrationRequest::from_published_passport` refuses to build a
        // registration without: a product identifier, a carrier and a facility.
        product_group_data: Some(
            serde_json::from_value(serde_json::json!({
                "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                "batteryChemistry": "LFP",
                "batteryType": "industrial",
                "nominalVoltageV": 3.2,
                "nominalCapacityAh": 100.0,
                "co2ePerUnitKg": 85.4
            }))
            .map(|battery| ProductGroupData::Battery(Box::new(battery)))
            .expect("a minimal battery deserialises"),
        ),
        status: PassportStatus::Draft,
        qr_code_url: Some("https://id.example.com/01/09506000134352".into()),
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        placed_on_market_date: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        derived_from: Vec::new(),
        component_refs: Vec::new(),
        life_status: None,
        personal_data: Default::default(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: Some("did:web:test.example".into()),
        responsible_operator: None,
        facility: Some(dpp_domain::FacilitySnapshot {
            scheme: "gln".into(),
            value: "4012345000009".into(),
            name: "Outbox Plant".into(),
            country: "DE".into(),
            address: None,
        }),
        seal: None,
        carrier_serial: None,
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
    let payload = serde_json::to_value(
        RegistrationRequest::from_published_passport(
            &p,
            test_operator(),
            RegistrationGranularity::Item,
        )
        .expect("a complete passport builds a registration"),
    )
    .unwrap();
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

/// What the registry says. A submission is answered with `Accepted`, `Held` or
/// `Transient`; the poll that follows with `Registered`, `Rejected`,
/// `Processing` or `Transient`. The two steps are different questions with
/// different answers, which is the shape of a real asynchronous registration.
#[derive(Clone, Copy)]
enum Outcome {
    /// Submission accepted, under a correlation identifier.
    Accepted,
    /// A replayed submission: the registry holds it and gave no handle for it.
    Held,
    /// The registry could not be reached.
    Transient,
    /// Poll: the registry ruled and generated a registration identifier.
    Registered,
    /// Poll: the registry refused the submission.
    Rejected,
    /// Poll: the registry has not finished checking.
    Processing,
    /// Poll: the registry reported a state this node has no name for.
    Unrecognised,
}

/// The handle the mock registry gives a submission.
const CORRELATION_ID: &str = "CORR-TEST-0001";

/// The registration identifier the mock registry generates.
const REGISTRATION_ID: &str = "EU-REG-TEST-0001";

struct MockPort {
    /// What `register` answers.
    outcome: Outcome,
    calls: Arc<AtomicUsize>,
    /// Calls to `check_submission`, counted separately so a test can prove the
    /// drain *polled* a submitted row instead of registering it again.
    polls: Arc<AtomicUsize>,
    /// What a poll reports.
    poll_outcome: Outcome,
    /// What a lookup of a submission by what was submitted finds.
    lookup: SubmissionLookup,
    /// Calls to `find_submission`, and for which passport each was made, so a
    /// test can prove the drain looked, and looked for the right row.
    lookups: Arc<AtomicUsize>,
    looked_for: Arc<std::sync::Mutex<Vec<PassportId>>>,
}

#[async_trait]
impl RegistrySyncPort for MockPort {
    async fn find_submission(
        &self,
        request: &RegistrationRequest,
    ) -> Result<SubmissionLookup, DppError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.looked_for.lock().unwrap().push(request.passport_id);
        Ok(self.lookup.clone())
    }

    async fn register(
        &self,
        _req: RegistrationRequest,
    ) -> Result<SubmissionAcknowledgement, DppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            Outcome::Accepted => Ok(SubmissionAcknowledgement::Accepted {
                correlation_id: CORRELATION_ID.into(),
            }),
            Outcome::Held => Ok(SubmissionAcknowledgement::AlreadyHeld),
            Outcome::Transient => Err(DppError::Internal("EU registry transient failure".into())),
            other => panic!("not an answer to a submission: {}", other as u8),
        }
    }

    async fn check_submission(&self, correlation_id: &str) -> Result<SubmissionReport, DppError> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        // A poll names the submission by the handle the registry gave it, never
        // by this node's passport id.
        assert_eq!(correlation_id, CORRELATION_ID);
        match self.poll_outcome {
            Outcome::Registered => Ok(SubmissionReport::Registered {
                registration_id: REGISTRATION_ID.into(),
            }),
            Outcome::Rejected => Ok(SubmissionReport::Refused {
                reason: "the registry refused the submission: NOT_RESOLVABLE_UPI".into(),
            }),
            Outcome::Processing => Ok(SubmissionReport::Processing),
            Outcome::Unrecognised => Ok(SubmissionReport::Unrecognised {
                state: "UNDER_REVIEW".into(),
            }),
            Outcome::Transient => Err(DppError::Internal("EU registry transient failure".into())),
            other => panic!("not an answer to a poll: {}", other as u8),
        }
    }

    async fn check_status(&self, _registration_id: &str) -> Result<RegistryRecord, DppError> {
        unimplemented!("not exercised")
    }

    async fn notify_transfer(
        &self,
        _record: &dpp_domain::transfer::TransferRecord,
        _registry_id: &str,
    ) -> Result<TransferReport, DppError> {
        unimplemented!("not exercised")
    }
}

fn mock(outcome: Outcome) -> (Arc<dyn RegistrySyncPort>, Arc<AtomicUsize>) {
    let (port, calls, _) = mock_with_poll(outcome, Outcome::Processing);
    (port, calls)
}

/// A port whose submission and poll answer differently — the shape of a real
/// asynchronous registration.
fn mock_with_poll(
    outcome: Outcome,
    poll_outcome: Outcome,
) -> (
    Arc<dyn RegistrySyncPort>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let (port, calls, polls, _) =
        mock_with_lookup(outcome, poll_outcome, SubmissionLookup::Unsupported);
    (port, calls, polls)
}

/// What a recovery test watches: the lookups made, and for which passports.
struct Lookups {
    count: Arc<AtomicUsize>,
    looked_for: Arc<std::sync::Mutex<Vec<PassportId>>>,
}

/// A port that also answers a lookup of a submission by what was submitted — the
/// recovery path for a handle a replayed key left us without.
fn mock_with_lookup(
    outcome: Outcome,
    poll_outcome: Outcome,
    lookup: SubmissionLookup,
) -> (
    Arc<dyn RegistrySyncPort>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Lookups,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let lookups = Lookups {
        count: Arc::new(AtomicUsize::new(0)),
        looked_for: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let port: Arc<dyn RegistrySyncPort> = Arc::new(MockPort {
        outcome,
        calls: calls.clone(),
        polls: polls.clone(),
        poll_outcome,
        lookup,
        lookups: lookups.count.clone(),
        looked_for: lookups.looked_for.clone(),
    });
    (port, calls, polls, lookups)
}

/// Make every row due again, as the passage of the backoff would.
async fn make_due(dal: &PgDal, id: PassportId) {
    sqlx::query("UPDATE odal.registry_sync SET next_attempt_at = now() WHERE passport_id = $1")
        .bind(id.0)
        .execute(dal.pool())
        .await
        .expect("make the row due");
}

// ─── (a) atomic publish + idempotency + (b) drains exactly once ───────────────

#[tokio::test(flavor = "multi_thread")]
async fn publish_is_atomic_idempotent_and_drains_exactly_once() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
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
    let payload = serde_json::to_value(
        RegistrationRequest::from_published_passport(
            &again,
            test_operator(),
            RegistrationGranularity::Item,
        )
        .expect("a complete passport builds a registration"),
    )
    .unwrap();
    outbox.commit_publish(&again, payload).await.unwrap();
    assert_eq!(outbox_row_count(&dal, id).await, 1, "still exactly one row");

    // (b) drain with a healthy port. The first pass submits and the registry
    // answers with a handle; the second reads its ruling and registers. After
    // that a pass is a no-op, so the registry is submitted to exactly once
    // across the (simulated) restart.
    let (port, calls, polls) = mock_with_poll(Outcome::Accepted, Outcome::Registered);
    let s1 = drain_once(&outbox, &port, None, 50).await;
    assert_eq!(s1.submitted, 1);
    assert_eq!(s1.registered, 0, "an acknowledgement is not a registration");
    let submitted = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(submitted.status, RegistrySyncStatus::Submitted);
    assert_eq!(submitted.registry_id.as_deref(), Some(CORRELATION_ID));

    make_due(&dal, id).await;
    let s2 = drain_once(&outbox, &port, None, 50).await;
    assert_eq!(s2.registered, 1);
    let after = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(after.status, RegistrySyncStatus::Registered);
    assert_eq!(
        after.registry_id.as_deref(),
        Some(REGISTRATION_ID),
        "the column now holds the registration identifier, not the handle"
    );

    assert!(
        outbox.due(50).await.unwrap().is_empty(),
        "registered row not due"
    );
    let s3 = drain_once(&outbox, &port, None, 50).await;
    assert_eq!(s3.registered, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "submitted exactly once");
    assert_eq!(polls.load(Ordering::SeqCst), 1, "polled exactly once");
}

// ─── (c) transient backoff and (d) terminal rejection ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn drain_backs_off_on_transient_and_marks_terminal_rejection() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    // (c) transient failure → attempts++, still pending, pushed into the future.
    let transient_id = create_and_publish(&dal, &outbox).await;
    let (port_t, _) = mock(Outcome::Transient);
    let st = drain_once(&outbox, &port_t, None, 50).await;
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
    // The registry accepts the submission and rules against it afterwards.
    let (port_r, _, _) = mock_with_poll(Outcome::Accepted, Outcome::Rejected);
    drain_once(&outbox, &port_r, None, 50).await;
    make_due(&dal, rejected_id).await;
    let sr = drain_once(&outbox, &port_r, None, 50).await;
    assert_eq!(sr.rejected, 1);
    let row = outbox.pending_for(rejected_id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Rejected);
    assert!(
        row.message
            .as_deref()
            .is_some_and(|m| m.contains("NOT_RESOLVABLE_UPI")),
        "the registry's reason reaches the row for a human: {:?}",
        row.message
    );
}

// ─── 0024 heals rows the old write path already clobbered ─────────────────────

/// Bring a fresh database up to the pre-0024 schema by applying every migration
/// before it, so the damaged state can be reproduced and the repair exercised.
/// Returns the privileged URL.
/// Returns `(admin_url, app_url, container)`. Both are needed: the admin URL
/// does the privileged setup (role creation, hand-applying 0001–0023, seeding
/// the clobbered rows), and the app URL is what `PgDal::connect` takes — it
/// refuses a superuser role, since a superuser owns the audit table and the
/// append-only trigger cannot bind it.
/// Insert a passport plus a `registry_sync` row in the shape the old
/// `enqueue_status` left behind — an intent sitting in the `status` column.
async fn insert_clobbered_row(
    pool: &sqlx::PgPool,
    status: &str,
    registry_id: Option<&str>,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    // `sector`, not `product_group`, and deliberately so: this helper writes
    // against the schema as it stood before 0024, and the column is not renamed
    // until 0032. A rename sweep "corrected" this once and the insert began
    // failing with `column "product_group" does not exist` — the one place in
    // the tree where the old name is the right one, because it is describing
    // history rather than the current schema.
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
    let _c = start_pg_before("0024_").await;
    let (admin_url, app_url) = (_c.admin_url.clone(), _c.app_url.clone());
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
    // Repo-controlled migration text from ops/pg, not caller input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(&admin)
        .await
        .expect("apply 0024");
    admin.close().await;

    let dal = PgDal::connect(&app_url).await.expect("connect");
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
    let _c = start_pg().await;
    let dal = _c.dal.clone();
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
    let (port, calls) = mock(Outcome::Accepted);
    drain_once(&outbox, &port, None, 50).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the owed registration must still reach the EU registry"
    );
}

// ─── (e) suspend enqueues a durable status intent + counts ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn suspend_enqueues_status_intent_and_counts_reflect_state() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
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

/// `Draft -> Retired` is a legal transition, so `retire` reaches
/// `enqueue_status` for passports that never published and therefore have no
/// outbox row. Recording an intent must not invent one: a fabricated row has no
/// payload, so the drain would mark it `rejected` and raise an Art. 13 alarm for
/// a passport that never owed a registration. The outbox row is created by the
/// publish transaction and by nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn retiring_an_unpublished_draft_creates_no_outbox_row() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let repo = PgPassportRepo::new(dal.clone());

    // A draft that is retired without ever being published.
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
    let (port, calls) = mock(Outcome::Accepted);
    let stats = drain_once(&outbox, &port, None, 50).await;
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
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));

    let id = create_and_publish(&dal, &outbox).await;

    // Drain the registration — submitted, then ruled on — then suspend.
    let (port, _, _) = mock_with_poll(Outcome::Accepted, Outcome::Registered);
    drain_once(&outbox, &port, None, 50).await;
    make_due(&dal, id).await;
    drain_once(&outbox, &port, None, 50).await;
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
    let payload = serde_json::to_value(
        RegistrationRequest::from_published_passport(
            &again,
            test_operator(),
            RegistrationGranularity::Item,
        )
        .expect("a complete passport builds a registration"),
    )
    .unwrap();
    outbox.commit_publish(&again, payload).await.unwrap();

    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status_intent, None, "stale suspend intent cleared");
    assert_eq!(
        row.status,
        RegistrySyncStatus::Registered,
        "an already-registered row stays registered"
    );
}

// ─── asynchronous validation: submitted is not registered ────────────────────

/// The registry accepts a submission and validates it afterwards. That first
/// answer is `Pending`, and it must NOT close the row: doing so recorded every
/// submission as complete and never learned if it was later refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_submission_is_not_yet_a_registration() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, calls) = mock(Outcome::Accepted);
    let stats = drain_once(&outbox, &port, None, 10).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(stats.submitted, 1);
    assert_eq!(stats.registered, 0, "a verdict has not been given yet");

    let row = outbox
        .pending_for(id)
        .await
        .expect("query")
        .expect("row must survive");
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    assert_eq!(
        row.registry_id.as_deref(),
        Some(CORRELATION_ID),
        "the registry's handle is kept so the verdict can be polled for"
    );
}

/// A processing submission stays `submitted` and is asked again later: the
/// registry has not ruled, and neither recording a registration nor a refusal
/// would be true. "Later" is the backoff the acknowledgement set, applied again
/// by every poll that gets no ruling. Each poll counts as an attempt, so a
/// submission that is never ruled on reaches the stalled count, and the row is
/// not due again on the very next pass: left due it would be polled every pass
/// and sort to the head of the queue ahead of every pending row.
#[tokio::test(flavor = "multi_thread")]
async fn a_submission_still_being_checked_keeps_being_polled() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, calls, polls) = mock_with_poll(Outcome::Accepted, Outcome::Processing);
    drain_once(&outbox, &port, None, 10).await;
    let mut attempts = outbox.pending_for(id).await.unwrap().unwrap().attempts;
    for polled in 1..=2 {
        make_due(&dal, id).await;
        let stats = drain_once(&outbox, &port, None, 10).await;
        assert_eq!(stats.submitted, 1);
        assert_eq!((stats.registered, stats.rejected), (0, 0));

        // The poll found no ruling, so the row is backed off and the attempt is
        // counted...
        let row = outbox.pending_for(id).await.unwrap().unwrap();
        assert!(
            row.next_attempt_at > Utc::now(),
            "a poll with no ruling backs the row off"
        );
        assert!(row.attempts > attempts, "and counts as an attempt");
        attempts = row.attempts;

        // ...so the next pass, with the backoff still running, leaves it alone.
        let idle = drain_once(&outbox, &port, None, 10).await;
        assert_eq!(idle.submitted, 0);
        assert_eq!(
            polls.load(Ordering::SeqCst),
            polled,
            "not polled again before the backoff has passed"
        );
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1, "never resubmitted");
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    assert_eq!(row.registry_id.as_deref(), Some(CORRELATION_ID));
}

/// A replayed idempotency key is answered without an id: the registry holds the
/// submission and says nothing more about it. The row must still move to
/// `submitted` — that is what stops the drain posting it again — but it must not
/// record an empty string as the registry's id, which the status route would
/// then report as one.
#[tokio::test(flavor = "multi_thread")]
async fn a_submission_the_registry_already_holds_is_submitted_without_an_id() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, calls) = mock(Outcome::Held);
    let stats = drain_once(&outbox, &port, None, 10).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(stats.submitted, 1);
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    assert_eq!(
        row.registry_id, None,
        "no id was returned, so none may be recorded"
    );

    // With no handle there is nothing to poll, and the node's own passport id is
    // not a substitute: the registry never received it. The row waits, neither
    // polled nor submitted again.
    let attempts = row.attempts;
    make_due(&dal, id).await;
    let later = drain_once(&outbox, &port, None, 10).await;
    assert_eq!(later.submitted, 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the registry holds it already, so it is not submitted again"
    );
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    // Waiting is backed off and counted, not left due: a row that stays due sorts
    // to the head of the queue every pass, and one whose attempts never grow can
    // never reach the stalled count that says it needs reconciling.
    assert!(
        row.next_attempt_at > Utc::now(),
        "a handle-less row is backed off, not left due"
    );
    assert!(
        row.attempts > attempts,
        "and each pass counts as an attempt"
    );
}

// ─── a handle a replayed key left us without ────────────────────────────────

/// 🚨 The registry holds a submission and a replayed key did not say under which
/// handle. The drain looks for it, by what the passport was submitted under, and
/// when it is found the row takes the handle *and* the ruling in the same pass: a
/// passport that would have waited for a person is registered.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_handle_is_recovered_and_the_ruling_applied() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, calls, polls, lookups) = mock_with_lookup(
        Outcome::Held,
        Outcome::Processing,
        SubmissionLookup::Found {
            correlation_id: CORRELATION_ID.into(),
            report: SubmissionReport::Registered {
                registration_id: REGISTRATION_ID.into(),
            },
        },
    );
    let stats = drain_once(&outbox, &port, None, 10).await;

    assert_eq!(stats.recovered, 1);
    assert_eq!(stats.registered, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "submitted once");
    assert_eq!(polls.load(Ordering::SeqCst), 0, "found, so not polled");
    assert_eq!(lookups.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        lookups.looked_for.lock().unwrap().as_slice(),
        [id],
        "it looked for this passport's submission, from its own frozen payload"
    );
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Registered);
    assert_eq!(row.registry_id.as_deref(), Some(REGISTRATION_ID));
}

/// A submission found while the registry is still checking it gives the handle
/// and nothing else: the row keeps the handle, stays `submitted`, and the next
/// pass polls it as it would any submission it holds the handle of.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_handle_found_while_still_being_checked_is_polled_next() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, _calls, polls, lookups) = mock_with_lookup(
        Outcome::Held,
        Outcome::Registered,
        SubmissionLookup::Found {
            correlation_id: CORRELATION_ID.into(),
            report: SubmissionReport::Processing,
        },
    );
    let first = drain_once(&outbox, &port, None, 10).await;
    assert_eq!(
        (first.recovered, first.submitted, first.registered),
        (1, 1, 0)
    );
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    assert_eq!(
        row.registry_id.as_deref(),
        Some(CORRELATION_ID),
        "the handle is recorded, whatever the ruling turns out to be"
    );

    // From here it is an ordinary submitted row: polled by its handle, and the
    // lookup is not asked again.
    make_due(&dal, id).await;
    let second = drain_once(&outbox, &port, None, 10).await;
    assert_eq!(second.registered, 1);
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(lookups.count.load(Ordering::SeqCst), 1);
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Registered);
}

/// 🚨 Two submissions report the passport's identifier, so the handle is not
/// chosen: choosing would give the passport another's registration. The row waits
/// for a person, backed off and counted, with nothing recorded as a handle.
#[tokio::test(flavor = "multi_thread")]
async fn an_ambiguous_lost_handle_is_not_guessed() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, _calls, polls, _lookups) = mock_with_lookup(
        Outcome::Held,
        Outcome::Registered,
        SubmissionLookup::Ambiguous {
            candidates: vec!["CORR-OLD".into(), "CORR-NEW".into()],
        },
    );
    let stats = drain_once(&outbox, &port, None, 10).await;

    assert_eq!(
        (stats.recovered, stats.registered, stats.submitted),
        (0, 0, 1)
    );
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "no handle, so nothing to poll"
    );
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    assert_eq!(
        row.registry_id, None,
        "no candidate is recorded as the handle"
    );
    assert!(
        row.next_attempt_at > Utc::now(),
        "backed off, so it does not sort to the head of the queue every pass"
    );
    // The reason is on the row, where the per-passport registry route reads it,
    // and not only in a log: both candidates, and what to do about them.
    let message = row.message.expect("a row waiting for a person says why");
    assert!(
        message.contains("CORR-OLD") && message.contains("CORR-NEW"),
        "the candidates are named: {message}"
    );
    assert!(
        message.contains("odal registry handle"),
        "and so is the way to settle it: {message}"
    );
}

/// 🚨 The whole way through: a row waiting for a person says why, a handle
/// recorded by hand is polled like any other, the ruling is applied by the drain,
/// and the row's old stall does not outlive the intervention.
#[tokio::test(flavor = "multi_thread")]
async fn a_handle_recorded_by_hand_is_polled_and_ruled_on_by_the_drain() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (blind, _, _, _) = mock_with_lookup(
        Outcome::Held,
        Outcome::Registered,
        SubmissionLookup::Ambiguous {
            candidates: vec!["CORR-OLD".into(), CORRELATION_ID.into()],
        },
    );
    drain_once(&outbox, &blind, None, 10).await;
    let waiting = outbox.pending_for(id).await.unwrap().unwrap();
    assert!(waiting.attempts > 0 && waiting.message.is_some());

    assert!(
        outbox.record_handle(id, CORRELATION_ID).await.unwrap(),
        "a submitted row with no handle takes one"
    );
    let recorded = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(recorded.registry_id.as_deref(), Some(CORRELATION_ID));
    assert_eq!(recorded.status, RegistrySyncStatus::Submitted);
    assert_eq!(
        recorded.attempts, 0,
        "a new poll on a checked handle is not the stall that came before"
    );
    assert_eq!(
        recorded.message, None,
        "the reason was about the missing handle"
    );
    assert!(
        recorded.next_attempt_at <= Utc::now(),
        "due at once, not after the backoff the missing handle earned"
    );

    // The drain polls by the recorded handle and applies the ruling.
    let (seeing, calls, polls, lookups) = mock_with_lookup(
        Outcome::Held,
        Outcome::Registered,
        SubmissionLookup::Unsupported,
    );
    let stats = drain_once(&outbox, &seeing, None, 10).await;
    assert_eq!(stats.registered, 1);
    assert_eq!(polls.load(Ordering::SeqCst), 1, "polled by the handle");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "never submitted again");
    assert_eq!(
        lookups.count.load(Ordering::SeqCst),
        0,
        "nothing to look for"
    );
    let ruled = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(ruled.status, RegistrySyncStatus::Registered);
    assert_eq!(ruled.registry_id.as_deref(), Some(REGISTRATION_ID));
}

/// 🚨 `record_handle` takes a handle only for a `submitted` row that holds none.
/// It never overwrites one the registry gave, never reaches a row that has been
/// ruled on, and never makes a handle of a row that has not been submitted.
#[tokio::test(flavor = "multi_thread")]
async fn a_handle_is_recorded_only_on_a_submitted_row_that_holds_none() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    // Pending: the registry has not accepted it, so there is no handle to record.
    assert!(!outbox.record_handle(id, "CORR-X").await.unwrap());
    let pending = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(
        (pending.status, pending.registry_id),
        (RegistrySyncStatus::Pending, None)
    );

    // Submitted with no handle: it takes one…
    outbox.mark_submitted(id, String::new()).await.unwrap();
    assert!(outbox.record_handle(id, "CORR-FIRST").await.unwrap());
    // …and only one: a second is not stacked on the first.
    assert!(!outbox.record_handle(id, "CORR-SECOND").await.unwrap());
    assert!(
        !outbox.record_handle(id, "CORR-FIRST").await.unwrap(),
        "even the same one: the answer is that nothing was written"
    );
    assert_eq!(
        outbox
            .pending_for(id)
            .await
            .unwrap()
            .unwrap()
            .registry_id
            .as_deref(),
        Some("CORR-FIRST")
    );

    // Ruled on: the registration identifier is not to be replaced by a handle.
    outbox
        .mark_registered(id, REGISTRATION_ID.into())
        .await
        .unwrap();
    assert!(!outbox.record_handle(id, "CORR-LATE").await.unwrap());
    assert_eq!(
        outbox
            .pending_for(id)
            .await
            .unwrap()
            .unwrap()
            .registry_id
            .as_deref(),
        Some(REGISTRATION_ID)
    );

    // And a rejected row, which holds no handle worth recording.
    let other = {
        let repo = PgPassportRepo::new(dal.clone());
        let mut p = draft_passport();
        p.id = PassportId::new();
        repo.create(p.clone()).await.expect("create second draft");
        p.status = PassportStatus::Published;
        p.published_at = Some(Utc::now());
        let payload = serde_json::to_value(
            RegistrationRequest::from_published_passport(
                &p,
                test_operator(),
                RegistrationGranularity::Item,
            )
            .unwrap(),
        )
        .unwrap();
        outbox.commit_publish(&p, payload).await.unwrap();
        p.id
    };
    outbox.mark_rejected(other, "refused".into()).await.unwrap();
    assert!(!outbox.record_handle(other, "CORR-Y").await.unwrap());
}

/// 🚨 `abandon` ends only a row the drain has tried and is not about to try again:
/// `pending`, attempted at least once, and backed off. A new row is due, a row
/// being attempted is still due, and a `submitted` row is one the registry holds.
/// Each is what stops this write racing the drain or orphaning a registration.
#[tokio::test(flavor = "multi_thread")]
async fn a_row_is_abandoned_only_after_a_failed_attempt_and_while_it_waits() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    // Never tried: due now, and indistinguishable from a row about to be submitted.
    assert!(!outbox.abandon(id, "withdrawn".into()).await.unwrap());

    // Tried and failed: backed off, so the drain is not about to touch it.
    outbox
        .mark_attempt_failed(id, "the registry refused the payload".into())
        .await
        .unwrap();
    // …but a row the backoff has run out on is due again, and so is not abandoned.
    make_due(&dal, id).await;
    assert!(
        !outbox.abandon(id, "withdrawn".into()).await.unwrap(),
        "due again: the drain may be in the middle of trying it"
    );
    outbox
        .mark_attempt_failed(id, "the registry refused the payload".into())
        .await
        .unwrap();

    assert!(outbox.abandon(id, "withdrawn".into()).await.unwrap());
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Abandoned);
    assert_eq!(row.message.as_deref(), Some("withdrawn"));
    assert_eq!(row.attempts, 2, "what it took to give up on is kept");

    // And only once.
    assert!(!outbox.abandon(id, "again".into()).await.unwrap());
    assert_eq!(
        outbox
            .pending_for(id)
            .await
            .unwrap()
            .unwrap()
            .message
            .as_deref(),
        Some("withdrawn")
    );

    // A submitted row is one the registry holds; a ruled-on one needs nothing.
    let held = create_and_publish(&dal, &outbox).await;
    outbox.mark_submitted(held, "CORR-X".into()).await.unwrap();
    assert!(!outbox.abandon(held, "no".into()).await.unwrap());
    outbox
        .mark_registered(held, REGISTRATION_ID.into())
        .await
        .unwrap();
    assert!(!outbox.abandon(held, "no".into()).await.unwrap());
    assert_eq!(
        outbox.pending_for(held).await.unwrap().unwrap().status,
        RegistrySyncStatus::Registered
    );
}

/// 🚨 Abandoned is terminal for the drain. It is never offered a row in that state,
/// and nothing it writes can move one out of it: a pass that read a row before it
/// was abandoned would otherwise record its outcome over the decision.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_the_drain_writes_resurrects_an_abandoned_row() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;
    outbox
        .mark_attempt_failed(id, "refused".into())
        .await
        .unwrap();
    assert!(outbox.abandon(id, "withdrawn".into()).await.unwrap());
    make_due(&dal, id).await;

    // A pass finds nothing to do, and submits nothing.
    let (port, calls, polls, lookups) = mock_with_lookup(
        Outcome::Accepted,
        Outcome::Registered,
        SubmissionLookup::Unsupported,
    );
    let stats = drain_once(&outbox, &port, None, 10).await;
    assert_eq!(
        (
            stats.registered,
            stats.submitted,
            stats.rejected,
            stats.retried
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "never submitted");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(lookups.count.load(Ordering::SeqCst), 0);

    // And every write the drain makes about a row bounces off.
    assert!(outbox.mark_submitted(id, "CORR".into()).await.is_err());
    assert!(
        outbox
            .mark_submitted_noting(id, "waiting".into())
            .await
            .is_err()
    );
    assert!(
        outbox
            .mark_registered(id, REGISTRATION_ID.into())
            .await
            .is_err()
    );
    assert!(outbox.mark_rejected(id, "refused".into()).await.is_err());
    assert!(
        outbox
            .mark_attempt_failed(id, "failed".into())
            .await
            .is_err()
    );
    assert!(!outbox.record_handle(id, "CORR").await.unwrap());

    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Abandoned);
    assert_eq!(row.message.as_deref(), Some("withdrawn"));
    assert_eq!(row.registry_id, None);
}

/// An abandoned registration is counted, so a published passport that will not be
/// registered is visible and not read as still owed, and it does not count as
/// stalled work for anyone to do.
#[tokio::test(flavor = "multi_thread")]
async fn an_abandoned_registration_is_counted_and_is_not_stalled() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;
    for _ in 0..3 {
        outbox
            .mark_attempt_failed(id, "refused".into())
            .await
            .unwrap();
    }
    let before = outbox.status_counts(2).await.unwrap();
    assert_eq!(
        (before.pending, before.abandoned, before.stalled),
        (1, 0, 1)
    );

    assert!(outbox.abandon(id, "withdrawn".into()).await.unwrap());

    let after = outbox.status_counts(2).await.unwrap();
    assert_eq!(
        (after.pending, after.abandoned, after.stalled),
        (0, 1, 0),
        "no longer owed, and no longer asking for a person"
    );
}

/// Publishing the passport again is a new obligation to register it, and the only
/// way back: it queues the registration afresh, as it does one the registry
/// rejected.
#[tokio::test(flavor = "multi_thread")]
async fn publishing_again_queues_an_abandoned_registration_afresh() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let repo = PgPassportRepo::new(dal.clone());
    let mut p = draft_passport();
    repo.create(p.clone()).await.expect("create draft");
    p.status = PassportStatus::Published;
    p.published_at = Some(Utc::now());
    let payload = serde_json::to_value(
        RegistrationRequest::from_published_passport(
            &p,
            test_operator(),
            RegistrationGranularity::Item,
        )
        .unwrap(),
    )
    .unwrap();
    outbox.commit_publish(&p, payload.clone()).await.unwrap();
    outbox
        .mark_attempt_failed(p.id, "refused".into())
        .await
        .unwrap();
    assert!(outbox.abandon(p.id, "withdrawn".into()).await.unwrap());

    outbox.commit_publish(&p, payload).await.unwrap();

    let row = outbox.pending_for(p.id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Pending);
    assert_eq!(row.attempts, 0);
    assert_eq!(
        row.message, None,
        "whatever it said belonged to the old one"
    );
    assert!(row.next_attempt_at <= Utc::now(), "due at once");
}

/// A state nobody has named keeps the row polling and says what it was, so an
/// operator is not left to find it in a log.
#[tokio::test(flavor = "multi_thread")]
async fn an_unrecognised_submission_state_is_kept_on_the_row() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    // The row is submitted under a handle, then polled.
    outbox
        .mark_submitted(id, CORRELATION_ID.into())
        .await
        .unwrap();
    make_due(&dal, id).await;
    let (port, _, _) = mock_with_poll(Outcome::Held, Outcome::Unrecognised);
    let stats = drain_once(&outbox, &port, None, 10).await;

    assert_eq!(stats.submitted, 1);
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    let message = row.message.expect("the state is on the row");
    assert!(message.contains("UNDER_REVIEW"), "{message}");

    // And a later answer that is just "still checking" takes the note away: it
    // was about a state the registry has since left.
    make_due(&dal, id).await;
    let (port, _, _) = mock_with_poll(Outcome::Held, Outcome::Processing);
    drain_once(&outbox, &port, None, 10).await;
    assert_eq!(outbox.pending_for(id).await.unwrap().unwrap().message, None);
}

/// Not finding it is not an answer, so the lookup is repeated on a later pass,
/// each one counted as an attempt: a row that is never found reaches the stalled
/// count that tells an operator it needs a person.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_handle_that_is_not_found_is_looked_for_again_and_counted() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let (port, _calls, _polls, lookups) = mock_with_lookup(
        Outcome::Held,
        Outcome::Processing,
        SubmissionLookup::NotFound { exhaustive: false },
    );
    drain_once(&outbox, &port, None, 10).await;
    let first_attempts = outbox.pending_for(id).await.unwrap().unwrap().attempts;

    let idle = drain_once(&outbox, &port, None, 10).await;
    assert_eq!(
        idle.submitted, 0,
        "backed off: not looked for on the very next pass"
    );
    assert_eq!(lookups.count.load(Ordering::SeqCst), 1);

    make_due(&dal, id).await;
    let again = drain_once(&outbox, &port, None, 10).await;
    assert_eq!((again.submitted, again.recovered), (1, 0));
    assert_eq!(lookups.count.load(Ordering::SeqCst), 2, "looked for again");
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert!(row.attempts > first_attempts, "every look is an attempt");
    assert_eq!(row.status, RegistrySyncStatus::Submitted);
    assert_eq!(row.registry_id, None);
    let message = row.message.expect("a row that cannot be found says so");
    assert!(
        message.contains("not found among its tasks") && message.contains("absence proves nothing"),
        "{message}"
    );
}

/// A submitted row with no handle that was left by an earlier pass is recovered
/// too, not only one that was just told so: the row's frozen payload is what says
/// what to look for.
#[tokio::test(flavor = "multi_thread")]
async fn a_handleless_row_from_an_earlier_pass_is_recovered_from_its_payload() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    // The first pass finds nothing: the registry's list does not show it yet.
    let (blind, _, _, _) = mock_with_lookup(
        Outcome::Held,
        Outcome::Processing,
        SubmissionLookup::NotFound { exhaustive: false },
    );
    drain_once(&outbox, &blind, None, 10).await;
    assert_eq!(
        outbox.pending_for(id).await.unwrap().unwrap().registry_id,
        None
    );

    // A later pass, once it is listed, finds it, and does not submit again.
    let (seeing, calls, _polls, lookups) = mock_with_lookup(
        Outcome::Held,
        Outcome::Processing,
        SubmissionLookup::Found {
            correlation_id: CORRELATION_ID.into(),
            report: SubmissionReport::Processing,
        },
    );
    make_due(&dal, id).await;
    let stats = drain_once(&outbox, &seeing, None, 10).await;

    assert_eq!(stats.recovered, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "not submitted again");
    assert_eq!(lookups.count.load(Ordering::SeqCst), 1);
    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.registry_id.as_deref(), Some(CORRELATION_ID));
    assert_eq!(
        row.message, None,
        "found, so the reason it was waiting is gone"
    );
}

/// A submitted row is polled, never resubmitted — resubmitting is what would
/// register the same product twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_submitted_row_is_polled_not_resubmitted() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    // First pass: accepted for validation.
    let (port, calls, polls) = mock_with_poll(Outcome::Accepted, Outcome::Registered);
    drain_once(&outbox, &port, None, 10).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(polls.load(Ordering::SeqCst), 0);

    // The row is backed off; make it due again.
    sqlx::query("UPDATE odal.registry_sync SET next_attempt_at = now() WHERE passport_id = $1")
        .bind(id.0)
        .execute(dal.pool())
        .await
        .expect("make the row due");

    // Second pass: the verdict arrives via a poll.
    let stats = drain_once(&outbox, &port, None, 10).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the registration must not be submitted a second time"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1, "it must be polled instead");
    assert_eq!(stats.registered, 1);

    let row = outbox.pending_for(id).await.unwrap().unwrap();
    assert_eq!(row.status, RegistrySyncStatus::Registered);
}

// ─── reconciliation: published passports nobody is tracking ──────────────────

/// A passport published before this outbox existed (or lost to an older write
/// path) owes a registration with nothing tracking it. The reconciliation count
/// surfaces those without fabricating a row that could never drain.
#[tokio::test(flavor = "multi_thread")]
async fn a_published_passport_with_no_outbox_row_is_counted() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let repo = PgPassportRepo::new(dal.clone());

    // A passport written straight to Published, bypassing commit_publish — the
    // shape of every passport that predates the outbox.
    let mut orphan = draft_passport();
    orphan.status = PassportStatus::Published;
    orphan.published_at = Some(Utc::now());
    repo.create(orphan.clone()).await.expect("create orphan");

    assert_eq!(
        outbox
            .unregistered_published_count()
            .await
            .expect("count query"),
        1,
        "a Published passport with no outbox row must be visible"
    );
    assert!(
        outbox.pending_for(orphan.id).await.unwrap().is_none(),
        "and it must NOT have been given a fabricated row"
    );

    // A properly published passport does not add to the count.
    create_and_publish(&dal, &outbox).await;
    assert_eq!(
        outbox
            .unregistered_published_count()
            .await
            .expect("count query"),
        1,
        "a passport published through the outbox is tracked, not orphaned"
    );
}

/// A draft is not owed a registration, so it is not an orphan.
#[tokio::test(flavor = "multi_thread")]
async fn an_unpublished_draft_is_not_counted_as_unregistered() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let repo = PgPassportRepo::new(dal.clone());

    repo.create(draft_passport()).await.expect("create draft");

    assert_eq!(
        outbox
            .unregistered_published_count()
            .await
            .expect("count query"),
        0
    );
}

// ─── verified-operator status gates the drain ────────────────────────────────

/// Set the operator's verification date, returning the repo the drain reads.
async fn operator_verified_at(
    dal: &PgDal,
    at: Option<chrono::DateTime<Utc>>,
) -> Arc<dyn dpp_types::operator::OperatorConfigRepository> {
    let repo = dpp_dal::pg::PgOperatorConfigRepo::new(dal.clone());
    let mut cfg = dpp_types::OperatorConfig::empty(dpp_types::STANDALONE_OPERATOR_ID);
    cfg.legal_name = "Test Operator GmbH".into();
    cfg.address = "Berlin".into();
    cfg.country = "DE".into();
    cfg.contact_email = "ops@example.com".into();
    cfg.registry_verified_at = at;
    dpp_types::operator::OperatorConfigRepository::upsert(&repo, cfg)
        .await
        .expect("seed operator config");
    Arc::new(repo)
}

/// Verified status lapses after three years. Submitting past that earns an
/// opaque remote refusal, so the drain holds instead — and holds *without*
/// touching the rows, so re-verification resumes everything untouched.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_operator_holds_the_drain_without_losing_rows() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    let id = create_and_publish(&dal, &outbox).await;

    let expired =
        operator_verified_at(&dal, Some(Utc::now() - chrono::Duration::days(365 * 3 + 1))).await;
    let (port, calls, _) = mock_with_poll(Outcome::Accepted, Outcome::Registered);
    let stats = drain_once(&outbox, &port, Some(&expired), 50).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "an unverified operator must not reach the registry"
    );
    assert_eq!(stats, Default::default(), "nothing was processed");

    let row = outbox.pending_for(id).await.unwrap().expect("row survives");
    assert_eq!(row.status, RegistrySyncStatus::Pending);
    assert_eq!(
        row.attempts, 0,
        "holding is not a failed attempt — the row must not back off"
    );

    // Re-verify, and the same pass now goes through.
    let current = operator_verified_at(&dal, Some(Utc::now())).await;
    let stats = drain_once(&outbox, &port, Some(&current), 50).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        stats.submitted, 1,
        "the held row is submitted once verified"
    );

    // And the registry's ruling follows on the next pass.
    make_due(&dal, id).await;
    let stats = drain_once(&outbox, &port, Some(&current), 50).await;
    assert_eq!(stats.registered, 1);
}

/// Never verified is the same refusal: there is no verified status to rely on.
#[tokio::test(flavor = "multi_thread")]
async fn a_never_verified_operator_also_holds_the_drain() {
    let _c = start_pg().await;
    let dal = _c.dal.clone();
    let outbox: Arc<dyn RegistrySyncOutbox> = Arc::new(PgRegistrySyncRepo::new(dal.clone()));
    create_and_publish(&dal, &outbox).await;

    let never = operator_verified_at(&dal, None).await;
    let (port, calls) = mock(Outcome::Accepted);
    drain_once(&outbox, &port, Some(&never), 50).await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
