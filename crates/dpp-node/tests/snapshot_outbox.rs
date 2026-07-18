//! Continuity-tier drain: convergence semantics of the snapshot reconcile pass.
//!
//! In-memory ports throughout — no Docker, no S3. The point of these tests is
//! not "does S3 work" (the MinIO tier covers the adapter) but "does the drain
//! always leave object storage agreeing with the database", including when rows
//! are stale, replayed, or arrive out of order.
//!
//! The load-bearing test is
//! `a_stale_reconcile_never_resurrects_a_suspended_passport` — it is the reason
//! a queued row names a passport instead of carrying a put/remove action.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;

use dpp_domain::{
    DppError,
    domain::{
        passport::{ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
    },
    ports::passport_repo::PassportRepository,
};
use dpp_types::snapshot::{
    SnapshotOutbox, SnapshotOutboxCounts, SnapshotReconcileRow, SnapshotStore,
};

use dpp_node::infra::snapshot_drain::{MAX_ATTEMPTS, drain_once};

// ---------------------------------------------------------------------------
// In-memory ports
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct InMemoryPassportRepo {
    store: Arc<Mutex<HashMap<PassportId, Passport>>>,
}

#[async_trait]
impl PassportRepository for InMemoryPassportRepo {
    async fn create(&self, passport: Passport) -> Result<Passport, DppError> {
        self.store
            .lock()
            .unwrap()
            .insert(passport.id, passport.clone());
        Ok(passport)
    }
    async fn find_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        Ok(self.store.lock().unwrap().get(&id).cloned())
    }
    async fn find_published_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.find_by_id(id).await
    }
    async fn find_published_by_gtin(&self, _gtin: &str) -> Result<Option<Passport>, DppError> {
        Ok(None)
    }
    async fn find_by_id_any_status(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.find_by_id(id).await
    }
    async fn update(&self, passport: Passport) -> Result<Passport, DppError> {
        self.store
            .lock()
            .unwrap()
            .insert(passport.id, passport.clone());
        Ok(passport)
    }
    async fn update_status(
        &self,
        id: PassportId,
        status: PassportStatus,
    ) -> Result<Passport, DppError> {
        let mut g = self.store.lock().unwrap();
        let mut p = g
            .get(&id)
            .cloned()
            .ok_or_else(|| DppError::NotFound(id.to_string()))?;
        p.status = status;
        g.insert(id, p.clone());
        Ok(p)
    }
    async fn list(
        &self,
        _status: Option<PassportStatus>,
        _q: Option<&str>,
        _facility_id: Option<&str>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        Ok(self.store.lock().unwrap().values().cloned().collect())
    }
    async fn count(
        &self,
        _status: Option<PassportStatus>,
        _facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        Ok(self.store.lock().unwrap().len() as u64)
    }
}

/// Object store double. Optionally fails every write, to drive the retry path.
#[derive(Default, Clone)]
struct InMemorySnapshotStore {
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    html: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    fail: Arc<Mutex<bool>>,
}

#[async_trait]
impl SnapshotStore for InMemorySnapshotStore {
    async fn put_public_json(&self, dpp_id: &str, bytes: &[u8]) -> Result<(), DppError> {
        if *self.fail.lock().unwrap() {
            return Err(DppError::Internal("object store unavailable".into()));
        }
        self.objects
            .lock()
            .unwrap()
            .insert(dpp_id.to_owned(), bytes.to_vec());
        Ok(())
    }
    async fn put_public_html(&self, dpp_id: &str, bytes: &[u8]) -> Result<(), DppError> {
        if *self.fail.lock().unwrap() {
            return Err(DppError::Internal("object store unavailable".into()));
        }
        self.html
            .lock()
            .unwrap()
            .insert(dpp_id.to_owned(), bytes.to_vec());
        Ok(())
    }
    async fn remove(&self, dpp_id: &str) -> Result<(), DppError> {
        if *self.fail.lock().unwrap() {
            return Err(DppError::Internal("object store unavailable".into()));
        }
        self.objects.lock().unwrap().remove(dpp_id);
        self.html.lock().unwrap().remove(dpp_id);
        Ok(())
    }
}

impl InMemorySnapshotStore {
    fn get(&self, dpp_id: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(dpp_id).cloned()
    }
    fn get_html(&self, dpp_id: &str) -> Option<String> {
        self.html
            .lock()
            .unwrap()
            .get(dpp_id)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }
    fn set_failing(&self, failing: bool) {
        *self.fail.lock().unwrap() = failing;
    }
}

/// Reconcile-outbox double: an explicit queue a test can load with exactly the
/// rows it wants (including deliberately stale ones), plus the terminal-state
/// tallies so retry/exhaust transitions can be asserted.
#[derive(Default, Clone)]
struct FakeOutbox {
    rows: Arc<Mutex<Vec<SnapshotReconcileRow>>>,
    reconciled: Arc<Mutex<Vec<uuid::Uuid>>>,
    failed: Arc<Mutex<Vec<(uuid::Uuid, String)>>>,
    exhausted: Arc<Mutex<Vec<(uuid::Uuid, String)>>>,
}

#[async_trait]
impl SnapshotOutbox for FakeOutbox {
    async fn enqueue(&self, passport_id: PassportId) -> Result<(), DppError> {
        self.rows.lock().unwrap().push(SnapshotReconcileRow {
            id: uuid::Uuid::now_v7(),
            passport_id,
            attempts: 0,
        });
        Ok(())
    }
    async fn due(&self, limit: i64) -> Result<Vec<SnapshotReconcileRow>, DppError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows.iter().take(limit as usize).cloned().collect())
    }
    async fn enqueue_divergent(&self, _limit: i64) -> Result<u64, DppError> {
        // The repair sweep is a database-level query; these tests drive the
        // drain, which cannot tell a swept row from a lifecycle-queued one. Its
        // semantics are pinned against real Postgres in `dpp-dal`.
        Ok(0)
    }
    async fn mark_reconciled(&self, id: uuid::Uuid) -> Result<(), DppError> {
        self.reconciled.lock().unwrap().push(id);
        self.rows.lock().unwrap().retain(|r| r.id != id);
        Ok(())
    }
    async fn mark_attempt_failed(&self, id: uuid::Uuid, message: String) -> Result<(), DppError> {
        self.failed.lock().unwrap().push((id, message));
        // Mirror the SQL: attempts increments, row stays pending.
        if let Some(r) = self.rows.lock().unwrap().iter_mut().find(|r| r.id == id) {
            r.attempts += 1;
        }
        Ok(())
    }
    async fn mark_exhausted(&self, id: uuid::Uuid, message: String) -> Result<(), DppError> {
        self.exhausted.lock().unwrap().push((id, message));
        self.rows.lock().unwrap().retain(|r| r.id != id);
        Ok(())
    }
    async fn status_counts(&self) -> Result<SnapshotOutboxCounts, DppError> {
        Ok(SnapshotOutboxCounts {
            pending: self.rows.lock().unwrap().len() as i64,
            reconciled: self.reconciled.lock().unwrap().len() as i64,
            exhausted: self.exhausted.lock().unwrap().len() as i64,
        })
    }
}

impl FakeOutbox {
    /// Queue a row directly, bypassing `enqueue`, so a test can construct a row
    /// that is already stale relative to the passport's current status.
    fn push_row(&self, passport_id: PassportId, attempts: i32) -> uuid::Uuid {
        let id = uuid::Uuid::now_v7();
        self.rows.lock().unwrap().push(SnapshotReconcileRow {
            id,
            passport_id,
            attempts,
        });
        id
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Resolver base the snapshot page's links and QR carrier are built against.
const TEST_RESOLVER_BASE: &str = "https://dpp.example.test";

fn passport(status: PassportStatus) -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Drain Test Widget".into(),
        sector: Sector::Textile,
        product_category: None,
        manufacturer: ManufacturerInfo {
            name: "Drain Test GmbH".into(),
            address: "Berlin, DE".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        sector_data: None,
        status,
        qr_code_url: None,
        jws_signature: Some("full.jws.signature".into()),
        public_jws_signature: Some("public.jws.signature".into()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        schema_version: "1.0.0".into(),
        retention_locked: true,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    }
}

type Ports = (
    Arc<dyn SnapshotOutbox>,
    Arc<dyn PassportRepository>,
    Arc<dyn SnapshotStore>,
);

fn ports(outbox: &FakeOutbox, repo: &InMemoryPassportRepo, store: &InMemorySnapshotStore) -> Ports {
    (
        Arc::new(outbox.clone()),
        Arc::new(repo.clone()),
        Arc::new(store.clone()),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn drain_mirrors_a_published_passport() {
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();

    let (o, r, s) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.stored, 1);
    assert_eq!(stats.removed, 0);
    let bytes = store
        .get(&p.id.to_string())
        .expect("a published passport must be mirrored");

    // What lands is the public view: it carries the public JWS and never the
    // confidential full-view one.
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["productName"], "Drain Test Widget");
    assert_eq!(v["publicJwsSignature"], "public.jws.signature");
    assert!(v.get("jwsSignature").is_none(), "full-view JWS leaked: {v}");
}

#[tokio::test]
async fn drain_stores_a_readable_page_beside_the_signed_json() {
    // The JSON is what a verifier checks; the page is what the person who
    // scanned the QR code actually reads. Serving only JSON would leave the
    // passport technically reachable and practically useless.
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let mut p = passport(PassportStatus::Published);
    // `batchId` is Professional tier, and the page template renders it. That
    // makes it the honest probe for "was this rendered from the public view or
    // from the full passport?" — unlike the JWS fields, which the template
    // never emits and which therefore cannot detect the mistake.
    p.batch_id = Some("LOT-CONFIDENTIAL-42".into());
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();

    let (o, r, s) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    let html = store
        .get_html(&p.id.to_string())
        .expect("a published passport must be mirrored as a page too");

    assert!(html.starts_with("<!DOCTYPE html>"), "not an HTML document");
    assert!(html.contains("Drain Test Widget"), "product name missing");

    // The banner is the honesty requirement: a saved copy must say it is a
    // saved copy, on the page, where a consumer will actually see it.
    assert!(
        html.contains("saved copy"),
        "a snapshot page must disclose that it is stale: {html}"
    );

    // The page must be rendered from the redacted public view, never the full
    // passport — otherwise the static tier becomes a disclosure hole precisely
    // because it renders HTML.
    assert!(
        !html.contains("LOT-CONFIDENTIAL-42"),
        "a non-public field leaked into the snapshot page: {html}"
    );
}

#[tokio::test]
async fn retiring_a_snapshot_removes_the_page_too() {
    // A retired passport that left its page behind would keep answering
    // `published` to every human reader while the JSON was already gone.
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();

    let (o, r, s) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;
    assert!(store.get_html(&p.id.to_string()).is_some());

    repo.update_status(p.id, PassportStatus::Suspended)
        .await
        .unwrap();
    outbox.push_row(p.id, 0);
    drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    assert!(
        store.get(&p.id.to_string()).is_none(),
        "the signed JSON must be retired"
    );
    assert!(
        store.get_html(&p.id.to_string()).is_none(),
        "the readable page must be retired with it"
    );
}

#[tokio::test]
async fn drain_retires_a_passport_that_left_the_public_tier() {
    for status in [
        PassportStatus::Suspended,
        PassportStatus::Archived,
        PassportStatus::Deactivated,
        PassportStatus::Draft,
    ] {
        let (outbox, repo, store) = (
            FakeOutbox::default(),
            InMemoryPassportRepo::default(),
            InMemorySnapshotStore::default(),
        );
        let p = passport(status.clone());
        repo.create(p.clone()).await.unwrap();
        // Pretend a snapshot is already live from an earlier publish.
        store
            .put_public_json(&p.id.to_string(), b"{\"status\":\"published\"}")
            .await
            .unwrap();
        outbox.enqueue(p.id).await.unwrap();

        let (o, r, s) = ports(&outbox, &repo, &store);
        let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

        assert_eq!(stats.removed, 1, "{status:?} must retire the snapshot");
        assert!(
            store.get(&p.id.to_string()).is_none(),
            "{status:?} must not keep being served from the static tier"
        );
    }
}

#[tokio::test]
async fn a_stale_reconcile_never_resurrects_a_suspended_passport() {
    // This is the whole argument for a row naming a passport rather than an
    // action. Sequence: the passport is published and a reconcile is queued; the
    // passport is then suspended. The queued row is now *stale* — under a
    // put/remove design it would still say "put", and draining it would
    // re-publish a suspended passport to the public tier under a valid
    // signature. Deriving the action from current status makes that impossible.
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );

    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();

    // First pass mirrors it — the passport really is public at this point.
    let (o, r, s) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;
    assert!(store.get(&p.id.to_string()).is_some());

    // The passport is suspended. Queue a row that predates the suspension (the
    // out-of-order / retried case).
    repo.update_status(p.id, PassportStatus::Suspended)
        .await
        .unwrap();
    outbox.push_row(p.id, 0);

    let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.stored, 0, "a stale row must never store");
    assert_eq!(stats.removed, 1);
    assert!(
        store.get(&p.id.to_string()).is_none(),
        "a suspended passport must never be resurrected in the public tier"
    );
}

#[tokio::test]
async fn draining_the_same_row_twice_is_a_no_op() {
    // Convergence means replay-safety: re-running a reconcile against unchanged
    // state must land in the same place, so a crash mid-pass costs nothing.
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();

    let (o, r, s) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;
    let first = store.get(&p.id.to_string()).expect("mirrored");

    outbox.push_row(p.id, 0);
    drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;
    let second = store.get(&p.id.to_string()).expect("still mirrored");

    assert_eq!(first, second, "a replayed reconcile must be byte-identical");
}

#[tokio::test]
async fn a_failing_store_backs_off_and_leaves_the_row_pending() {
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();
    store.set_failing(true);

    let (o, r, s) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.retried, 1);
    assert_eq!(stats.stored, 0);
    assert_eq!(outbox.failed.lock().unwrap().len(), 1);
    // Still pending, so the next cycle retries — nothing is lost.
    assert_eq!(outbox.rows.lock().unwrap().len(), 1);

    // Once storage recovers, the same row converges.
    store.set_failing(false);
    let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;
    assert_eq!(stats.stored, 1);
    assert!(store.get(&p.id.to_string()).is_some());
}

#[tokio::test]
async fn a_row_at_the_attempt_cap_is_exhausted_not_retried_forever() {
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    // One attempt short of the cap: this pass pushes it over.
    outbox.push_row(p.id, MAX_ATTEMPTS - 1);
    store.set_failing(true);

    let (o, r, s) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.exhausted, 1);
    assert_eq!(stats.retried, 0);
    assert_eq!(outbox.rows.lock().unwrap().len(), 0, "no longer pending");
}

#[tokio::test]
async fn one_bad_row_does_not_stall_the_rest_of_the_pass() {
    // A missing passport is the per-row failure case; the pass must continue.
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let good = passport(PassportStatus::Published);
    repo.create(good.clone()).await.unwrap();

    // A reconcile for a passport that no longer exists: the drain treats "not
    // Published" as "must not be served", so it retires rather than erroring.
    outbox.push_row(PassportId::new(), 0);
    outbox.enqueue(good.id).await.unwrap();

    let (o, r, s) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.removed, 1, "the absent passport is retired");
    assert_eq!(stats.stored, 1, "the good row still drained");
    assert!(store.get(&good.id.to_string()).is_some());
}

#[test]
fn the_drain_interval_is_the_suspend_lag_sla() {
    // The static tier's integrity guarantee is bounded by how often the drain
    // runs: a passport that leaves the public tier stops being served within one
    // cycle. This value is quoted to operators in the contract (04-LEGAL §3.7),
    // so it is pinned against the real constant the loop uses — changing it is a
    // contract change, not a tuning tweak.
    assert_eq!(
        dpp_node::infra::drain::DRAIN_INTERVAL.as_secs(),
        30,
        "suspend lag is stated to operators; update 04-LEGAL §3.7 before changing it"
    );
}
