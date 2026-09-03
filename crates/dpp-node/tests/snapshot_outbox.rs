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
use base64::Engine;
use chrono::Utc;

use dpp_dal::in_memory_repo::InMemoryPassportRepo;
use dpp_domain::{
    DppError,
    credential::{PassportCredential, PassportCredentialSubject, SignedCredential},
    passport::{ManufacturerInfo, Passport, PassportId},
    ports::identity::IdentityPort,
    ports::passport_repo::PassportRepository,
    product_group::ProductGroup,
    status::PassportStatus,
};
use dpp_types::snapshot::{
    SnapshotMeta, SnapshotOutbox, SnapshotOutboxCounts, SnapshotReconcileRow, SnapshotStore,
};

use dpp_node::infra::drain::{
    SNAPSHOT_REFRESH_INTERVAL, SNAPSHOT_REFRESH_SCAN_INTERVAL, SNAPSHOT_VALIDITY,
};
use dpp_node::infra::snapshot_drain::{MAX_ATTEMPTS, drain_once};

// ---------------------------------------------------------------------------
// In-memory ports
// ---------------------------------------------------------------------------

/// Object store double. Optionally fails every write, to drive the retry path.
#[derive(Default, Clone)]
struct InMemorySnapshotStore {
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    html: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    meta: Arc<Mutex<HashMap<String, SnapshotMeta>>>,
    fail: Arc<Mutex<bool>>,
}

#[async_trait]
impl SnapshotStore for InMemorySnapshotStore {
    async fn put_public_json(
        &self,
        dpp_id: &str,
        bytes: &[u8],
        meta: SnapshotMeta,
    ) -> Result<(), DppError> {
        if *self.fail.lock().unwrap() {
            return Err(DppError::Internal("object store unavailable".into()));
        }
        self.objects
            .lock()
            .unwrap()
            .insert(dpp_id.to_owned(), bytes.to_vec());
        self.meta.lock().unwrap().insert(dpp_id.to_owned(), meta);
        Ok(())
    }
    async fn put_public_html(
        &self,
        dpp_id: &str,
        bytes: &[u8],
        _meta: SnapshotMeta,
    ) -> Result<(), DppError> {
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
        self.meta.lock().unwrap().remove(dpp_id);
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
    fn get_meta(&self, dpp_id: &str) -> Option<SnapshotMeta> {
        self.meta.lock().unwrap().get(dpp_id).copied()
    }
    fn set_failing(&self, failing: bool) {
        *self.fail.lock().unwrap() = failing;
    }
}

/// Metadata for a snapshot a test plants directly, standing in for one an
/// earlier drain pass would have written.
fn planted_meta() -> SnapshotMeta {
    let as_of = Utc::now();
    SnapshotMeta {
        as_of,
        valid_until: as_of + chrono::Duration::days(7),
        max_age: std::time::Duration::from_secs(24 * 3600),
    }
}

/// Signing double for the drain: a real Ed25519 key signing over RFC 8785
/// canonical bytes, exactly as the identity service does, so the snapshot proof
/// these tests read is a genuine one.
struct StubSigner {
    key: ed25519_dalek::SigningKey,
}

impl StubSigner {
    fn new() -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]),
        }
    }
    fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_bytes())
    }
}

#[async_trait]
impl IdentityPort for StubSigner {
    async fn sign_passport(
        &self,
        passport_id: PassportId,
        payload: &serde_json::Value,
    ) -> Result<SignedCredential, DppError> {
        use ed25519_dalek::Signer as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let canonical =
            dpp_crypto::jws::canonicalize(payload).map_err(|e| DppError::Signing(e.to_string()))?;
        let signing_input = format!(
            "{}.{}",
            b64.encode(br#"{"alg":"EdDSA"}"#),
            b64.encode(&canonical)
        );
        let sig = self.key.sign(signing_input.as_bytes());
        Ok(SignedCredential {
            credential: PassportCredential::new(
                "did:web:example".to_owned(),
                PassportCredentialSubject {
                    id: format!("urn:uuid:{passport_id}"),
                    payload_hash: String::new(),
                },
            ),
            jws: format!("{signing_input}.{}", b64.encode(sig.to_bytes())),
            issuer_did: "did:web:example".to_owned(),
        })
    }
    async fn verify_signature(
        &self,
        _jws: &str,
        _payload: &serde_json::Value,
    ) -> Result<bool, DppError> {
        unimplemented!("the drain only signs")
    }
    async fn own_did_document(&self) -> Result<serde_json::Value, DppError> {
        unimplemented!("the drain only signs")
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
    async fn enqueue_stale(
        &self,
        _older_than: chrono::Duration,
        _limit: i64,
    ) -> Result<u64, DppError> {
        // Likewise a query. What the drain does with a refreshed row is the
        // subject of `a_refresh_of_a_withdrawn_passport_retires_it_instead`,
        // which queues the row directly.
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

/// A compact JWS whose payload segment decodes to `{"id": ..., "productName": ...}`
/// — the minimal shape `dpp_vault::public_view::signed_public_view` needs to
/// decode and bind to the row it was read from. Header and signature are
/// placeholders: the drain only decodes this payload, it does not verify it.
fn signed_view_jws(id: PassportId, product_name: &str) -> String {
    let payload = serde_json::json!({ "id": id.to_string(), "productName": product_name });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    format!("aGVhZGVy.{b64}.c2ln")
}

fn passport(status: PassportStatus) -> Passport {
    let id = PassportId::new();
    let product_name = "Drain Test Widget";
    Passport {
        id,
        batch_id: None,
        product_name: product_name.into(),
        product_group: ProductGroup::Textile,
        applicable_instruments: Vec::new(),
        granularity: None,
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
        product_group_data: None,
        status,
        qr_code_url: None,
        jws_signature: Some("full.jws.signature".into()),
        public_jws_signature: Some(signed_view_jws(id, product_name)),
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        placed_on_market_date: None,
        schema_version: "1.0.0".into(),
        retention_locked: true,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    }
}

type Ports = (
    Arc<dyn SnapshotOutbox>,
    Arc<dyn PassportRepository>,
    Arc<dyn SnapshotStore>,
    Arc<dyn IdentityPort>,
);

fn ports(outbox: &FakeOutbox, repo: &InMemoryPassportRepo, store: &InMemorySnapshotStore) -> Ports {
    (
        Arc::new(outbox.clone()),
        Arc::new(repo.clone()),
        Arc::new(store.clone()),
        Arc::new(StubSigner::new()),
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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.stored, 1);
    assert_eq!(stats.removed, 0);
    let bytes = store
        .get(&p.id.to_string())
        .expect("a published passport must be mirrored");

    // What lands is the public view: it carries the public JWS and never the
    // confidential full-view one.
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["productName"], "Drain Test Widget");
    assert_eq!(
        v["publicJwsSignature"],
        p.public_jws_signature.clone().unwrap()
    );
    assert!(v.get("jwsSignature").is_none(), "full-view JWS leaked: {v}");
}

/// What reaches object storage has to state how long it stands, under a
/// signature, or a copy of it is indistinguishable from a live answer forever.
///
/// Asserted end to end rather than only at the renderer because the two halves
/// can disagree independently: the payload could carry a bound the object
/// metadata contradicts, and a reader who trusts the wrong one is misled by
/// exactly the mechanism meant to stop that.
#[tokio::test]
async fn a_stored_snapshot_states_and_signs_how_long_it_stands() {
    let (outbox, repo, store) = (
        FakeOutbox::default(),
        InMemoryPassportRepo::default(),
        InMemorySnapshotStore::default(),
    );
    let p = passport(PassportStatus::Published);
    repo.create(p.clone()).await.unwrap();
    outbox.enqueue(p.id).await.unwrap();

    let signer = StubSigner::new();
    let (o, r, s, i) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

    let bytes = store.get(&p.id.to_string()).expect("mirrored");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let as_of: chrono::DateTime<Utc> = v["asOf"].as_str().expect("asOf").parse().unwrap();
    let valid_until: chrono::DateTime<Utc> = v["validUntil"]
        .as_str()
        .expect("validUntil")
        .parse()
        .unwrap();
    assert_eq!(
        valid_until - as_of,
        chrono::Duration::from_std(SNAPSHOT_VALIDITY).unwrap(),
        "the window written into the payload is not the one the node promises"
    );

    let proof = v["snapshotJwsSignature"].as_str().expect("proof");
    assert!(
        dpp_crypto::jws::verify_jws(proof, &signer.public_key_b64()).unwrap(),
        "the bound is not signed, so anyone holding a copy could extend it"
    );

    // The unsigned echo on the object must agree with the signed claim inside
    // it, and must expire at the refresh cadence rather than the validity one —
    // a cache allowed to hold this for the full window would serve a copy the
    // node has already replaced, including one replaced by a deletion.
    let meta = store.get_meta(&p.id.to_string()).expect("meta recorded");
    assert_eq!(meta.as_of, as_of);
    assert_eq!(meta.valid_until, valid_until);
    assert_eq!(meta.max_age, SNAPSHOT_REFRESH_INTERVAL);
}

/// The margin between the two constants is what keeps a *live* passport from
/// expiring, so it is pinned rather than left to be adjusted by whoever next
/// tunes a loop.
///
/// Bring them close together and one bad day — a signing outage, a database
/// wedged for hours, an object store refusing writes — silently ends continuity
/// for every passport in the deployment at once.
#[test]
fn the_validity_window_survives_several_failed_refreshes() {
    assert!(
        SNAPSHOT_VALIDITY >= SNAPSHOT_REFRESH_INTERVAL * 4,
        "validity must outlast several consecutive refresh failures"
    );
    assert!(
        SNAPSHOT_REFRESH_SCAN_INTERVAL < SNAPSHOT_REFRESH_INTERVAL,
        "scanning less often than snapshots go stale renews nothing on time"
    );
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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

    let html = store
        .get_html(&p.id.to_string())
        .expect("a published passport must be mirrored as a page too");

    assert!(html.starts_with("<!DOCTYPE html>"), "not an HTML document");
    assert!(html.contains("Drain Test Widget"), "product name missing");

    // The banner is the honesty requirement: a saved copy must say it is a
    // saved copy, on the page, where a consumer will actually see it — and say
    // when it stops standing, since the page is written once and can never
    // notice its own lapse.
    assert!(
        html.contains("saved copy"),
        "a snapshot page must disclose that it is stale: {html}"
    );
    let expiry = (Utc::now() + chrono::Duration::from_std(SNAPSHOT_VALIDITY).unwrap())
        .format("%Y-%m-%d")
        .to_string();
    assert!(
        html.contains(&expiry),
        "a snapshot page must name the date it stops being reliable: {html}"
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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;
    assert!(store.get_html(&p.id.to_string()).is_some());

    repo.update_status(p.id, PassportStatus::Suspended)
        .await
        .unwrap();
    outbox.push_row(p.id, 0);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

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
            .put_public_json(
                &p.id.to_string(),
                b"{\"status\":\"published\"}",
                planted_meta(),
            )
            .await
            .unwrap();
        outbox.enqueue(p.id).await.unwrap();

        let (o, r, s, i) = ports(&outbox, &repo, &store);
        let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

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
    let (o, r, s, i) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;
    assert!(store.get(&p.id.to_string()).is_some());

    // The passport is suspended. Queue a row that predates the suspension (the
    // out-of-order / retried case).
    repo.update_status(p.id, PassportStatus::Suspended)
        .await
        .unwrap();
    outbox.push_row(p.id, 0);

    let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;
    let first = store.get(&p.id.to_string()).expect("mirrored");

    outbox.push_row(p.id, 0);
    drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;
    let second = store.get(&p.id.to_string()).expect("still mirrored");

    assert_eq!(
        without_freshness(&first),
        without_freshness(&second),
        "a replayed reconcile must converge on the same content"
    );
}

/// A snapshot minus the two fields that say *when it was taken*.
///
/// The drain stamps `as_of` from the wall clock, truncated to the second
/// (`snapshot_drain.rs`), and derives `valid_until` from it. Comparing whole
/// snapshots therefore asserted that two drains happen within the same second —
/// true in microseconds locally, and false often enough on a loaded CI runner to
/// fail this test with "a replayed reconcile must be byte-identical".
///
/// That was the assertion being too strong, not the code being wrong: a
/// freshness marker is *supposed* to move. Convergence is a claim about the
/// content, so the content is what this compares.
///
/// `snapshotJwsSignature` goes with them, and dropping the timestamps without it
/// would fix nothing: the outer proof is taken over the whole document *except
/// itself*, so it covers `asOf` and moves whenever `asOf` moves. What remains is
/// the passport content and `publicJwsSignature`, the inner proof that is frozen
/// at publish — which is exactly the pair a replay must not disturb.
fn without_freshness(snapshot: &[u8]) -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_slice(snapshot).expect("a snapshot is JSON");
    if let Some(o) = v.as_object_mut() {
        o.remove("asOf");
        o.remove("validUntil");
        o.remove("snapshotJwsSignature");
    }
    v
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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.retried, 1);
    assert_eq!(stats.stored, 0);
    assert_eq!(outbox.failed.lock().unwrap().len(), 1);
    // Still pending, so the next cycle retries — nothing is lost.
    assert_eq!(outbox.rows.lock().unwrap().len(), 1);

    // Once storage recovers, the same row converges.
    store.set_failing(false);
    let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;
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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

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

    let (o, r, s, i) = ports(&outbox, &repo, &store);
    let stats = drain_once(&o, &r, &s, &i, TEST_RESOLVER_BASE, 50).await;

    assert_eq!(stats.removed, 1, "the absent passport is retired");
    assert_eq!(stats.stored, 1, "the good row still drained");
    assert!(store.get(&good.id.to_string()).is_some());
}

#[test]
fn the_drain_interval_is_the_suspend_lag_sla() {
    // The static tier's integrity guarantee is bounded by how often the drain
    // runs: a passport that leaves the public tier stops being served within one
    // cycle. That makes this the suspend lag an operator is owed a number for,
    // so it is pinned against the real constant the loop uses rather than left
    // to drift with whoever last tuned a loop.
    assert_eq!(
        dpp_node::infra::drain::DRAIN_INTERVAL.as_secs(),
        30,
        "this is the suspend lag operators are quoted — move the statement of it with the constant"
    );
}
