//! Continuity-tier hooks: every change to a passport's public state queues a
//! reconcile. Drives the real `PassportService` lifecycle with in-memory ports
//! and real Ed25519 signing — no Docker.
//!
//! Scope note: the service's whole continuity responsibility is *enqueue*. It
//! deliberately never touches object storage — deciding put-vs-remove and
//! driving the store belongs to the node's drain, which converges on the
//! passport's current status (see `dpp-node/tests/snapshot_outbox.rs`). So these
//! tests assert only that each lifecycle transition records a reconcile for the
//! right passport. The byte-identical render + JWS-travels contract is
//! unit-tested in `service::mod`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;

use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync,
    compliance::passthrough_registry::PassthroughRegistry,
    domain::{
        eol::{DeactivationReason, EolEvent},
        passport::{FacilitySnapshot, ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
    },
    ports::passport_repo::PassportRepository,
};
use dpp_types::{
    api_key::ApiKeyScope,
    audit::{AuditEntry, AuditRepository, GENESIS_PREV_HASH},
    auth::AuthContext,
    snapshot::{SnapshotOutbox, SnapshotOutboxCounts, SnapshotReconcileRow},
};
use dpp_vault::domain::service::PassportService;

// ---------------------------------------------------------------------------
// In-memory ports (no Docker/Postgres) — the two the lifecycle actually needs.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InMemoryPassportRepo {
    store: Mutex<HashMap<PassportId, Passport>>,
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

/// Chains entries exactly as `PgAuditRepo` does, so the lifecycle's audit
/// appends succeed.
#[derive(Default)]
struct InMemoryAuditRepo {
    entries: Mutex<Vec<AuditEntry>>,
}

#[async_trait]
impl AuditRepository for InMemoryAuditRepo {
    async fn append(&self, entry: AuditEntry) -> Result<(), DppError> {
        let mut entries = self.entries.lock().unwrap();
        let prev_hash = entries
            .iter()
            .rev()
            .find(|e| e.passport_id == entry.passport_id)
            .and_then(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_owned());
        let mut entry = entry;
        entry.entry_hash = Some(entry.chain_hash(&prev_hash));
        entry.prev_hash = Some(prev_hash);
        entries.push(entry);
        Ok(())
    }
    async fn list_by_passport(&self, passport_id: &str) -> Result<Vec<AuditEntry>, DppError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.passport_id == passport_id)
            .cloned()
            .collect())
    }
}

/// In-memory reconcile outbox — records every enqueue in order so a test can
/// assert which passports the lifecycle queued. Models the Postgres upsert: one
/// row per passport, re-armed rather than duplicated. Cloneable; clones share state.
#[derive(Default, Clone)]
struct InMemorySnapshotOutbox {
    /// Every enqueue call, in order (including repeats — the point of the
    /// idempotence assertion is that the *queue* dedupes, not the call log).
    calls: Arc<Mutex<Vec<PassportId>>>,
}

#[async_trait]
impl SnapshotOutbox for InMemorySnapshotOutbox {
    async fn enqueue(&self, passport_id: PassportId) -> Result<(), DppError> {
        self.calls.lock().unwrap().push(passport_id);
        Ok(())
    }
    async fn due(&self, _limit: i64) -> Result<Vec<SnapshotReconcileRow>, DppError> {
        // The upsert collapses repeats to one pending row per passport.
        let calls = self.calls.lock().unwrap();
        let mut seen = Vec::new();
        for id in calls.iter() {
            if !seen.contains(id) {
                seen.push(*id);
            }
        }
        Ok(seen
            .into_iter()
            .map(|passport_id| SnapshotReconcileRow {
                id: uuid::Uuid::now_v7(),
                passport_id,
                attempts: 0,
            })
            .collect())
    }
    async fn mark_reconciled(&self, _id: uuid::Uuid) -> Result<(), DppError> {
        Ok(())
    }
    async fn mark_attempt_failed(&self, _id: uuid::Uuid, _m: String) -> Result<(), DppError> {
        Ok(())
    }
    async fn mark_exhausted(&self, _id: uuid::Uuid, _m: String) -> Result<(), DppError> {
        Ok(())
    }
    async fn status_counts(&self) -> Result<SnapshotOutboxCounts, DppError> {
        Ok(SnapshotOutboxCounts::default())
    }
}

impl InMemorySnapshotOutbox {
    /// How many times `passport_id` was queued for reconcile.
    fn enqueue_count(&self, passport_id: PassportId) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|id| **id == passport_id)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn auth() -> AuthContext {
    AuthContext {
        user_id: "snapshot-test".into(),
        scope: ApiKeyScope::Admin,
        key_id: None,
    }
}

/// A `PassportService` with real signing + in-memory ports + the reconcile outbox.
async fn build_service() -> (PassportService, InMemorySnapshotOutbox) {
    let key_path =
        std::env::temp_dir().join(format!("snapshot-test-{}.json", uuid::Uuid::new_v4()));
    let store =
        dpp_crypto::keystore::KeyStore::open(&key_path, "test-pass").expect("open keystore");
    store.generate_key("root").expect("generate key");
    let identity = Arc::new(dpp_crypto::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        "snapshot-test.example.com".to_owned(),
    ));

    let snapshots = InMemorySnapshotOutbox::default();
    let service = PassportService::new(
        Arc::new(InMemoryPassportRepo::default()),
        identity,
        Arc::new(PassthroughRegistry::new()),
        Arc::new(InMemoryAuditRepo::default()),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        "DE".to_owned(),
    )
    .with_snapshot_outbox(Arc::new(snapshots.clone()));
    (service, snapshots)
}

fn draft_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Continuity Snapshot Widget".into(),
        sector: Sector::Textile,
        product_category: None,
        manufacturer: ManufacturerInfo {
            name: "Snapshot Test GmbH".into(),
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
        schema_version: "1.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        // Set directly (no registry reader in this harness) so the Annex III /
        // Art. 13 completeness gate at publish is satisfied.
        operator_identifier: Some("did:web:snapshot-test.example.com".into()),
        facility: Some(FacilitySnapshot {
            scheme: "gln".into(),
            value: "1234567890128".into(),
            name: "Test Facility".into(),
            country: "DE".into(),
            address: None,
        }),
        seal: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_enqueues_a_reconcile() {
    let (service, outbox) = build_service().await;
    let auth = auth();

    let created = service
        .create(draft_passport(), &auth)
        .await
        .expect("create");
    // A draft is not public — nothing to reconcile yet.
    assert_eq!(
        outbox.enqueue_count(created.id),
        0,
        "creating a draft must not queue a reconcile"
    );

    let published = service.publish(created.id, &auth).await.expect("publish");
    assert_eq!(
        outbox.enqueue_count(published.id),
        1,
        "publish must queue exactly one reconcile"
    );
}

#[tokio::test]
async fn suspend_enqueues_a_reconcile() {
    let (service, outbox) = build_service().await;
    let auth = auth();

    let created = service
        .create(draft_passport(), &auth)
        .await
        .expect("create");
    let published = service.publish(created.id, &auth).await.expect("publish");

    service
        .suspend(published.id, &auth, None)
        .await
        .expect("suspend");

    // Publish queued one, suspend queues the second: the static tier must be
    // told the passport left the public tier, or it keeps serving `active`.
    assert_eq!(
        outbox.enqueue_count(published.id),
        2,
        "suspend must queue a reconcile"
    );
}

#[tokio::test]
async fn declaring_end_of_life_enqueues_a_reconcile() {
    let (service, outbox) = build_service().await;
    let auth = auth();

    let created = service
        .create(draft_passport(), &auth)
        .await
        .expect("create");
    let published = service.publish(created.id, &auth).await.expect("publish");

    let eol = EolEvent::new(
        published.id,
        DeactivationReason::Recycled,
        "did:web:snapshot-test.example.com",
    );
    service
        .declare_eol(published.id, eol, &auth)
        .await
        .expect("declare eol");

    // The live public read serves only `Published`, so a deactivated passport
    // must not keep answering `published` from the static tier under a still
    // valid signature.
    assert_eq!(
        outbox.enqueue_count(published.id),
        2,
        "end-of-life must queue a reconcile"
    );
}

#[tokio::test]
async fn repeated_state_changes_collapse_to_one_pending_reconcile() {
    let (service, outbox) = build_service().await;
    let auth = auth();

    let created = service
        .create(draft_passport(), &auth)
        .await
        .expect("create");
    let published = service.publish(created.id, &auth).await.expect("publish");
    service
        .suspend(published.id, &auth, None)
        .await
        .expect("suspend");

    // Two lifecycle transitions, two enqueue calls...
    assert_eq!(outbox.enqueue_count(published.id), 2);

    // ...but one pending row: a reconcile names a passport, not an action, so a
    // second change while one is still queued is subsumed by it rather than
    // stacking a duplicate. This is what the `passport_id UNIQUE` upsert buys.
    let due = outbox.due(50).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "repeat changes to one passport must collapse to a single pending reconcile"
    );
    assert_eq!(due[0].passport_id, published.id);
}
