//! Round-trip: publish -> transfer -> declare EOL -> generate + persist the
//! evidence dossier -> verify it via `PassportService::verify_evidence`.
//!
//! Uses real Ed25519 signing (`dpp_vc::LocalIdentityService`, backed by a
//! throwaway on-disk keystore) and small in-memory port implementations —
//! no Docker, no Postgres. This is deliberately a lighter, faster tier than
//! the `integration-tests` feature's testcontainer-backed suite, chosen
//! because it needs genuinely valid cryptographic signatures (the
//! `integration-tests` tier's `MockIdentity` produces a non-cryptographic
//! fake JWS that would never round-trip through the verifier).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use dpp_dal::in_memory_repo::InMemoryPassportRepo;
use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync, PassthroughRegistry,
    eol::{DeactivationReason, EolEvent},
    passport::{FacilitySnapshot, ManufacturerInfo, Passport, PassportId},
    product_group::ProductGroup,
    status::PassportStatus,
    transfer::{OperatorRole, ResponsibleOperator, TransferChain, TransferReason},
};
use dpp_types::{
    api_key::ApiKeyScope,
    audit::{AuditRepository, GENESIS_PREV_HASH, PassportAuditEntry},
    auth::AuthContext,
    evidence::{
        EvidenceDossierRecord, EvidenceDossierRepository, EvidenceDossierSummary, content_hash,
    },
    transfer::TransferStore,
};
use dpp_vault::domain::service::{OperatorIdentity, PassportService};

// ---------------------------------------------------------------------------
// In-memory ports (no Docker/Postgres — see module doc comment)
// ---------------------------------------------------------------------------

/// Chains entries exactly as `dpp-dal::pg::repo_audit::PgAuditRepo` does —
/// read the current head's `entry_hash` (or genesis), fold it into the new
/// entry's hash, store both. Without this, `verify_audit_chain` would fail
/// on a perfectly legitimate dossier.
#[derive(Default)]
struct InMemoryAuditRepo {
    entries: Mutex<Vec<PassportAuditEntry>>,
}

#[async_trait]
impl AuditRepository for InMemoryAuditRepo {
    async fn append(&self, entry: PassportAuditEntry) -> Result<(), DppError> {
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
    async fn list_by_passport(
        &self,
        passport_id: &str,
    ) -> Result<Vec<PassportAuditEntry>, DppError> {
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

#[derive(Default)]
struct InMemoryTransferStore {
    chains: Mutex<HashMap<PassportId, TransferChain>>,
}

#[async_trait]
impl TransferStore for InMemoryTransferStore {
    async fn get_chain(&self, passport_id: PassportId) -> Result<Option<TransferChain>, DppError> {
        Ok(self.chains.lock().unwrap().get(&passport_id).cloned())
    }
    async fn save_chain(&self, chain: &TransferChain) -> Result<(), DppError> {
        self.chains
            .lock()
            .unwrap()
            .insert(chain.passport_id, chain.clone());
        Ok(())
    }
}

/// In-memory `EvidenceDossierRepository` — append-only in spirit (nothing
/// here exposes an update path), mirroring `PgEvidenceDossierRepo`'s shape.
#[derive(Default)]
struct InMemoryEvidenceRepo {
    records: Mutex<Vec<EvidenceDossierRecord>>,
}

impl InMemoryEvidenceRepo {
    /// Test-only hook: overwrite a stored record in place to simulate a
    /// tampered row (the DB has no such path — this stands in for "what if
    /// storage returned altered bytes").
    fn replace(&self, record: EvidenceDossierRecord) {
        let mut records = self.records.lock().unwrap();
        if let Some(slot) = records.iter_mut().find(|r| r.id == record.id) {
            *slot = record;
        }
    }
}

#[async_trait]
impl EvidenceDossierRepository for InMemoryEvidenceRepo {
    async fn insert(&self, record: &EvidenceDossierRecord) -> Result<(), DppError> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
    async fn list_by_passport(
        &self,
        passport_id: PassportId,
    ) -> Result<Vec<EvidenceDossierSummary>, DppError> {
        let mut summaries: Vec<EvidenceDossierSummary> = self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.passport_id == passport_id)
            .map(|r| EvidenceDossierSummary {
                id: r.id,
                passport_id: r.passport_id,
                actor: r.actor.clone(),
                created_at: r.created_at,
                doc_hash: r.doc_hash.clone(),
            })
            .collect();
        summaries.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        Ok(summaries)
    }
    async fn get(&self, id: Uuid) -> Result<Option<EvidenceDossierRecord>, DppError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn auth() -> AuthContext {
    AuthContext {
        user_id: "evidence-test".into(),
        scope: ApiKeyScope::Admin,
        key_id: None,
    }
}

/// Builds a `PassportService` wired with real Ed25519 signing and in-memory
/// ports, plus the DID the identity's did:web document actually publishes as
/// (pathless form — see `dpp_vc::did_builder`).
async fn build_service() -> (PassportService, Arc<InMemoryEvidenceRepo>, String) {
    // `tempfile` creates the directory with restrictive permissions and removes
    // it on drop; `env::temp_dir()` did neither, leaving an Ed25519 private key
    // behind on every run.
    let key_dir = tempfile::tempdir().expect("temp dir");
    let store =
        dpp_crypto::keystore::KeyStore::open(key_dir.path().join("keystore.json"), "test-pass")
            .expect("open keystore");
    store.generate_key("root").expect("generate key");
    let base_url = "evidence-test.example.com".to_owned();
    let issuer_did = format!("did:web:{}", base_url.replace(':', "%3A"));
    let identity = Arc::new(dpp_vc::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        base_url,
    ));

    let evidence_store = Arc::new(InMemoryEvidenceRepo::default());

    let service = PassportService::new(
        Arc::new(InMemoryPassportRepo::default()),
        identity,
        Arc::new(PassthroughRegistry::new()),
        Arc::new(InMemoryAuditRepo::default()),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostArchive),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "DE".to_owned(),
        },
    )
    .with_transfer_store(Arc::new(InMemoryTransferStore::default()))
    .with_evidence_store(evidence_store.clone());

    (service, evidence_store, issuer_did)
}

fn draft_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Evidence Dossier Test Widget".into(),
        product_group: ProductGroup::Textile,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "Evidence Test GmbH".into(),
            address: "Berlin, DE".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        product_group_data: None,
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        placed_on_market_date: None,
        schema_version: "1.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        // Set directly rather than via a registry reader (none configured in
        // this harness) — sidesteps the Annex III in-force completeness gate
        // regardless of whether "textile" happens to be in force.
        operator_identifier: Some("did:web:evidence-test.example.com".into()),
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
// The tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generate_evidence_fails_for_a_draft_passport() {
    let (service, _evidence, _issuer_did) = build_service().await;
    let auth = auth();
    let created = service
        .create(draft_passport(), &auth)
        .await
        .expect("create");

    let err = service
        .generate_evidence(created.id, &auth)
        .await
        .expect_err("draft passport has no signature to export");
    assert!(matches!(err, DppError::Validation(_)));
}

#[tokio::test]
async fn publish_transfer_eol_then_generate_verifies_and_persists() {
    let (service, evidence, issuer_did) = build_service().await;
    let auth = auth();

    let created = service
        .create(draft_passport(), &auth)
        .await
        .expect("create");
    let published = service.publish(created.id, &auth).await.expect("publish");
    assert_eq!(published.status, PassportStatus::Published);
    assert!(published.jws_signature.is_some());
    assert!(published.public_jws_signature.is_some());

    // Transfer: today this node signs on behalf of both parties (see
    // transfer.rs's own doc comment — a documented single-node
    // simplification), so both operator DIDs must be the node's own DID for
    // the signatures to verify against a DID document this test can supply.
    let operator = |name: &str| ResponsibleOperator {
        did: issuer_did.clone(),
        name: name.into(),
        role: OperatorRole::Distributor,
        eu_operator_id: None,
        eu_operator_id_scheme: None,
        country: "DE".into(),
    };
    service
        .initiate_transfer(
            published.id,
            operator("From Operator"),
            operator("To Operator"),
            TransferReason::Sale,
            Some("evidence dossier test".into()),
            &auth,
        )
        .await
        .expect("initiate transfer");
    service
        .accept_transfer(published.id, &auth)
        .await
        .expect("accept transfer");

    // End of life.
    let eol = EolEvent::new(
        published.id,
        DeactivationReason::Recycled,
        issuer_did.clone(),
    );
    service
        .declare_eol(published.id, eol, &auth)
        .await
        .expect("declare eol");

    // Generate the dossier and persist it.
    let record = service
        .generate_evidence(published.id, &auth)
        .await
        .expect("generate evidence");

    assert_eq!(record.actor, "evidence-test");
    assert_eq!(record.passport_id, published.id);
    let recomputed = content_hash(&serde_json::to_value(&record.dossier).unwrap())
        .expect("stored dossier canonicalises");
    assert_eq!(
        record.doc_hash, recomputed,
        "stored doc_hash must match a fresh recomputation over the stored dossier"
    );

    let dossier = &record.dossier;
    assert_eq!(
        dossier.transfer_chain.as_ref().map(|c| c.transfers.len()),
        Some(1)
    );
    assert!(dossier.eol_event.is_some(), "EOL event should be present");
    assert!(
        dossier.calc_receipts.is_empty(),
        "calc receipts are always empty in v1"
    );
    assert!(
        dossier.checkpoint.is_none(),
        "checkpoint is always absent in v1"
    );

    // Verify the stored dossier — must come back clean.
    let report = service
        .verify_evidence(record.id)
        .await
        .expect("verify freshly generated dossier");
    assert!(
        report.all_verified(),
        "clean dossier must verify: {report:#?}"
    );
    assert_eq!(report.exit_code(), 0);

    // Tamper: flip one byte in the stored record (standing in for storage
    // returning altered bytes) and confirm verification names the break
    // rather than reporting false-green.
    let mut tampered = record.clone();
    tampered.dossier.audit_entries[0].action = "tampered".into();
    evidence.replace(tampered);

    let tampered_report = service
        .verify_evidence(record.id)
        .await
        .expect("a tampered-but-structurally-valid dossier must still parse");
    assert!(
        !tampered_report.all_verified(),
        "tampered audit row must be detected"
    );
    let audit_check = tampered_report
        .checks
        .iter()
        .find(|c| c.name == "audit_chain")
        .unwrap();
    assert!(matches!(
        audit_check.status,
        dpp_types::evidence::CheckStatus::Fail(_)
    ));

    // Generating a second dossier and listing must return both, newest first.
    // A short sleep avoids a `created_at` tie with `record` under fast clocks.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let record2 = service
        .generate_evidence(published.id, &auth)
        .await
        .expect("generate a second dossier");
    let summaries = service
        .list_evidence(published.id)
        .await
        .expect("list evidence");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].id, record2.id, "newest dossier must be first");
    assert_eq!(summaries[1].id, record.id);
}
