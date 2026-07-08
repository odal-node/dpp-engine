//! N02 round-trip: publish -> transfer -> declare EOL -> export the evidence
//! dossier -> verify it fully offline via `dpp_evidence::verify_dossier_json`.
//!
//! Uses real Ed25519 signing (`dpp_crypto::LocalIdentityService`, backed by a
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

use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync,
    compliance::passthrough_registry::PassthroughRegistry,
    domain::{
        eol::{DeactivationReason, EolEvent},
        passport::{FacilitySnapshot, ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
        transfer::{OperatorRole, ResponsibleOperator, TransferChain, TransferReason},
    },
    ports::passport_repo::PassportRepository,
};
use dpp_types::{
    api_key::ApiKeyScope,
    audit::{AuditEntry, AuditRepository, GENESIS_PREV_HASH},
    auth::AuthContext,
    transfer::TransferStore,
};
use dpp_vault::domain::service::PassportService;

// ---------------------------------------------------------------------------
// In-memory ports (no Docker/Postgres — see module doc comment)
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

/// Chains entries exactly as `dpp-dal::pg::repo_audit::PgAuditRepo` does —
/// read the current head's `entry_hash` (or genesis), fold it into the new
/// entry's hash, store both. Without this, `verify_audit_chain` would fail
/// on a perfectly legitimate dossier.
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
/// (pathless form — see `dpp_crypto::identity::did_builder`).
async fn build_service() -> (PassportService, String) {
    let key_path =
        std::env::temp_dir().join(format!("evidence-test-{}.json", uuid::Uuid::new_v4()));
    let store =
        dpp_crypto::keystore::KeyStore::open(&key_path, "test-pass").expect("open keystore");
    store.generate_key("root").expect("generate key");
    let base_url = "evidence-test.example.com".to_owned();
    let issuer_did = format!("did:web:{}", base_url.replace(':', "%3A"));
    let identity = Arc::new(dpp_crypto::LocalIdentityService::new(
        Arc::new(store),
        "root".to_owned(),
        base_url,
    ));

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
    .with_transfer_store(Arc::new(InMemoryTransferStore::default()));

    (service, issuer_did)
}

fn draft_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Evidence Export Test Widget".into(),
        sector: Sector::Textile,
        product_category: None,
        manufacturer: ManufacturerInfo {
            name: "Evidence Test GmbH".into(),
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
        schema_version: "1.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        retention_until: None,
        product_id: None,
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
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_transfer_eol_then_export_verifies_fully_offline() {
    let (service, issuer_did) = build_service().await;
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
        country: "DE".into(),
    };
    service
        .initiate_transfer(
            published.id,
            operator("From Operator"),
            operator("To Operator"),
            TransferReason::Sale,
            Some("evidence export test".into()),
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

    // Export the dossier and verify it fully offline.
    let dossier = service
        .export_evidence(published.id)
        .await
        .expect("export evidence");

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

    let dossier_bytes = serde_json::to_vec(&dossier).unwrap();
    let report =
        dpp_evidence::verify_dossier_json(&dossier_bytes, dpp_evidence::VerifyMode::Embedded)
            .expect("a freshly exported dossier must at least parse");
    assert!(
        report.all_verified(),
        "clean dossier must verify: {report:#?}"
    );
    assert_eq!(report.exit_code(), 0);

    // Determinism: exporting again (no new events in between) differs only
    // in the manifest's own timestamp/signature, not in the underlying
    // members.
    let dossier2 = service
        .export_evidence(published.id)
        .await
        .expect("export evidence again");
    assert_eq!(dossier.full_view.payload, dossier2.full_view.payload);
    assert_eq!(dossier.audit_entries.len(), dossier2.audit_entries.len());

    // Tamper: flip one byte in a stored audit row (round-tripped through
    // JSON, exactly as a real consumer of the exported file would see it)
    // and confirm the verifier names the break rather than reporting
    // false-green.
    let mut tampered = serde_json::to_value(&dossier).unwrap();
    tampered["auditEntries"][0]["action"] = serde_json::json!("tampered");
    let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
    let tampered_report =
        dpp_evidence::verify_dossier_json(&tampered_bytes, dpp_evidence::VerifyMode::Embedded)
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
        dpp_evidence::CheckStatus::Fail(_)
    ));
}
