//! A passport repository that archives every version it replaces.
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — *"all changes to the digital
//! product passport shall be archived"*.
//!
//! # Why this is a decorator and not a step in the service layer
//!
//! The clause says **all** changes. A rule with that shape cannot live in the
//! callers, because the failure mode is a caller that does not know it exists:
//! the next write path added is the one that forgets, and nothing fails when it
//! does — the passport simply changes with no version kept, and the omission is
//! invisible until somebody asks for a version that was never taken.
//!
//! Every mutation in this workspace goes through [`PassportRepository`]. Wrapping
//! it means the archive is not something a write path remembers to do; it is
//! something a write path *cannot avoid*. A new service method gets it by
//! existing.
//!
//! The cost is that a repository now writes somewhere the caller did not name,
//! which is a real surprise — so the type is named for what it does, and the
//! composition root wires it visibly rather than hiding it behind a constructor.
//!
//! # Archiving begins at the first change
//!
//! [`PassportRepository::create`] is passed straight through. The clause starts
//! archiving *"when the first change of the initial digital product passport
//! occurs"*, and a version archived at create would be one that nothing had
//! superseded — the live record already answers every question about the time
//! before the first change.
//!
//! # The pre-change state is what gets archived
//!
//! Each row is the passport *as it was*, stamped with the moment it stopped
//! being current. So the first change archives the initial passport, and the
//! live record is always the present. Archiving the post-change state instead
//! would leave the initial version unrecorded — exactly the one the clause names.
//!
//! # The batch methods are covered without being written here
//!
//! `update_batch` is deliberately **not** overridden. Its trait default loops
//! over `self.update`, and `self` is this decorator — so each item archives,
//! and the coverage comes from not writing the method rather than from writing
//! it. Overriding it to call `inner.update_batch` is the mistake available
//! here: it would be the obvious "pass it through" and would skip every version
//! in a bulk import.
//!
//! `create_batch` likewise loops over `self.create`, which passes through,
//! which is correct — creates are not changes.
//!
//! The inner repository defines neither, so nothing faster is being bypassed
//! today. If one grows a bulk implementation, this decorator has to grow a
//! matching override that archives first — the default will silently stop
//! reaching it.
//!
//! # 🚨 Archive first, then mutate
//!
//! The port exposes no transaction, so the two writes cannot be made atomic
//! here. They are ordered so that the failure is the harmless one: archive, then
//! mutate. A crash in between leaves a version identical to the still-current
//! record — a duplicate, which later reads simply see twice over the same
//! interval and answer identically. The other order loses a version outright,
//! and a lost version is not detectable after the fact.

use async_trait::async_trait;
use chrono::Utc;

use dpp_domain::{
    DppError,
    passport::{Passport, PassportId},
    ports::passport_repo::PassportRepository,
    status::PassportStatus,
};
use dpp_types::audit::PassportVersionStore;

/// Wraps a passport repository, archiving each version it replaces.
pub struct ArchivingPassportRepo<R: PassportRepository> {
    inner: R,
    versions: std::sync::Arc<dyn PassportVersionStore>,
}

impl<R: PassportRepository> ArchivingPassportRepo<R> {
    /// Wrap `inner`, recording superseded versions in `versions`.
    pub fn new(inner: R, versions: std::sync::Arc<dyn PassportVersionStore>) -> Self {
        Self { inner, versions }
    }

    /// Archive the current state of `id`, if there is one to archive.
    ///
    /// A failure here **fails the write**. The alternative — log and carry on —
    /// would mean a passport that changed with no version kept, which is the
    /// one outcome the clause forbids, and it would be silent. Refusing the
    /// change is visible, recoverable, and leaves the passport consistent with
    /// its own archive.
    async fn archive_current(&self, id: PassportId) -> Result<(), DppError> {
        let Some(current) = self.inner.find_by_id_any_status(id).await? else {
            // Nothing to supersede. The mutation below will fail on its own
            // terms and say so more precisely than this could.
            return Ok(());
        };
        let doc = serde_json::to_value(&current).map_err(|e| {
            DppError::Serialisation(format!("cannot archive the passport version: {e}"))
        })?;
        self.versions
            .archive(&id.to_string(), &doc, Utc::now())
            .await
    }
}

#[async_trait]
impl<R: PassportRepository> PassportRepository for ArchivingPassportRepo<R> {
    // ── Reads pass straight through ────────────────────────────────────────

    async fn find_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.inner.find_by_id(id).await
    }

    async fn find_published_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.inner.find_published_by_id(id).await
    }

    async fn find_published_by_gtin(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        self.inner.find_published_by_gtin(gtin).await
    }

    async fn find_by_gtin_any_status(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        self.inner.find_by_gtin_any_status(gtin).await
    }

    async fn find_by_id_any_status(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.inner.find_by_id_any_status(id).await
    }

    async fn list(
        &self,
        status: Option<PassportStatus>,
        q: Option<&str>,
        facility_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        self.inner.list(status, q, facility_id, limit, offset).await
    }

    async fn count(
        &self,
        status: Option<PassportStatus>,
        facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        self.inner.count(status, facility_id).await
    }

    // ── Create is not a change ─────────────────────────────────────────────

    async fn create(&self, passport: Passport) -> Result<Passport, DppError> {
        self.inner.create(passport).await
    }

    // ── Every mutation archives what it replaces ───────────────────────────

    async fn update(&self, passport: Passport) -> Result<Passport, DppError> {
        self.archive_current(passport.id).await?;
        self.inner.update(passport).await
    }

    async fn patch_fields(
        &self,
        id: PassportId,
        fields: serde_json::Value,
    ) -> Result<Passport, DppError> {
        self.archive_current(id).await?;
        self.inner.patch_fields(id, fields).await
    }

    async fn update_status(
        &self,
        id: PassportId,
        status: PassportStatus,
    ) -> Result<Passport, DppError> {
        self.archive_current(id).await?;
        self.inner.update_status(id, status).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// An in-memory version store that records what it was asked to archive.
    #[derive(Default)]
    struct Recording {
        archived: Mutex<Vec<(String, serde_json::Value)>>,
    }

    #[async_trait]
    impl PassportVersionStore for Recording {
        async fn archive(
            &self,
            passport_id: &str,
            doc: &serde_json::Value,
            _superseded_at: chrono::DateTime<Utc>,
        ) -> Result<(), DppError> {
            self.archived
                .lock()
                .expect("lock")
                .push((passport_id.to_owned(), doc.clone()));
            Ok(())
        }

        async fn versions(
            &self,
            _passport_id: &str,
        ) -> Result<Vec<dpp_types::audit::PassportVersion>, DppError> {
            Ok(Vec::new())
        }

        async fn version_at(
            &self,
            _passport_id: &str,
            _at: chrono::DateTime<Utc>,
        ) -> Result<Option<dpp_types::audit::PassportVersion>, DppError> {
            Ok(None)
        }
    }

    fn a_passport() -> Passport {
        Passport {
            id: PassportId::new(),
            batch_id: None,
            serial_number: None,
            product_name: "Kettle".into(),
            product_group: dpp_domain::product_group::ProductGroup::Battery,
            applicable_instruments: Vec::new(),
            granularity: None,
            manufacturer: dpp_domain::passport::ManufacturerInfo {
                name: "GreenCell GmbH".into(),
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
            schema_version: "2.0.0".into(),
            retention_locked: false,
            version: 1,
            supersedes_id: None,
            derived_from: Vec::new(),
            component_refs: Vec::new(),
            life_status: None,
            retention_until: None,
            product_id: None,
            commodity_code: None,
            operator_identifier: None,
            responsible_operator: None,
            facility: None,
            seal: None,
        }
    }

    /// Creating is not a change, so it archives nothing.
    ///
    /// EN 18221 clause 4.2 starts archiving *"when the first change of the
    /// initial digital product passport occurs"*. A version taken at create
    /// would be one nothing had superseded, and the live record already answers
    /// every question about the time before the first change.
    #[tokio::test]
    async fn creating_a_passport_archives_nothing() {
        let versions = std::sync::Arc::new(Recording::default());
        let repo = ArchivingPassportRepo::new(
            crate::in_memory_repo::InMemoryPassportRepo::default(),
            versions.clone(),
        );

        repo.create(a_passport()).await.expect("create");

        assert!(
            versions.archived.lock().expect("lock").is_empty(),
            "create is not a change"
        );
    }

    /// Every mutation archives the state it replaced.
    ///
    /// The **pre**-change state, which is what makes the first change record the
    /// initial passport — the version the clause names. Archiving the result
    /// instead would leave the initial version unrecorded, and no later change
    /// could recover it.
    #[tokio::test]
    async fn every_mutation_archives_what_it_replaced() {
        let versions = std::sync::Arc::new(Recording::default());
        let repo = ArchivingPassportRepo::new(
            crate::in_memory_repo::InMemoryPassportRepo::default(),
            versions.clone(),
        );

        let created = repo.create(a_passport()).await.expect("create");
        let id = created.id;

        let mut changed = created.clone();
        changed.product_name = "Kettle Mk II".to_owned();
        repo.update(changed).await.expect("update");

        repo.patch_fields(id, serde_json::json!({ "productName": "Kettle Mk III" }))
            .await
            .expect("patch");

        repo.update_status(id, PassportStatus::Published)
            .await
            .expect("status");

        let archived = versions.archived.lock().expect("lock");
        assert_eq!(
            archived.len(),
            3,
            "one version per change — update, patch and status transition are all changes"
        );
        assert!(
            archived.iter().all(|(pid, _)| pid == &id.to_string()),
            "each version belongs to the passport that changed"
        );
        assert_eq!(
            archived[0].1.get("productName").and_then(|v| v.as_str()),
            Some("Kettle"),
            "the first change archives the passport as it was, not as it became"
        );
        assert_eq!(
            archived[1].1.get("productName").and_then(|v| v.as_str()),
            Some("Kettle Mk II"),
            "and each later change archives what it in turn replaced"
        );
        assert_eq!(
            archived[2].1.get("productName").and_then(|v| v.as_str()),
            Some("Kettle Mk III"),
            "including the state a status transition replaced, which it did not itself write"
        );
    }

    /// A bulk update archives every item, without this type saying so.
    ///
    /// 🚨 The property is inherited rather than written: `update_batch`'s trait
    /// default loops over `self.update`, and `self` is the decorator. Overriding
    /// it to delegate to `inner.update_batch` is the mistake available here —
    /// the obvious "pass it through" — and it would silently skip every version
    /// in an import. This pins the inheritance so that mistake fails.
    #[tokio::test]
    async fn a_batch_update_archives_every_item() {
        let versions = std::sync::Arc::new(Recording::default());
        let repo = ArchivingPassportRepo::new(
            crate::in_memory_repo::InMemoryPassportRepo::default(),
            versions.clone(),
        );

        let first = repo.create(a_passport()).await.expect("create");
        let second = repo.create(a_passport()).await.expect("create");
        assert!(
            versions.archived.lock().expect("lock").is_empty(),
            "still no changes"
        );

        repo.update_batch(vec![first, second]).await;

        assert_eq!(
            versions.archived.lock().expect("lock").len(),
            2,
            "a bulk update is a change per item, and each one is archived"
        );
    }
}
