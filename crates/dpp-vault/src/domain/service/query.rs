//! Read paths: fetch by id or printed label, paginated list, count, and audit
//! history.

use dpp_domain::{
    Gtin, ProductIdentifier,
    error::DppError,
    passport::{CarrierQualifier, Passport, PassportId},
    ports::passport_repo::{MAX_SUCCESSION_HOPS, PassportRepository},
    product::ProductIdentity,
    status::PassportStatus,
};
use dpp_types::audit::PassportAuditEntry;

use super::PassportService;

impl PassportService {
    /// Fetch a passport by id regardless of status.
    ///
    /// # Errors
    ///
    /// Returns `DppError::NotFound` if the id is unknown.
    pub async fn find_by_id(&self, id: PassportId) -> Result<Passport, DppError> {
        match self.repo.find_by_id(id).await? {
            Some(p) => Ok(p),
            None => Err(DppError::NotFound(id.to_string())),
        }
    }

    /// Fetch a published passport by id, or `None` if unpublished or unknown.
    pub async fn find_published(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.repo.find_published_by_id(id).await
    }

    /// The one passport a printed GS1 label resolves to, in any status, so the
    /// caller can tell a missing product from a recalled one.
    ///
    /// `batch` and `serial` are the label's AI 10 and AI 21. A serial names one
    /// passport at any level, so once it is present the batch is not consulted:
    /// labels printed before the carrier followed `granularity` carry both, and
    /// the serial is the part that identifies. A batch alone names a batch-level
    /// passport. A bare GTIN names a model-level carrier, or is what someone
    /// holding only the GTIN typed, so it reads both
    /// [`find_by_carrier`](PassportRepository::find_by_carrier) with `Model` and
    /// [`find_by_identifier`](PassportRepository::find_by_identifier) with no
    /// batch and no serial.
    ///
    /// # Why it follows amendments
    ///
    /// The label on the object never changes, and an amendment issues a new
    /// passport. A successor that carries the carrier forward is found directly;
    /// one issued before successors did is reached only by walking forward from
    /// the superseded record. Either way the reader holding the product reaches
    /// the current record. See [`current_record`].
    ///
    /// Drafts are never an answer. An amendment writes its successor as a draft
    /// before publishing it, and one whose publish was refused stays behind as a
    /// draft; neither is the record the label names.
    ///
    /// # Errors
    ///
    /// [`DppError::Internal`] when the label names more than one current record
    /// that are not one amendment chain. That is a data error; choosing one
    /// would send a reader holding one product to another's passport.
    /// [`DppError::SuccessionUnresolvable`] from the store, for a chain it
    /// cannot walk.
    pub async fn resolve_label(
        &self,
        gtin: Gtin,
        batch: Option<&str>,
        serial: Option<&str>,
    ) -> Result<Option<Passport>, DppError> {
        resolve_label(&*self.repo, gtin, batch, serial).await
    }

    /// Fetch a passport by exact compound identity (product group, GTIN, batch),
    /// across `Draft` and `Published` — the import delta-matcher's lookup.
    pub async fn find_by_identity(
        &self,
        identity: &ProductIdentity,
    ) -> Result<Option<Passport>, DppError> {
        self.repo.find_by_identity(identity).await
    }

    /// Fetch a passport in any status, including `Retired`. Returns `None` if unknown.
    pub async fn find_by_id_any_status(
        &self,
        id: PassportId,
    ) -> Result<Option<Passport>, DppError> {
        self.repo.find_by_id_any_status(id).await
    }

    /// Paginated list of passports with optional status, text, and facility filter.
    pub async fn list(
        &self,
        status: Option<PassportStatus>,
        q: Option<&str>,
        facility_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        self.repo.list(status, q, facility_id, limit, offset).await
    }

    /// Count passports, optionally filtered by status and/or facility.
    pub async fn count(
        &self,
        status: Option<PassportStatus>,
        facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        self.repo.count(status, facility_id).await
    }

    /// Return the append-only audit trail for a passport.
    ///
    /// Verifies the passport exists first so an unknown id returns
    /// `DppError::NotFound` rather than an empty list.
    pub async fn history(&self, id: PassportId) -> Result<Vec<PassportAuditEntry>, DppError> {
        // Verify the passport exists so an unknown id returns 404 (consistent
        // with GET /dpp/{id}); otherwise the handler's NotFound branch is dead
        // and a nonexistent passport would return `200 []`.
        self.find_by_id(id).await?;
        self.audit.list_by_passport(&id.to_string()).await
    }

    /// Every archived version of a passport, oldest first.
    ///
    /// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2.
    ///
    /// Verifies the passport exists first, for the same reason [`Self::history`]
    /// does: otherwise an unknown id returns `200 []`, which reads as "this
    /// passport has never changed" rather than "there is no such passport".
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown id; otherwise the store's own failure.
    pub async fn versions(
        &self,
        id: PassportId,
    ) -> Result<Vec<dpp_types::audit::PassportVersion>, DppError> {
        self.find_by_id(id).await?;
        self.versions
            .as_ref()
            .ok_or_else(|| DppError::Internal("version archive not configured".into()))?
            .versions(&id.to_string())
            .await
    }

    /// The version that was current at `at`.
    ///
    /// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — *"the archived version
    /// corresponding to a given point in time shall be retrievable"*.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown id; otherwise the store's own failure.
    pub async fn version_at(
        &self,
        id: PassportId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<VersionAt, DppError> {
        let passport = self.find_by_id(id).await?;

        // 🚨 Before the passport existed, the store answers the wrong question.
        //
        // `version_at` asks for the earliest version that stopped being current
        // *after* `at`, and for any instant before the first change that is the
        // initial version — including instants before the passport was created.
        // So "what did this say in 1990" returned the initial record, which
        // asserts the passport existed in 1990.
        //
        // Checked here rather than in the store because this is where the live
        // record is in hand; the store holds versions and has no way to know
        // when the thing they are versions of came into being.
        if at < passport.created_at {
            return Ok(VersionAt::BeforeItExisted);
        }

        let found = self
            .versions
            .as_ref()
            .ok_or_else(|| DppError::Internal("version archive not configured".into()))?
            .version_at(&id.to_string(), at)
            .await?;

        Ok(found.map_or(VersionAt::Live, VersionAt::Found))
    }
}

/// [`PassportService::resolve_label`], over the port alone.
async fn resolve_label(
    repo: &dyn PassportRepository,
    gtin: Gtin,
    batch: Option<&str>,
    serial: Option<&str>,
) -> Result<Option<Passport>, DppError> {
    let identifier = ProductIdentifier::gs1(gtin);
    let named = match (serial, batch) {
        (Some(serial), _) => {
            repo.find_by_carrier(&identifier, &CarrierQualifier::Serial(serial.into()))
                .await?
        }
        (None, Some(batch)) => {
            repo.find_by_carrier(&identifier, &CarrierQualifier::Batch(batch.into()))
                .await?
        }
        (None, None) => {
            let mut named = repo
                .find_by_carrier(&identifier, &CarrierQualifier::Model)
                .await?;
            named.extend(repo.find_by_identifier(&identifier, None, None).await?);
            named
        }
    };

    let mut current: Vec<Passport> = Vec::new();
    for record in named {
        if record.status == PassportStatus::Draft {
            continue;
        }
        let record = current_record(repo, record).await?;
        if !current.iter().any(|seen| seen.id == record.id) {
            current.push(record);
        }
    }

    match current.len() {
        0 | 1 => Ok(current.pop()),
        n => Err(DppError::Internal(format!(
            "a GS1 label for {} names {n} current passports that are not one \
             amendment chain: {}",
            identifier.as_str(),
            current
                .iter()
                .map(|p| p.id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The record a reader holding `record`'s label should reach: `record` itself,
/// unless it was superseded, in which case the record that superseded it,
/// followed forward until one was not.
///
/// # Why not `find_superseding_head`
///
/// The port's walk returns the last record claiming a predecessor, whatever its
/// status. An amendment writes its successor as a draft and publishes it before
/// superseding anything, and a draft whose publish was refused keeps its claim.
/// So a published record with a failed amendment behind it has a draft "head",
/// and the port's walk would turn a working label into a `404`. Only a
/// `Superseded` record has a successor that was published, so the walk stops at
/// the first record that is not one.
///
/// Bounded and cycle-checked like the port's walk, for the same reason: an
/// inconsistent store must not turn one scan into an unbounded run of queries.
async fn current_record(
    repo: &dyn PassportRepository,
    record: Passport,
) -> Result<Passport, DppError> {
    let start = record.id;
    let mut seen = std::collections::HashSet::from([record.id]);
    let mut cursor = record;
    for _ in 0..MAX_SUCCESSION_HOPS {
        if cursor.status != PassportStatus::Superseded {
            return Ok(cursor);
        }
        match repo.find_superseding(cursor.id).await? {
            // A superseded record whose successor is still a draft, or that
            // names no successor, is inconsistent. It still serves as the
            // signed record it is, which is better than nothing for a reader.
            None => return Ok(cursor),
            Some(next) if next.status == PassportStatus::Draft => return Ok(cursor),
            Some(next) => {
                if !seen.insert(next.id) {
                    return Err(DppError::SuccessionUnresolvable {
                        id: start.to_string(),
                        reason: format!(
                            "the chain returns to passport {} — it is a cycle",
                            next.id
                        ),
                    });
                }
                cursor = next;
            }
        }
    }
    if cursor.status != PassportStatus::Superseded {
        return Ok(cursor);
    }
    Err(DppError::SuccessionUnresolvable {
        id: start.to_string(),
        reason: format!("the chain is longer than {MAX_SUCCESSION_HOPS} hops"),
    })
}

/// What [`PassportService::version_at`] found.
///
/// Three answers rather than two, because the two ways of having no archived
/// version are different facts and only one of them is answered by the live
/// record. Collapsed into an `Option`, a caller asking about a moment before the
/// passport existed would be told the live record is the state at that time —
/// which is a statement that the passport existed then.
#[derive(Debug, Clone)]
pub enum VersionAt {
    /// The version that was current at that instant.
    Found(dpp_types::audit::PassportVersion),
    /// No archived version covers the instant, and the **live** record is the
    /// state then: the passport had not changed by then, or the instant is after
    /// its most recent change.
    ///
    /// The live record is deliberately not returned from here. A route named for
    /// archived versions that sometimes answers with the current one makes
    /// "which version am I holding" unanswerable, and `GET /dpp/{dppId}` already
    /// serves it.
    Live,
    /// The instant is before the passport was created.
    BeforeItExisted,
}

#[cfg(test)]
mod label_resolution {
    //! Which passport a printed label reaches. The port lookups are core's and
    //! tested there; what is pinned here is the choice this module makes among
    //! what they return: drafts skipped, amendments followed, and two unrelated
    //! records refused rather than one picked.

    use chrono::Utc;
    use dpp_dal::in_memory_repo::InMemoryPassportRepo;
    use dpp_domain::ports::passport_repo::PassportRepository;
    use dpp_domain::{
        Gtin,
        catalog::Granularity,
        error::DppError,
        passport::{ManufacturerInfo, Passport, PassportId},
        product_group::{ProductGroup, ProductGroupData},
        status::PassportStatus,
    };

    use super::resolve_label;

    const GTIN: &str = "09506000134352";

    fn gtin() -> Gtin {
        Gtin::parse(GTIN).expect("valid GTIN")
    }

    fn passport(status: PassportStatus) -> Passport {
        let battery = serde_json::from_value(serde_json::json!({
            "productIdentifier": { "scheme": "gs1", "gtin": GTIN },
            "batteryChemistry": "LFP",
            "batteryType": "industrial",
            "nominalVoltageV": 3.2,
            "nominalCapacityAh": 100.0,
            "co2ePerUnitKg": 85.4
        }))
        .expect("a minimal battery deserialises");
        Passport {
            id: PassportId::new(),
            batch_id: None,
            serial_number: None,
            product_name: "Label Battery".into(),
            product_group: ProductGroup::Battery,
            applicable_instruments: Vec::new(),
            granularity: None,
            manufacturer: ManufacturerInfo {
                name: "ACME".into(),
                address: "1 Street".into(),
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
            product_group_data: Some(ProductGroupData::Battery(Box::new(battery))),
            status,
            qr_code_url: None,
            jws_signature: None,
            public_jws_signature: None,
            disclosure_signatures: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            published_at: None,
            placed_on_market_date: None,
            schema_version: "2.7.0".into(),
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
            carrier_serial: None,
        }
    }

    async fn store(repo: &InMemoryPassportRepo, passports: &[&Passport]) {
        for p in passports {
            repo.create((*p).clone()).await.expect("create");
        }
    }

    async fn resolved(
        repo: &InMemoryPassportRepo,
        batch: Option<&str>,
        serial: Option<&str>,
    ) -> Option<PassportId> {
        resolve_label(repo, gtin(), batch, serial)
            .await
            .expect("resolves")
            .map(|p| p.id)
    }

    /// One GTIN, three passports at three levels: each label names its own.
    #[tokio::test]
    async fn every_label_names_exactly_its_passport() {
        let repo = InMemoryPassportRepo::default();
        let mut model = passport(PassportStatus::Published);
        model.granularity = Some(Granularity::Model);
        let mut lot = passport(PassportStatus::Published);
        lot.granularity = Some(Granularity::Batch);
        lot.batch_id = Some("LOT-A".into());
        // No level stated, so its carrier prints a serial.
        let mut unit = passport(PassportStatus::Published);
        unit.batch_id = Some("LOT-A".into());
        store(&repo, &[&model, &lot, &unit]).await;
        let serial = unit.effective_carrier_serial().into_owned();

        assert_eq!(resolved(&repo, None, Some(&serial)).await, Some(unit.id));
        assert_eq!(resolved(&repo, Some("LOT-A"), None).await, Some(lot.id));
        assert_eq!(resolved(&repo, None, None).await, Some(model.id));
        // The shape printed before the carrier followed the level: the serial
        // identifies, and the lot beside it is not consulted.
        assert_eq!(
            resolved(&repo, Some("LOT-A"), Some(&serial)).await,
            Some(unit.id)
        );
        assert_eq!(resolved(&repo, None, Some("NOT-A-SERIAL")).await, None);
    }

    /// The label on the object outlives the record: after an amendment it
    /// reaches the successor, which carries the predecessor's serial.
    #[tokio::test]
    async fn an_amended_label_resolves_to_the_successor() {
        let repo = InMemoryPassportRepo::default();
        let predecessor = passport(PassportStatus::Superseded);
        let label = predecessor.effective_carrier_serial().into_owned();
        let mut successor = passport(PassportStatus::Published);
        successor.supersedes_id = Some(predecessor.id);
        successor.carrier_serial = Some(label.clone());
        store(&repo, &[&predecessor, &successor]).await;

        assert_eq!(
            resolved(&repo, None, Some(&label)).await,
            Some(successor.id)
        );
    }

    /// A successor that did not carry the serial — issued before successors
    /// did — is still reached, by walking forward from the superseded record.
    #[tokio::test]
    async fn a_successor_without_the_serial_is_reached_by_walking_forward() {
        let repo = InMemoryPassportRepo::default();
        let first = passport(PassportStatus::Superseded);
        let label = first.effective_carrier_serial().into_owned();
        let mut second = passport(PassportStatus::Superseded);
        second.supersedes_id = Some(first.id);
        let mut third = passport(PassportStatus::Published);
        third.supersedes_id = Some(second.id);
        store(&repo, &[&first, &second, &third]).await;

        assert_eq!(resolved(&repo, None, Some(&label)).await, Some(third.id));
    }

    /// An amendment writes its successor as a draft before publishing it, and a
    /// refused publish leaves the draft behind. Following it would turn a
    /// working label into a `404`.
    #[tokio::test]
    async fn a_draft_successor_does_not_capture_the_label() {
        let repo = InMemoryPassportRepo::default();
        let live = passport(PassportStatus::Published);
        let label = live.effective_carrier_serial().into_owned();
        let mut refused = passport(PassportStatus::Draft);
        refused.supersedes_id = Some(live.id);
        refused.carrier_serial = Some(label.clone());
        store(&repo, &[&live, &refused]).await;

        assert_eq!(resolved(&repo, None, Some(&label)).await, Some(live.id));
    }

    /// A withdrawn passport is still found, so the route can answer `410` — the
    /// recall signal — rather than a `404` that reads as a bad label.
    #[tokio::test]
    async fn a_suspended_passport_is_found_not_hidden() {
        let repo = InMemoryPassportRepo::default();
        let suspended = passport(PassportStatus::Suspended);
        let label = suspended.effective_carrier_serial().into_owned();
        store(&repo, &[&suspended]).await;

        let found = resolve_label(&repo, gtin(), None, Some(&label))
            .await
            .expect("resolves")
            .expect("found");
        assert_eq!(found.status, PassportStatus::Suspended);
    }

    /// Two current records under one label that are not one chain are a data
    /// error. Choosing one would send a reader holding one product to another's
    /// passport.
    #[tokio::test]
    async fn two_unrelated_records_under_one_label_are_refused_not_chosen() {
        let repo = InMemoryPassportRepo::default();
        let mut a = passport(PassportStatus::Published);
        a.carrier_serial = Some("SN-0001".into());
        let mut b = passport(PassportStatus::Published);
        b.carrier_serial = Some("SN-0001".into());
        store(&repo, &[&a, &b]).await;

        let err = resolve_label(&repo, gtin(), None, Some("SN-0001"))
            .await
            .expect_err("an ambiguous label must not resolve");
        assert!(matches!(err, DppError::Internal(_)), "{err:?}");
    }

    /// The same serial under another GTIN is another product's label.
    #[tokio::test]
    async fn a_label_under_another_gtin_names_nothing() {
        let repo = InMemoryPassportRepo::default();
        let p = passport(PassportStatus::Published);
        let label = p.effective_carrier_serial().into_owned();
        store(&repo, &[&p]).await;

        let other = Gtin::parse("01234567890128").expect("valid GTIN");
        assert!(
            resolve_label(&repo, other, None, Some(&label))
                .await
                .expect("resolves")
                .is_none()
        );
    }
}
