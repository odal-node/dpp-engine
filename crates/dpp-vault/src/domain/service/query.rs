//! Read paths: fetch by id or printed label, paginated list, count, and audit
//! history.

use dpp_domain::{
    Gtin, ProductIdentifier,
    error::DppError,
    passport::{CarrierQualifier, Passport, PassportId},
    ports::passport_repo::{MAX_SUCCESSION_HOPS, PassportRepository},
    product::ProductIdentity,
    product_group::ProductGroupData,
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
    /// caller can tell a missing product from a recalled one, and the level it
    /// was found at.
    ///
    /// `batch` and `serial` are the label's AI 10 and AI 21. The label is read at
    /// the most specific level it names, and where nothing is on record there, at
    /// each less specific level it carries, ending at the model:
    ///
    /// | Label | Levels tried, in order |
    /// |---|---|
    /// | serial, with or without a lot | serial, then the lot if the label has one, then the model |
    /// | lot only | lot, then the model |
    /// | GTIN only | the model |
    ///
    /// A serial names one passport at any level, so labels printed before the
    /// carrier followed `granularity` — which carry both — resolve by the serial,
    /// and the lot beside it is consulted only if the serial finds nothing. The
    /// model level is what a bare GTIN names, or is what someone holding only the
    /// GTIN typed, so it reads both
    /// [`find_by_carrier`](PassportRepository::find_by_carrier) with `Model` and
    /// [`find_by_identifier`](PassportRepository::find_by_identifier) with no
    /// batch and no serial.
    ///
    /// # Why it falls back
    ///
    /// An item or a lot inherits what is recorded for the product above it; that
    /// is how a GS1 resolver answers a granular identifier (GS1-CRSV1, 2.5.9 and
    /// 2.5.10). A unit whose serial the manufacturer's own system stamped, and
    /// that was never attributed here, is still a unit of the model, and the
    /// model's passport is its answer. Without the fallback every such unit is a
    /// `404`, which is what a label that resolves to nothing was.
    ///
    /// A level with a record answers, whatever the record's status. The fallback
    /// is for a level with **no** record, never a way past one: a recalled unit
    /// shows the recall, not its model's passport.
    ///
    /// The answer says which level it came from, so a caller can tell an exact
    /// match from an inherited one. A forged or mistyped serial resolves to the
    /// genuine model record; the count of those is the only trace of it.
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
    /// A published successor whose predecessor is not yet superseded is not an
    /// answer either: the label is the predecessor's until the supersede, and
    /// then it walks forward. See [`without_pending_successors`].
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
    ) -> Result<Option<LabelResolution>, DppError> {
        resolve_label(&*self.repo, gtin, batch, serial).await
    }

    /// Whether another passport already prints `serial` under `identifier`, so
    /// that a new passport attributing it would make one label name two unrelated
    /// records.
    ///
    /// `replaces` is the passport the new one declares it supersedes. A successor
    /// carries its predecessor's serial by design, and one label names the whole
    /// amendment chain, so the passport being replaced does not hold the serial
    /// against its successor, and neither does any superseded record behind it.
    ///
    /// A check, not a constraint. Two requests that arrive together can both pass
    /// it. The collision is not silent when it happens: the label lookup refuses
    /// to choose between two unrelated current records and answers with an error.
    ///
    /// # Errors
    ///
    /// The store's own failure.
    pub async fn carrier_serial_is_taken(
        &self,
        identifier: &ProductIdentifier,
        serial: &str,
        replaces: Option<PassportId>,
    ) -> Result<bool, DppError> {
        carrier_serial_is_taken(&*self.repo, identifier, serial, replaces).await
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
    /// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — the passport as it stood at
    /// any given moment can be retrieved.
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
) -> Result<Option<LabelResolution>, DppError> {
    let identifier = ProductIdentifier::gs1(gtin);

    // Most specific first. Built from the three levels this module names rather
    // than by matching on `CarrierQualifier`, which is `#[non_exhaustive]`: a
    // match from here needs a wildcard, and a wildcard would file a level core
    // adds later under one of these three without anyone deciding that it should.
    let mut ladder: Vec<(LabelLevel, CarrierQualifier<'_>)> = Vec::with_capacity(3);
    if let Some(serial) = serial {
        ladder.push((LabelLevel::Serial, CarrierQualifier::Serial(serial.into())));
    }
    if let Some(batch) = batch {
        ladder.push((LabelLevel::Batch, CarrierQualifier::Batch(batch.into())));
    }
    ladder.push((LabelLevel::Model, CarrierQualifier::Model));
    let requested = ladder[0].0;

    for (level, qualifier) in &ladder {
        let mut named = repo.find_by_carrier(&identifier, qualifier).await?;
        if *level == LabelLevel::Model {
            // A bare GTIN names a model-level carrier, or is what someone holding
            // only the GTIN typed: both are the model.
            named.extend(repo.find_by_identifier(&identifier, None, None).await?);
        }
        if let Some(passport) = current_for(repo, &identifier, named).await? {
            let resolution = LabelResolution {
                passport,
                requested,
                resolved: *level,
            };
            if resolution.inherited() {
                // The only trace a forged or mistyped serial leaves: the answer
                // is the genuine model record, and nothing in it says the label
                // did not match.
                metrics::counter!(
                    "label_inherited_total",
                    "requested" => requested.as_str(),
                    "resolved" => level.as_str()
                )
                .increment(1);
            }
            return Ok(Some(resolution));
        }
    }
    Ok(None)
}

/// The one current passport among `named`, or `None` when none is current.
///
/// Drafts never answer, amendments are followed, and two current records that are
/// not one chain are refused.
async fn current_for(
    repo: &dyn PassportRepository,
    identifier: &ProductIdentifier,
    named: Vec<Passport>,
) -> Result<Option<Passport>, DppError> {
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
    let mut current = without_pending_successors(current);

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

/// `current` without each record whose declared predecessor is also in it.
///
/// A successor takes over its predecessor's label when the predecessor is
/// superseded, not when the successor is published. Until then both are current,
/// and the one the label names is the predecessor, which the state machine still
/// holds live. Two moments put a pair here: an amendment publishes its successor
/// a step before it supersedes the predecessor, and a successor declared with
/// `supersedesId` at create waits for a separate `supersede` call. Without this
/// the label is an error for the whole of that wait, which for a declared
/// successor has no bound.
///
/// Left unfiltered when every record would go, which only records that each
/// declare another of them can do. That is an inconsistent store, and the
/// caller's refusal of an ambiguous label is the answer to it.
fn without_pending_successors(current: Vec<Passport>) -> Vec<Passport> {
    let ids: Vec<PassportId> = current.iter().map(|p| p.id).collect();
    let pending = |p: &Passport| p.supersedes_id.is_some_and(|prev| ids.contains(&prev));
    if current.iter().all(pending) {
        return current;
    }
    current.into_iter().filter(|p| !pending(p)).collect()
}

/// [`PassportService::carrier_serial_is_taken`], over the port alone.
///
/// Read through the same lookup a printed label goes through, so it answers for
/// the serial the label would print: an attributed one, or the default a passport
/// derives from its id.
async fn carrier_serial_is_taken(
    repo: &dyn PassportRepository,
    identifier: &ProductIdentifier,
    serial: &str,
    replaces: Option<PassportId>,
) -> Result<bool, DppError> {
    let holders = repo
        .find_by_carrier(identifier, &CarrierQualifier::Serial(serial.into()))
        .await?;
    // Superseded records are never a chain's head, and the head is either the
    // passport being replaced or a passport that holds the serial in its own
    // right. So ignoring them cannot hide a real holder.
    Ok(holders
        .iter()
        .any(|p| Some(p.id) != replaces && p.status != PassportStatus::Superseded))
}

/// Whether a live passport outside `passport`'s chain already prints its carrier
/// serial under its GTIN.
///
/// Publish asks this at the moment the label goes live. Create asks
/// [`carrier_serial_is_taken`] first, but two creates that arrive together can
/// both pass it, and two published holders of one label cannot be repaired:
/// neither declares the other, and `supersedesId` is fixed at create. Drafts do
/// not count here because a draft answers no label, so whichever of two drafts
/// publishes first keeps the serial and the other stays a draft.
///
/// "Outside the chain" is the rule [`without_pending_successors`] resolves by:
/// a passport and one that declares it in `supersedesId`, in either direction,
/// are one chain, and superseded records are behind its head.
pub(super) async fn carrier_serial_is_live_elsewhere(
    repo: &dyn PassportRepository,
    passport: &Passport,
) -> Result<bool, DppError> {
    let Some(identifier) = passport
        .product_group_data
        .as_ref()
        .and_then(ProductGroupData::product_identifier)
        .filter(|id| id.gtin().is_some())
    else {
        return Ok(false);
    };
    let serial = passport.effective_carrier_serial();
    let holders = repo
        .find_by_carrier(
            identifier,
            &CarrierQualifier::Serial(serial.as_ref().into()),
        )
        .await?;
    Ok(holders.iter().any(|p| {
        p.id != passport.id
            && Some(p.id) != passport.supersedes_id
            && p.supersedes_id != Some(passport.id)
            && !matches!(p.status, PassportStatus::Draft | PassportStatus::Superseded)
    }))
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

/// The level a printed label identifies: what follows its GTIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelLevel {
    /// The GTIN alone: every unit of a model.
    Model,
    /// AI 10: one production run.
    Batch,
    /// AI 21: one unit.
    Serial,
}

impl LabelLevel {
    /// The value this level takes as a metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Batch => "batch",
            Self::Serial => "serial",
        }
    }
}

/// The passport a printed label reached, and how it got there.
#[derive(Debug, Clone)]
pub struct LabelResolution {
    /// The passport the label resolves to.
    pub passport: Passport,
    /// The most specific level the label named.
    pub requested: LabelLevel,
    /// The level the passport was found at. Equal to `requested` for an exact
    /// match, less specific when the label's own level had no record.
    pub resolved: LabelLevel,
}

impl LabelResolution {
    /// Whether a less specific level answered than the label named.
    #[must_use]
    pub fn inherited(&self) -> bool {
        self.requested != self.resolved
    }
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

    use super::{
        LabelLevel, LabelResolution, carrier_serial_is_live_elsewhere, carrier_serial_is_taken,
        resolve_label,
    };

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

    async fn resolution(
        repo: &InMemoryPassportRepo,
        batch: Option<&str>,
        serial: Option<&str>,
    ) -> Option<LabelResolution> {
        resolve_label(repo, gtin(), batch, serial)
            .await
            .expect("resolves")
    }

    async fn resolved(
        repo: &InMemoryPassportRepo,
        batch: Option<&str>,
        serial: Option<&str>,
    ) -> Option<PassportId> {
        resolution(repo, batch, serial).await.map(|r| r.passport.id)
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
        assert_eq!(found.passport.status, PassportStatus::Suspended);
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

    /// A successor published before its predecessor is superseded has not taken
    /// the label over yet. An amendment is in that state for one step, and a
    /// successor declared with `supersedesId` until someone calls `supersede`;
    /// the label answers the predecessor throughout, and never an error.
    #[tokio::test]
    async fn a_published_successor_takes_the_label_only_once_its_predecessor_is_superseded() {
        let repo = InMemoryPassportRepo::default();
        let mut predecessor = passport(PassportStatus::Published);
        predecessor.carrier_serial = Some("SN-0001".into());
        let mut successor = passport(PassportStatus::Published);
        successor.carrier_serial = Some("SN-0001".into());
        successor.supersedes_id = Some(predecessor.id);
        store(&repo, &[&predecessor, &successor]).await;

        assert_eq!(
            resolved(&repo, None, Some("SN-0001")).await,
            Some(predecessor.id),
            "before the supersede the predecessor is still the live record"
        );

        repo.update_status(predecessor.id, PassportStatus::Superseded)
            .await
            .expect("supersede");
        assert_eq!(
            resolved(&repo, None, Some("SN-0001")).await,
            Some(successor.id)
        );
    }

    /// Records that each declare another of them are not one chain in any order,
    /// so the label stays refused rather than resolving to nothing.
    #[tokio::test]
    async fn records_that_declare_each_other_are_still_refused() {
        let repo = InMemoryPassportRepo::default();
        let mut a = passport(PassportStatus::Published);
        a.carrier_serial = Some("SN-0001".into());
        let mut b = passport(PassportStatus::Published);
        b.carrier_serial = Some("SN-0001".into());
        a.supersedes_id = Some(b.id);
        b.supersedes_id = Some(a.id);
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

    /// The model passport of the test GTIN.
    fn model() -> Passport {
        let mut p = passport(PassportStatus::Published);
        p.granularity = Some(Granularity::Model);
        p
    }

    /// A lot-level passport for `LOT-A`.
    fn lot() -> Passport {
        let mut p = passport(PassportStatus::Published);
        p.granularity = Some(Granularity::Batch);
        p.batch_id = Some("LOT-A".into());
        p
    }

    /// A unit of lot `LOT-A` that states no level, so its carrier prints a
    /// serial. It carries a lot, which keeps a bare-GTIN lookup from taking it
    /// for the model.
    fn unit(status: PassportStatus) -> Passport {
        let mut p = passport(status);
        p.batch_id = Some("LOT-A".into());
        p
    }

    /// A serial stamped by the manufacturer's own system and never attributed
    /// here still belongs to a model whose passport is on record. Without the
    /// fallback every such unit is a `404`.
    #[tokio::test]
    async fn an_unknown_serial_inherits_the_model_passport() {
        let repo = InMemoryPassportRepo::default();
        let model = model();
        store(&repo, &[&model]).await;

        let found = resolution(&repo, None, Some("ERP-000042"))
            .await
            .expect("inherits the model");
        assert_eq!(found.passport.id, model.id);
        assert_eq!(found.requested, LabelLevel::Serial);
        assert_eq!(found.resolved, LabelLevel::Model);
        assert!(found.inherited());
    }

    /// A label carrying both a lot and a serial reads the lot before the model:
    /// the unit's lot has a passport and the model's is further up.
    #[tokio::test]
    async fn an_unknown_serial_inherits_its_lot_before_the_model() {
        let repo = InMemoryPassportRepo::default();
        let (model, lot) = (model(), lot());
        store(&repo, &[&model, &lot]).await;

        let found = resolution(&repo, Some("LOT-A"), Some("ERP-000042"))
            .await
            .expect("inherits the lot");
        assert_eq!(found.passport.id, lot.id);
        assert_eq!(found.requested, LabelLevel::Serial);
        assert_eq!(found.resolved, LabelLevel::Batch);
    }

    /// A lot with no passport of its own is passed over on the way up, not a
    /// reason to stop.
    #[tokio::test]
    async fn a_lot_without_a_passport_is_passed_over_on_the_way_to_the_model() {
        let repo = InMemoryPassportRepo::default();
        let model = model();
        store(&repo, &[&model]).await;

        let found = resolution(&repo, Some("LOT-X"), Some("ERP-000042"))
            .await
            .expect("inherits the model");
        assert_eq!(found.passport.id, model.id);
        assert_eq!(found.requested, LabelLevel::Serial);
        assert_eq!(found.resolved, LabelLevel::Model);
    }

    /// A lot-only label with no passport for that lot inherits the model.
    #[tokio::test]
    async fn an_unknown_lot_inherits_the_model_passport() {
        let repo = InMemoryPassportRepo::default();
        let (model, lot) = (model(), lot());
        store(&repo, &[&model, &lot]).await;

        let found = resolution(&repo, Some("LOT-B"), None)
            .await
            .expect("inherits the model");
        assert_eq!(found.passport.id, model.id);
        assert_eq!(found.requested, LabelLevel::Batch);
        assert_eq!(found.resolved, LabelLevel::Model);
    }

    /// Inheritance needs something to inherit from. A product with a unit on
    /// record and no model passport has nothing at the level above, so another
    /// unit's serial names nothing.
    #[tokio::test]
    async fn an_unknown_serial_with_no_model_on_record_names_nothing() {
        let repo = InMemoryPassportRepo::default();
        let unit = unit(PassportStatus::Published);
        store(&repo, &[&unit]).await;

        assert!(resolution(&repo, None, Some("ERP-000042")).await.is_none());
    }

    /// A label that has its own record is answered by it. The model is the
    /// answer for a level with no record, never a replacement for one.
    #[tokio::test]
    async fn a_known_serial_is_answered_by_its_own_passport_not_the_models() {
        let repo = InMemoryPassportRepo::default();
        let (model, unit) = (model(), unit(PassportStatus::Published));
        store(&repo, &[&model, &unit]).await;
        let serial = unit.effective_carrier_serial().into_owned();

        let found = resolution(&repo, None, Some(&serial)).await.expect("found");
        assert_eq!(found.passport.id, unit.id);
        assert_eq!(found.resolved, LabelLevel::Serial);
        assert!(!found.inherited());
    }

    /// A GTIN-only label is the model itself, and nothing was inherited.
    #[tokio::test]
    async fn a_model_label_is_not_an_inherited_answer() {
        let repo = InMemoryPassportRepo::default();
        let model = model();
        store(&repo, &[&model]).await;

        let found = resolution(&repo, None, None).await.expect("found");
        assert_eq!(found.passport.id, model.id);
        assert!(!found.inherited());
    }

    /// A recall on one unit must reach the person holding that unit. If the
    /// model's passport answered instead, the recalled unit would read as a
    /// healthy one.
    #[tokio::test]
    async fn a_recalled_unit_is_not_hidden_by_its_models_passport() {
        let repo = InMemoryPassportRepo::default();
        let (model, unit) = (model(), unit(PassportStatus::Suspended));
        store(&repo, &[&model, &unit]).await;
        let serial = unit.effective_carrier_serial().into_owned();

        let found = resolution(&repo, None, Some(&serial)).await.expect("found");
        assert_eq!(found.passport.id, unit.id);
        assert_eq!(found.passport.status, PassportStatus::Suspended);
        assert!(!found.inherited());
    }

    /// The count of inherited answers is the only trace a forged or mistyped
    /// serial leaves, so it is pinned: removing or renaming it fails here.
    /// An exact answer is not counted, or the series would be every scan.
    #[tokio::test]
    async fn an_inherited_answer_is_counted_and_an_exact_one_is_not() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Thread-local, and a `#[tokio::test]` runs on one thread, so every await
        // below is recorded here and no other test sees it.
        let _guard = metrics::set_default_local_recorder(&recorder);

        let repo = InMemoryPassportRepo::default();
        let model = model();
        store(&repo, &[&model]).await;

        resolution(&repo, None, None).await.expect("exact");
        assert!(
            !handle.render().contains("label_inherited_total"),
            "an exact answer must not be counted"
        );

        resolution(&repo, None, Some("ERP-000042"))
            .await
            .expect("inherited");
        let rendered = handle.render();
        assert!(
            rendered.contains(r#"label_inherited_total{requested="serial",resolved="model"} 1"#),
            "an inherited answer is counted by the level asked and the level answered:\n{rendered}"
        );
    }

    /// A draft is nobody's answer, so a unit that has not been published yet
    /// leaves its label to the model.
    #[tokio::test]
    async fn a_draft_unit_does_not_answer_its_label() {
        let repo = InMemoryPassportRepo::default();
        let (model, unit) = (model(), unit(PassportStatus::Draft));
        store(&repo, &[&model, &unit]).await;
        let serial = unit.effective_carrier_serial().into_owned();

        let found = resolution(&repo, None, Some(&serial))
            .await
            .expect("inherits the model");
        assert_eq!(found.passport.id, model.id);
        assert_eq!(found.resolved, LabelLevel::Model);
    }

    /// A passport that attributes `serial` to its carrier.
    fn attributing(serial: &str, status: PassportStatus) -> Passport {
        let mut p = passport(status);
        p.carrier_serial = Some(serial.into());
        p
    }

    async fn taken(
        repo: &InMemoryPassportRepo,
        gtin: Gtin,
        serial: &str,
        replaces: Option<PassportId>,
    ) -> bool {
        carrier_serial_is_taken(
            repo,
            &dpp_domain::ProductIdentifier::gs1(gtin),
            serial,
            replaces,
        )
        .await
        .expect("checks")
    }

    /// Two unrelated passports under one GTIN that attribute one serial make a
    /// label that names both, and a label that names two resolves to neither. So
    /// the second is refused rather than stored.
    #[tokio::test]
    async fn a_serial_another_passport_holds_is_taken() {
        let repo = InMemoryPassportRepo::default();
        store(&repo, &[&attributing("SN-1", PassportStatus::Published)]).await;

        assert!(taken(&repo, gtin(), "SN-1", None).await);
        assert!(!taken(&repo, gtin(), "SN-2", None).await);
    }

    /// The same serial under another GTIN names another product, as a label under
    /// another GTIN always does.
    #[tokio::test]
    async fn a_serial_held_under_another_gtin_is_free() {
        let repo = InMemoryPassportRepo::default();
        store(&repo, &[&attributing("SN-1", PassportStatus::Published)]).await;

        let other = Gtin::parse("01234567890128").expect("valid GTIN");
        assert!(!taken(&repo, other, "SN-1", None).await);
    }

    /// A draft holds its serial. Otherwise two drafts could attribute one and
    /// collide when the first is published.
    #[tokio::test]
    async fn a_draft_holds_its_serial() {
        let repo = InMemoryPassportRepo::default();
        store(&repo, &[&attributing("SN-1", PassportStatus::Draft)]).await;

        assert!(taken(&repo, gtin(), "SN-1", None).await);
    }

    /// The passport a new one replaces shares its serial by design: one label
    /// names the whole amendment chain, and the current record answers it.
    #[tokio::test]
    async fn the_passport_being_replaced_does_not_hold_the_serial_against_its_successor() {
        let repo = InMemoryPassportRepo::default();
        let predecessor = attributing("SN-1", PassportStatus::Published);
        store(&repo, &[&predecessor]).await;

        assert!(
            !taken(&repo, gtin(), "SN-1", Some(predecessor.id)).await,
            "a successor may carry its predecessor's serial"
        );
        // Naming a different passport as the one replaced does not excuse it.
        assert!(taken(&repo, gtin(), "SN-1", Some(PassportId::new())).await);
    }

    /// Behind the head of a chain every record is superseded and shares the
    /// serial, so none of them holds it against a further successor.
    #[tokio::test]
    async fn a_superseded_chain_does_not_hold_the_serial_against_its_successor() {
        let repo = InMemoryPassportRepo::default();
        let first = attributing("SN-1", PassportStatus::Superseded);
        let mut second = attributing("SN-1", PassportStatus::Superseded);
        second.supersedes_id = Some(first.id);
        let mut head = attributing("SN-1", PassportStatus::Published);
        head.supersedes_id = Some(second.id);
        store(&repo, &[&first, &second, &head]).await;

        assert!(!taken(&repo, gtin(), "SN-1", Some(head.id)).await);
        // Without naming the head, the head holds it.
        assert!(taken(&repo, gtin(), "SN-1", None).await);
    }

    async fn live_elsewhere(repo: &InMemoryPassportRepo, passport: &Passport) -> bool {
        carrier_serial_is_live_elsewhere(repo, passport)
            .await
            .expect("checks")
    }

    /// Two drafts that both passed create's check, because their creates arrived
    /// together: whichever publishes first keeps the serial, and the other is
    /// refused at publish rather than making the label name two passports.
    #[tokio::test]
    async fn the_second_of_two_drafts_sharing_a_serial_cannot_go_live() {
        let repo = InMemoryPassportRepo::default();
        let mut first = attributing("SN-1", PassportStatus::Draft);
        let second = attributing("SN-1", PassportStatus::Draft);
        store(&repo, &[&first, &second]).await;

        assert!(
            !live_elsewhere(&repo, &first).await,
            "a draft answers no label, so it does not hold the serial against a publish"
        );
        repo.update_status(first.id, PassportStatus::Published)
            .await
            .expect("publish");
        first.status = PassportStatus::Published;

        assert!(live_elsewhere(&repo, &second).await);
        assert!(
            !live_elsewhere(&repo, &first).await,
            "a passport does not hold its own serial against itself"
        );
    }

    /// A passport and one that names it in `supersedesId` are one chain in
    /// either direction, and a superseded record is behind its head. None of
    /// them blocks the other from going live.
    #[tokio::test]
    async fn a_chain_does_not_hold_its_serial_against_itself_at_publish() {
        let repo = InMemoryPassportRepo::default();
        let predecessor = attributing("SN-1", PassportStatus::Published);
        let mut successor = attributing("SN-1", PassportStatus::Draft);
        successor.supersedes_id = Some(predecessor.id);
        let behind = attributing("SN-1", PassportStatus::Superseded);
        store(&repo, &[&predecessor, &successor, &behind]).await;

        assert!(!live_elsewhere(&repo, &successor).await);
        repo.update_status(successor.id, PassportStatus::Published)
            .await
            .expect("publish");
        // The predecessor coming back from a suspension while its declared
        // successor is live is the same chain, not a collision.
        assert!(!live_elsewhere(&repo, &predecessor).await);
    }

    /// The label prints the *effective* serial, so a value another passport
    /// prints by default is as taken as one it attributed.
    #[tokio::test]
    async fn a_serial_another_passport_prints_by_default_is_taken() {
        let repo = InMemoryPassportRepo::default();
        let defaulted = passport(PassportStatus::Published);
        let printed = defaulted.effective_carrier_serial().into_owned();
        store(&repo, &[&defaulted]).await;

        assert!(taken(&repo, gtin(), &printed, None).await);
    }
}
