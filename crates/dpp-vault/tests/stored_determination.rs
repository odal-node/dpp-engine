//! A stored compliance determination follows the content stored beside it.
//!
//! Drives the real `PassportService` with in-memory ports and a registry double
//! that answers from the data it is given and says which call answered. No
//! Docker: what a draft carries between edits, and which determination a
//! publish signs, are decisions of the service. The SQL that stores one, and the
//! row it leaves, are pinned against PostgreSQL in `dpp-dal`'s
//! `pg_determination_write`.
//!
//! The service here has no state-change log, so every write takes the
//! non-transactional path in `commit_separately`, which is the one that has to
//! carry a determination beside a field delta through the port's own `update`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{NaiveDate, Utc};

use dpp_dal::in_memory_repo::InMemoryPassportRepo;
use dpp_domain::{
    ComplianceError, ComplianceErrorKind, ComplianceResult, DppError, GhostBackup,
    GhostRegistrySync,
    credential::{PassportCredential, PassportCredentialSubject, SignedCredential},
    passport::{FacilitySnapshot, ManufacturerInfo, Passport, PassportId},
    ports::{compliance::ComplianceRegistry, identity::IdentityPort},
    product_group::{ProductGroup, ProductGroupData},
    status::PassportStatus,
};
use dpp_types::{
    api_key::ApiKeyScope,
    audit::{AuditRepository, GENESIS_PREV_HASH, PassportAuditEntry},
    auth::AuthContext,
};
use dpp_vault::domain::service::{OperatorIdentity, PassportService};

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

/// Chains entries as `PgAuditRepo` does, so the lifecycle's audit appends succeed.
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

/// Signs nothing, and keeps every payload it was asked to sign, in order. A
/// publish signs the full payload first, so the first one recorded after a
/// publish begins is what the signature covers.
#[derive(Default, Clone)]
struct RecordingIdentity {
    signed: Arc<Mutex<Vec<serde_json::Value>>>,
}

#[async_trait]
impl IdentityPort for RecordingIdentity {
    async fn sign_passport(
        &self,
        passport_id: PassportId,
        payload: &serde_json::Value,
    ) -> Result<SignedCredential, DppError> {
        self.signed.lock().unwrap().push(payload.clone());
        Ok(SignedCredential {
            credential: PassportCredential {
                context: vec!["https://www.w3.org/ns/credentials/v2".into()],
                credential_type: vec!["VerifiableCredential".into()],
                id: format!("urn:uuid:{passport_id}"),
                issuer: "did:web:test.mock".to_owned(),
                valid_from: Utc::now(),
                credential_subject: PassportCredentialSubject {
                    id: format!("urn:uuid:{passport_id}"),
                    payload_hash: String::new(),
                },
            },
            jws: "test-header.test-payload.test-sig".to_owned(),
            issuer_did: "did:web:test.mock".to_owned(),
        })
    }

    async fn verify_signature(
        &self,
        _jws: &str,
        _payload: &serde_json::Value,
    ) -> Result<bool, DppError> {
        Ok(true)
    }

    async fn own_did_document(&self) -> Result<serde_json::Value, DppError> {
        Ok(serde_json::json!({ "id": "did:web:test.mock" }))
    }
}

/// How the registry answers the next call.
#[derive(Clone, Copy)]
enum Answer {
    /// A determination.
    Determine,
    /// Nothing is registered to evaluate the product group.
    Unregistered,
    /// The evaluator was reached and failed.
    Broken,
}

/// A registry that answers from the data it is handed — the declared footprint
/// of a battery or a textile becomes the score — and stamps each answer with the
/// number of the call that made it, so two answers over the same data still
/// differ.
struct ScriptedRegistry {
    calls: AtomicU32,
    answer: Mutex<Answer>,
}

impl ScriptedRegistry {
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }

    fn answer(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }
}

impl ComplianceRegistry for ScriptedRegistry {
    fn compute(
        &self,
        _product_group_key: &str,
        data: &ProductGroupData,
        _law_in_force_on: Option<NaiveDate>,
    ) -> Result<ComplianceResult, ComplianceError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let kind = match *self.answer.lock().unwrap() {
            Answer::Determine => {
                let co2e_score = match data {
                    ProductGroupData::Battery(b) => b.co2e_per_unit_kg,
                    ProductGroupData::Textile(t) => t.carbon_footprint_kg_co2e,
                    _ => None,
                };
                return Ok(ComplianceResult {
                    co2e_score,
                    ruleset_version: Some(format!("scripted@{call}")),
                    ..ComplianceResult::default()
                });
            }
            Answer::Unregistered => ComplianceErrorKind::UnknownProductGroup,
            Answer::Broken => ComplianceErrorKind::Internal,
        };
        Err(ComplianceError {
            kind,
            message: "scripted".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    service: PassportService,
    registry: Arc<ScriptedRegistry>,
    identity: RecordingIdentity,
}

fn harness() -> Harness {
    let registry = Arc::new(ScriptedRegistry {
        calls: AtomicU32::new(0),
        answer: Mutex::new(Answer::Determine),
    });
    let identity = RecordingIdentity::default();
    let service = PassportService::new(
        Arc::new(InMemoryPassportRepo::default()),
        Arc::new(identity.clone()),
        registry.clone(),
        Arc::new(InMemoryAuditRepo::default()),
        Arc::new(dpp_common::event::NoOpEventBus),
        Arc::new(GhostRegistrySync),
        Arc::new(GhostBackup),
        OperatorIdentity {
            legal_name: "Test Operator GmbH".to_owned(),
            country: "DE".to_owned(),
        },
        "https://resolver.example.com".to_owned(),
    );
    Harness {
        service,
        registry,
        identity,
    }
}

fn auth() -> AuthContext {
    AuthContext {
        user_id: "determination-test".into(),
        scope: ApiKeyScope::Admin,
        key_id: None,
    }
}

/// The shipped demo EV battery's product group data, declaring `co2e` kg per unit.
fn battery_json(co2e: f64) -> serde_json::Value {
    let raw = include_str!("../../../ops/demo/passports/04-battery-ev-nmc.json");
    let mut body: serde_json::Value = serde_json::from_str(raw).expect("demo passport is JSON");
    let mut data = body["productGroupData"].take();
    data["co2ePerUnitKg"] = serde_json::json!(co2e);
    data
}

/// A draft battery declaring `co2e` kg per unit, with no declared envelope metrics.
fn draft(co2e: f64) -> Passport {
    draft_of(ProductGroup::Battery, battery_json(co2e))
}

/// The shipped demo textile's product group data, declaring `co2e` kg per unit.
fn textile_json(co2e: f64) -> serde_json::Value {
    let raw = include_str!("../../../ops/demo/samples/textile-full.json");
    let mut body: serde_json::Value = serde_json::from_str(raw).expect("demo sample is JSON");
    let mut data = body["productGroupData"].take();
    data["carbonFootprintKgCo2e"] = serde_json::json!(co2e);
    data
}

/// A draft textile: a product group whose passport obligation is not live, which
/// a battery's is. The test that relies on it says so, and fails when the law
/// changes it, rather than silently testing the other branch.
fn textile_draft(co2e: f64) -> Passport {
    assert!(
        !dpp_domain::InstrumentCatalog::new().passport_obligation_live("textile"),
        "textile now has a live passport obligation: pick a product group that has none"
    );
    draft_of(ProductGroup::Textile, textile_json(co2e))
}

fn draft_of(product_group: ProductGroup, data: serde_json::Value) -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "Determination Product".into(),
        product_group,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "Determination Test GmbH".into(),
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
        product_group_data: Some(
            serde_json::from_value(data).expect("demo product group data deserialises"),
        ),
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        placed_on_market_date: NaiveDate::from_ymd_opt(2026, 7, 1),
        schema_version: "1.0.0".into(),
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
        // Set directly, so the Annex III completeness gate at publish is met
        // without a registry reader.
        operator_identifier: Some("did:web:determination-test.example.com".into()),
        responsible_operator: None,
        facility: Some(FacilitySnapshot {
            scheme: "gln".into(),
            value: "1234567890128".into(),
            name: "Test Facility".into(),
            country: "DE".into(),
            address: None,
            identifier: None,
        }),
        seal: None,
        carrier_serial: None,
    }
}

fn edit(co2e: f64) -> serde_json::Value {
    serde_json::json!({ "productGroupData": battery_json(co2e) })
}

fn score(passport: &Passport) -> Option<f64> {
    passport
        .compliance_result
        .as_ref()
        .and_then(|r| r.co2e_score)
}

/// The determination as the document states it, so two can be compared though
/// `ComplianceResult` has no equality.
fn stated(passport: &Passport) -> serde_json::Value {
    serde_json::to_value(&passport.compliance_result).expect("a determination serialises")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The defect: a draft was signed with the determination computed when it was
/// created, whatever it had been edited to since.
#[tokio::test]
async fn a_draft_edited_after_create_is_signed_with_the_determination_of_what_it_holds() {
    let h = harness();
    let created = h
        .service
        .create(draft(55.3), &auth())
        .await
        .expect("create");
    assert_eq!(score(&created), Some(55.3));

    let edited = h
        .service
        .update(created.id, edit(60.1), &auth())
        .await
        .expect("update");
    assert_eq!(
        score(&edited),
        Some(60.1),
        "the draft answers with the determination of the data it now holds"
    );
    let read_back = h.service.find_by_id(created.id).await.expect("read back");
    assert_eq!(
        score(&read_back),
        Some(60.1),
        "and so does what was stored, between the edit and the publish"
    );

    let published = h
        .service
        .publish(created.id, &auth())
        .await
        .expect("publish");
    assert_eq!(score(&published), Some(60.1));

    let signed = h.identity.signed.lock().unwrap();
    assert_eq!(
        signed[0]["complianceResult"]["co2eScore"],
        serde_json::json!(60.1),
        "the signature covers the determination for the published data"
    );
}

/// A registry that answers differently on each call shows which answer is kept:
/// publish makes one computation, and that is the verdict it stores and signs.
#[tokio::test]
async fn the_determination_publish_stores_is_the_one_it_computed() {
    let h = harness();
    let created = h
        .service
        .create(draft(55.3), &auth())
        .await
        .expect("create");
    let at_create = stated(&created);
    let before = h.registry.calls();

    let published = h
        .service
        .publish(created.id, &auth())
        .await
        .expect("publish");

    assert_eq!(
        h.registry.calls() - before,
        1,
        "one computation, so the verdict that gates the publish and the one signed are one value"
    );
    let version = published
        .compliance_result
        .as_ref()
        .and_then(|r| r.ruleset_version.clone());
    assert_eq!(version, Some(format!("scripted@{}", h.registry.calls())));
    assert_ne!(
        stated(&published),
        at_create,
        "not the one computed when the draft was created"
    );
    assert_eq!(
        h.identity.signed.lock().unwrap()[0]["complianceResult"]["rulesetVersion"],
        serde_json::json!(version),
        "and the one the signature covers"
    );
}

/// Where nothing is live and the computation fails, a publish goes ahead with
/// no determination: the verdict of earlier content is not the content's.
#[tokio::test]
async fn a_computation_that_fails_at_publish_leaves_no_determination() {
    for answer in [Answer::Broken, Answer::Unregistered] {
        let h = harness();
        let created = h
            .service
            .create(textile_draft(3.2), &auth())
            .await
            .expect("create");
        assert!(
            created.compliance_result.is_some(),
            "a draft starts with one"
        );

        h.registry.answer(answer);
        let published = h
            .service
            .publish(created.id, &auth())
            .await
            .expect("no obligation is live, so a failed computation does not refuse");

        assert!(published.compliance_result.is_none());
        let stored = h
            .service
            .find_by_id_any_status(created.id)
            .await
            .expect("read")
            .expect("stored");
        assert!(
            stored.compliance_result.is_none(),
            "nothing is stored, rather than the verdict of the create"
        );
        assert!(
            h.identity.signed.lock().unwrap()[0]
                .get("complianceResult")
                .is_none(),
            "and nothing is signed"
        );
    }
}

/// Where a passport obligation is live, a computation that fails still refuses
/// the publish: the gate that could not run is not a gate that passed. The
/// passport stays a draft, with the determination it had.
#[tokio::test]
async fn a_live_obligation_still_refuses_a_publish_whose_computation_fails() {
    let h = harness();
    let created = h
        .service
        .create(draft(55.3), &auth())
        .await
        .expect("create");
    assert!(
        dpp_domain::InstrumentCatalog::new().passport_obligation_live("battery"),
        "battery has no live passport obligation any more: pick a product group that has one"
    );

    h.registry.answer(Answer::Broken);
    let refused = h
        .service
        .publish(created.id, &auth())
        .await
        .expect_err("the evaluator failed");
    assert!(matches!(refused, DppError::Validation(_)), "{refused:?}");

    let stored = h
        .service
        .find_by_id(created.id)
        .await
        .expect("still a draft");
    assert_eq!(stated(&stored), stated(&created));
}

/// The content of a published passport is frozen, and so is its determination.
/// A fresh one carries a new assessment time and could not be stored, so a
/// re-publish keeps the one it was first published with.
#[tokio::test]
async fn a_republish_keeps_the_determination_it_was_first_published_with() {
    let h = harness();
    let created = h
        .service
        .create(draft(55.3), &auth())
        .await
        .expect("create");
    let first = h
        .service
        .publish(created.id, &auth())
        .await
        .expect("publish");
    h.service
        .suspend(created.id, &auth(), None)
        .await
        .expect("suspend");

    let again = h
        .service
        .publish(created.id, &auth())
        .await
        .expect("re-publish");

    assert_eq!(stated(&again), stated(&first));
}

/// `co2ePerUnit` and `repairabilityScore` hold what the operator declared. The
/// calculated figures stay in the determination, where a reader can tell them
/// apart.
#[tokio::test]
async fn create_and_update_do_not_fill_the_declared_metrics_from_a_determination() {
    let h = harness();
    let created = h
        .service
        .create(draft(55.3), &auth())
        .await
        .expect("create");
    assert_eq!(score(&created), Some(55.3));
    assert!(created.co2e_per_unit.is_none());
    assert!(created.repairability_score.is_none());

    let edited = h
        .service
        .update(created.id, edit(60.1), &auth())
        .await
        .expect("update");
    assert_eq!(score(&edited), Some(60.1));
    assert!(edited.co2e_per_unit.is_none());
    assert!(edited.repairability_score.is_none());

    let declared = h
        .service
        .update(
            created.id,
            serde_json::json!({ "co2ePerUnit": 42.0 }),
            &auth(),
        )
        .await
        .expect("declare");
    assert_eq!(
        declared.co2e_per_unit.as_ref().map(|c| c.value_kg),
        Some(42.0),
        "a declared value is stored as declared"
    );

    let later = h
        .service
        .update(created.id, edit(70.0), &auth())
        .await
        .expect("update again");
    assert_eq!(score(&later), Some(70.0));
    assert_eq!(
        later.co2e_per_unit.as_ref().map(|c| c.value_kg),
        Some(42.0),
        "and a later determination does not replace it"
    );
}

/// An edit the evaluator cannot assess leaves the draft with no determination,
/// not the verdict of the content before it.
#[tokio::test]
async fn an_edit_that_cannot_be_assessed_clears_the_stale_determination() {
    let h = harness();
    let created = h
        .service
        .create(draft(55.3), &auth())
        .await
        .expect("create");
    assert!(created.compliance_result.is_some());

    h.registry.answer(Answer::Broken);
    let edited = h
        .service
        .update(created.id, edit(60.1), &auth())
        .await
        .expect("update");
    assert!(edited.compliance_result.is_none());

    let stored = h.service.find_by_id(created.id).await.expect("read back");
    assert!(stored.compliance_result.is_none());
}
