//! `create` and `update` — draft-passport writes, plus their private helpers
//! `apply_patch` (validates and applies an update patch), `apply_compliance`
//! (backfills compliance-derived fields from the registered `ComplianceRegistry`),
//! and `apply_lint` (refreshes the non-binding plausibility findings).

use chrono::Utc;
use dpp_common::event;
use std::collections::HashSet;

use dpp_domain::{
    domain::{
        error::DppError,
        graph::{ComponentEdges, DEFAULT_DEPTH_CAP, EdgeRejection, check_edge},
        passport::{Passport, PassportId, PassportRef},
        sector::{CarbonFootprint, RepairabilityScore, SectorData},
        status::PassportStatus,
    },
    ports::compliance::ComplianceRegistry,
};
use dpp_types::{STANDALONE_OPERATOR_ID, audit::AuditEntry, auth::AuthContext};
use serde_json::Value;
use uuid::Uuid;

use super::PassportService;
use super::catalog;

impl PassportService {
    /// Create a new passport in `Draft` status.
    ///
    /// Assigns a fresh `PassportId`, normalises `schema_version` from the sector
    /// catalog, runs compliance enrichment, persists, appends an audit entry,
    /// and emits `dpp.passport.created` (non-blocking — failure is logged only).
    #[tracing::instrument(skip(self, passport), fields(passport_id = tracing::field::Empty))]
    pub async fn create(
        &self,
        mut passport: Passport,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        passport.id = PassportId::new();
        tracing::Span::current().record("passport_id", passport.id.to_string().as_str());
        passport.status = PassportStatus::Draft;
        passport.created_at = Utc::now();
        passport.updated_at = Utc::now();
        passport.schema_version = catalog()
            .current_schema_version(passport.sector.catalog_key())
            .unwrap_or("1.0.0")
            .to_owned();

        // Stamp the economic-operator registry identifiers (ESPR Annex III
        // facility + Art. 13 operator identifier) when the caller didn't supply
        // them, so EU registry payloads are complete. Read live from the operator
        // config so identifiers managed via the API/CLI apply without a restart.
        if let Some(reader) = &self.registry_reader {
            if passport.facility.is_none() {
                passport.facility = reader
                    .default_facility(STANDALONE_OPERATOR_ID)
                    .await
                    .unwrap_or(None);
            }
            if passport.operator_identifier.is_none() {
                // The passport stamps the identifier's value; its scheme is an
                // operator fact resolved at publish, where the registration is
                // built.
                passport.operator_identifier = reader
                    .primary_operator_identifier(STANDALONE_OPERATOR_ID)
                    .await
                    .unwrap_or(None)
                    .map(|(_scheme, value)| value);
            }
        }

        self.guard_component_graph(passport.id, &passport.component_refs)
            .await?;

        apply_compliance(&mut passport, &*self.compliance);
        apply_lint(&mut passport);

        let created = self.repo.create(passport).await?;

        let entry = AuditEntry::new(
            &created.id.to_string(),
            "created",
            &auth.user_id,
            None,
            Some(&PassportStatus::Draft.to_string()),
        );
        self.audit.append(entry).await?;

        // Event emitted after commit — failure is logged, not propagated.
        self.emit(
            event::subjects::PASSPORT_CREATED,
            serde_json::json!({
                "passportId": created.id.to_string(),
                "status": "draft",
            }),
        )
        .await;

        Ok(created)
    }

    /// Partial-update a draft passport.
    ///
    /// Rejects updates to non-`Draft` passports. Validates the patch, enriches
    /// compliance fields, writes only the changed fields to the DB (`patch_fields`),
    /// appends an audit entry, and emits `dpp.passport.updated`.
    #[tracing::instrument(skip(self, patch), fields(passport_id = %id))]
    pub async fn update(
        &self,
        id: PassportId,
        patch: serde_json::Value,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        let mut passport = self.find_by_id(id).await?;

        if !matches!(passport.status, PassportStatus::Draft) {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Draft.to_string(),
            });
        }

        // Validate the patch against a temporary copy, recording which fields
        // it actually applied, then build the delta from *those* — never from
        // the request body.
        let applied = apply_patch(&mut passport, &patch)?;
        self.guard_component_graph(id, &passport.component_refs)
            .await?;
        let pre_compliance_co2e = passport.co2e_per_unit.clone();
        let pre_compliance_repair = passport.repairability_score.clone();
        apply_compliance(&mut passport, &*self.compliance);
        apply_lint(&mut passport);

        let mut delta = delta_for(&passport, &applied);
        // Compliance-enriched values, added only when enrichment changed them.
        if passport.co2e_per_unit != pre_compliance_co2e
            && let Some(ref v) = passport.co2e_per_unit
        {
            delta.insert("co2ePerUnit".into(), serde_json::json!(v));
        }
        if passport.repairability_score != pre_compliance_repair
            && let Some(ref v) = passport.repairability_score
        {
            delta.insert("repairabilityScore".into(), serde_json::json!(v));
        }
        // Lint findings are cheap to recompute and always refreshed (unlike
        // co2e/repairability above, which only backfill when the caller left
        // them unset) — see PassportService::relint for the standalone re-check.
        if let Some(ref lint) = passport.lint_result {
            delta.insert("lintResult".into(), serde_json::json!(lint));
        }

        let updated = self
            .repo
            .patch_fields(id, serde_json::Value::Object(delta))
            .await?;

        let entry = AuditEntry::new(
            &updated.id.to_string(),
            "updated",
            &auth.user_id,
            None,
            None,
        );
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_UPDATED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": updated.status.to_string(),
            }),
        )
        .await;

        Ok(updated)
    }

    /// Gather the local component subgraph reachable from `seeds`, bounded to a
    /// fixed number of repo fetches. Returns `None` if the reachable graph is too
    /// large to fully gather — the caller then fails closed rather than approve a
    /// structure it could not fully check.
    async fn local_component_edges(&self, seeds: &[PassportId]) -> Option<ComponentEdges> {
        const MAX_GRAPH_NODES: usize = 256;
        let mut edges = ComponentEdges::new();
        let mut seen = HashSet::new();
        let mut stack = seeds.to_vec();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > MAX_GRAPH_NODES {
                return None;
            }
            // A ref that resolves to no local passport is another operator's —
            // its cycle safety is a verify-time concern, so treat it as a leaf.
            let Ok(Some(p)) = self.repo.find_by_id_any_status(id).await else {
                continue;
            };
            let children: Vec<PassportId> = p
                .component_refs
                .iter()
                .filter_map(|r| local_component_id(&r.uri))
                .collect();
            for &c in &children {
                stack.push(c);
            }
            edges.insert(id, children);
        }
        Some(edges)
    }

    /// Refuse `component_refs` that would close a cycle in — or overflow the
    /// depth of — the *local* component graph rooted at `parent`. Cross-operator
    /// refs (no resolvable local id) are cycle-checked at verify time, not here.
    async fn guard_component_graph(
        &self,
        parent: PassportId,
        component_refs: &[PassportRef],
    ) -> Result<(), DppError> {
        let local_children: Vec<PassportId> = component_refs
            .iter()
            .filter_map(|r| local_component_id(&r.uri))
            .collect();
        if local_children.is_empty() {
            return Ok(());
        }
        let edges = self
            .local_component_edges(&local_children)
            .await
            .ok_or_else(|| {
                DppError::Validation("componentRefs local graph too large to verify".into())
            })?;
        for &child in &local_children {
            check_edge(&edges, parent, child, DEFAULT_DEPTH_CAP).map_err(|e| match e {
                EdgeRejection::Cycle => DppError::Validation(
                    format!("componentRefs would create a cycle via passport {child}").into(),
                ),
                EdgeRejection::DepthExceeded => DppError::Validation(
                    format!("componentRefs exceed the maximum BOM depth of {DEFAULT_DEPTH_CAP}")
                        .into(),
                ),
            })?;
        }
        Ok(())
    }
}

/// Extract the local passport id a component ref points at, if its URI ends in a
/// UUID this node could hold. A ref to another operator simply won't resolve to
/// a local passport (the repo lookup returns `None`) and is treated as remote.
fn local_component_id(uri: &str) -> Option<PassportId> {
    let tail = uri.rsplit('/').next()?;
    let tail = tail.split(['?', '#']).next()?;
    Uuid::parse_str(tail).ok().map(PassportId)
}

fn apply_compliance(passport: &mut Passport, registry: &dyn ComplianceRegistry) {
    let Some(sector_data) = passport.sector_data.as_ref() else {
        return;
    };
    let sector = sector_data.sector();
    // The date the governing law attached to this product, read from its own
    // record. Never `Utc::now()`: a determination made against today's date is
    // wrong for every product not placed on the market today, and would change
    // its own answer as phase dates pass.
    let law_in_force_on = passport.placed_on_market_date;
    if let Ok(mut result) = registry.compute(sector.catalog_key(), sector_data, law_in_force_on) {
        // Backfill the two display metrics only when the caller didn't supply them.
        if passport.co2e_per_unit.is_none() {
            passport.co2e_per_unit = result.co2e_score.map(CarbonFootprint::from_kg);
        }
        if passport.repairability_score.is_none() {
            passport.repairability_score = result
                .repairability_index
                .map(RepairabilityScore::from_scalar);
        }
        // Persist the full determination (status, metrics, findings, receipt) on
        // the passport so it is part of the signed payload and queryable. Stamp
        // the assessment time if the registry didn't.
        if result.assessed_at.is_none() {
            result.assessed_at = Some(Utc::now());
        }
        passport.compliance_result = Some(result);
    }
}

/// Backfill `lint_result` from the `dpp-rules` plausibility lint pack.
/// Unlike `apply_compliance`, always overwrites — the pack is cheap to
/// re-run and freshness (not preserving a caller-supplied value) is the
/// point. A no-op when the passport carries no sector data.
fn apply_lint(passport: &mut Passport) {
    if let Some(sector_data) = passport.sector_data.as_ref() {
        passport.lint_result = Some(dpp_domain::LintResult::compute(sector_data));
    }
}

/// The only fields `PUT /dpp/{id}` may change, in the order they are applied.
///
/// This is an **allow-list**, and that is the point. The delta sent to
/// `patch_fields` used to be the caller's request body, with only the
/// repository's protected-field list standing between an arbitrary JSON key and
/// the stored document — so `facility`, `operatorIdentifier`, `commodityCode`
/// and `parentPassportRef` (modelled `Passport` fields, absent from that list)
/// were writable by any `write`-scope caller and rode into the signed publish
/// payload without ever meeting the validators that own them.
///
/// Naming what may change, rather than what may not, means a new `Passport`
/// field is immutable here by default. The old shape had the opposite default,
/// which is why four fields were writable without anyone deciding they should
/// be.
const PATCHABLE_FIELDS: [&str; 5] = [
    "productName",
    "co2ePerUnit",
    "repairabilityScore",
    "sectorData",
    "componentRefs",
];

/// Serialise exactly the `applied` fields out of the validated passport.
///
/// Reading from the passport rather than echoing the request body is what makes
/// the allow-list real: a value only reaches the database after `apply_patch`
/// has parsed it into its typed form and validated it, so an unparsed or
/// unvalidated value has no path here.
/// Iterating [`PATCHABLE_FIELDS`] and filtering by `applied` — rather than
/// iterating `applied` directly — makes the allow-list the thing that decides.
/// A name `apply_patch` returned but the list does not contain cannot produce a
/// delta entry, so the two would have to be wrong in the same way for a field to
/// slip through.
fn delta_for(passport: &Passport, applied: &[&'static str]) -> serde_json::Map<String, Value> {
    let mut delta = serde_json::Map::new();
    for field in PATCHABLE_FIELDS.iter().filter(|f| applied.contains(f)) {
        let value = match *field {
            "productName" => serde_json::json!(passport.product_name),
            "co2ePerUnit" => serde_json::json!(passport.co2e_per_unit),
            "repairabilityScore" => serde_json::json!(passport.repairability_score),
            "sectorData" => serde_json::json!(passport.sector_data),
            "componentRefs" => serde_json::json!(passport.component_refs),
            // Unreachable: `applied` only ever contains `PATCHABLE_FIELDS`
            // entries, and adding one there without a case here fails the
            // `every_patchable_field_serialises` test rather than silently
            // dropping the field.
            _ => continue,
        };
        delta.insert((*field).to_owned(), value);
    }
    delta
}

/// Apply the patch to `passport`, returning the fields it changed.
///
/// The returned list drives [`delta_for`]; a field the caller sent but this
/// function does not recognise is not applied and not returned, so it cannot
/// reach the database.
///
/// # Why unrecognised keys are ignored rather than refused
///
/// The integrator PUTs a full create-shaped body on its `update_draft` path
/// (`CreatePassportRequest`), which legitimately carries `sector`,
/// `manufacturer`, `batchId` and `schemaVersion` — fields that are fixed at
/// create by design. Refusing the request would break a real caller for sending
/// a shape it has always sent. What must not happen is those fields *taking
/// effect*, and building the delta from the allow-list is what prevents that.
fn apply_patch(
    passport: &mut Passport,
    patch: &serde_json::Value,
) -> Result<Vec<&'static str>, DppError> {
    let obj = match patch.as_object() {
        Some(o) => o,
        None => {
            return Err(DppError::Validation(
                "patch body must be a JSON object".into(),
            ));
        }
    };

    let mut applied = Vec::new();
    if let Some(v) = obj.get("productName").and_then(|v| v.as_str()) {
        passport.product_name = v.to_owned();
        applied.push("productName");
    }
    if let Some(v) = obj.get("co2ePerUnit").and_then(|v| v.as_f64()) {
        passport.co2e_per_unit = Some(CarbonFootprint::from_kg(v));
        applied.push("co2ePerUnit");
    }
    if let Some(v) = obj.get("repairabilityScore").and_then(|v| v.as_f64()) {
        passport.repairability_score = Some(RepairabilityScore::from_scalar(v));
        applied.push("repairabilityScore");
    }
    if let Some(v) = obj.get("sectorData") {
        let sector_data: SectorData = serde_json::from_value(v.clone())
            .map_err(|e| DppError::Validation(format!("invalid sectorData: {e}").into()))?;
        dpp_domain::validate_sector_data(&sector_data).map_err(DppError::Validation)?;
        passport.sector_data = Some(sector_data);
        applied.push("sectorData");
    }
    if let Some(v) = obj.get("componentRefs") {
        let refs: Vec<PassportRef> = serde_json::from_value(v.clone())
            .map_err(|e| DppError::Validation(format!("invalid componentRefs: {e}").into()))?;
        // Same shape check the create path applies: every ref is fetched
        // cross-operator at verify time, so an `http` or internal URI is a
        // target this node will refuse forever, and a malformed pin can never
        // match. Create validated these and update did not.
        for (i, r) in refs.iter().enumerate() {
            validate_component_ref(r, i).map_err(|e| DppError::Validation(e.into()))?;
        }
        passport.component_refs = refs;
        applied.push("componentRefs");
    }

    Ok(applied)
}

/// `https` + the SSRF shape guard on the URI, and a lowercase-hex SHA-256 pin —
/// the create path's `validate_passport_ref`, applied on update too.
fn validate_component_ref(r: &PassportRef, index: usize) -> Result<(), String> {
    dpp_common::url_guard::validate_public_https_url(&r.uri)
        .map_err(|e| format!("componentRefs[{index}].uri: {e}"))?;
    let pin = &r.public_jws_hash;
    if pin.len() != 64
        || !pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "componentRefs[{index}].publicJwsHash must be a lowercase hex SHA-256 digest"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_compliance, apply_patch};
    use chrono::Utc;
    use dpp_domain::{
        domain::{
            error::DppError,
            passport::{ManufacturerInfo, Passport, PassportId},
            sector::{Sector, SectorData},
            status::PassportStatus,
        },
        ports::compliance::{
            ComplianceError, ComplianceErrorKind, ComplianceRegistry, ComplianceResult,
        },
    };

    fn stub() -> Passport {
        Passport {
            id: PassportId::new(),
            batch_id: None,
            product_name: "Test".into(),
            sector: Sector::Battery,
            manufacturer: ManufacturerInfo {
                name: "ACME".into(),
                address: "1 Street".into(),
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
            operator_identifier: None,
            facility: None,
            seal: None,
        }
    }

    struct NoopRegistry;

    impl ComplianceRegistry for NoopRegistry {
        fn compute(
            &self,
            _: &str,
            _: &SectorData,
            _: Option<chrono::NaiveDate>,
        ) -> Result<ComplianceResult, ComplianceError> {
            Err(ComplianceError {
                kind: ComplianceErrorKind::UnknownSector,
                message: "noop".into(),
            })
        }
    }

    // ── apply_patch ──────────────────────────────────────────────────────────

    #[test]
    fn patch_non_object_returns_validation_error() {
        let mut p = stub();
        let err = apply_patch(&mut p, &serde_json::json!("not-an-object")).unwrap_err();
        assert!(matches!(err, DppError::Validation(_)));
    }

    // ── the allow-list ───────────────────────────────────────────────────────

    /// The finding this change exists for. `facility`, `operatorIdentifier`,
    /// `commodityCode` and `parentPassportRef` are modelled `Passport` fields
    /// that the repository's protected list did not cover, so a `write`-scope
    /// caller could set them through `PUT` — bypassing the **admin**-only routes
    /// and the GLN / LEI / tariff validators that own them — and they rode into
    /// the signed publish payload from there. `facility` in particular is a
    /// `Public`-tier field, so it reached the anonymous public view.
    #[test]
    fn registry_identity_fields_never_reach_the_delta() {
        let mut p = stub();
        let patch = serde_json::json!({
            "productName": "Legit",
            "facility": { "scheme": "gln", "value": "NOT-A-GLN", "name": "Anywhere" },
            "operatorIdentifier": "not-an-eori",
            "commodityCode": "not-a-tariff-code",
            "parentPassportRef": { "uri": "http://10.0.0.1/x", "publicJwsHash": "z" },
        });
        let applied = apply_patch(&mut p, &patch).expect("the recognised field applies");
        let delta = super::delta_for(&p, &applied);

        assert_eq!(delta.get("productName"), Some(&serde_json::json!("Legit")));
        for smuggled in [
            "facility",
            "operatorIdentifier",
            "commodityCode",
            "parentPassportRef",
        ] {
            assert!(
                !delta.contains_key(smuggled),
                "{smuggled} reached the database delta"
            );
        }
    }

    /// The delta is built from the *validated passport*, not echoed from the
    /// request — so a value only lands after `apply_patch` has parsed it into
    /// its typed form. Asserted via a float that round-trips through
    /// `CarbonFootprint` rather than being copied verbatim.
    #[test]
    fn the_delta_is_read_back_from_the_passport_not_the_request() {
        let mut p = stub();
        let applied = apply_patch(&mut p, &serde_json::json!({ "co2ePerUnit": 42.5 })).unwrap();
        let delta = super::delta_for(&p, &applied);
        assert_eq!(
            delta.get("co2ePerUnit"),
            Some(&serde_json::json!(p.co2e_per_unit)),
            "the delta must carry the typed value, not the raw request number"
        );
    }

    /// Every `PATCHABLE_FIELDS` entry must have a `delta_for` arm. Without this,
    /// adding a field to the allow-list and forgetting the match arm would drop
    /// it silently — an update that returns 200 and changes nothing.
    #[test]
    fn every_patchable_field_serialises() {
        let p = stub();
        for field in super::PATCHABLE_FIELDS {
            let delta = super::delta_for(&p, &[field]);
            assert!(
                delta.contains_key(field),
                "{field} is in PATCHABLE_FIELDS but delta_for has no arm for it"
            );
        }
    }

    /// A create-shaped body is what the integrator actually PUTs on its
    /// `update_draft` path, and `CreatePassportRequest` serialises `sector` and
    /// `schemaVersion` as explicit `null` (neither carries
    /// `skip_serializing_if`). Both are in the repository's protected list, and
    /// `contains_key` is true for a null value — so the old
    /// echo-the-request-body delta made that request fail with
    /// "cannot modify protected field(s): schemaVersion, sector" on **every**
    /// call. Building from the allow-list drops them before the repository sees
    /// them.
    #[test]
    fn a_create_shaped_body_no_longer_smuggles_null_protected_keys() {
        let mut p = stub();
        let patch = serde_json::json!({
            "productName": "Imported",
            "sector": serde_json::Value::Null,
            "schemaVersion": serde_json::Value::Null,
            "manufacturer": { "name": "ACME", "address": "1 Street" },
            "batchId": serde_json::Value::Null,
        });
        let applied = apply_patch(&mut p, &patch).unwrap();
        let delta = super::delta_for(&p, &applied);
        for protected in ["sector", "schemaVersion", "manufacturer", "batchId"] {
            assert!(!delta.contains_key(protected), "{protected} leaked");
        }
        assert_eq!(delta.len(), 1, "only productName should be written");
    }

    /// Create shape-checks every `componentRefs` URI against the SSRF guard and
    /// the pin format; update did not, so a ref pointing at an internal host or
    /// carrying a malformed pin could be stored and then signed at publish.
    #[test]
    fn component_refs_are_shape_checked_on_update_as_they_are_on_create() {
        let good = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut p = stub();
        assert!(
            apply_patch(
                &mut p,
                &serde_json::json!({ "componentRefs": [
                    { "uri": "https://id.example/dpp/a", "publicJwsHash": good }
                ]}),
            )
            .is_ok(),
            "a public https ref with a valid pin is accepted"
        );

        for bad in [
            serde_json::json!([{ "uri": "http://id.example/dpp/a", "publicJwsHash": good }]),
            serde_json::json!([{ "uri": "https://127.0.0.1/dpp/a", "publicJwsHash": good }]),
            serde_json::json!([{ "uri": "https://id.example/dpp/a", "publicJwsHash": "short" }]),
            serde_json::json!([{ "uri": "https://id.example/dpp/a", "publicJwsHash": good.to_uppercase() }]),
        ] {
            let mut p = stub();
            assert!(
                apply_patch(&mut p, &serde_json::json!({ "componentRefs": bad })).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn patch_updates_product_name() {
        let mut p = stub();
        apply_patch(&mut p, &serde_json::json!({"productName": "Updated"})).unwrap();
        assert_eq!(p.product_name, "Updated");
    }

    #[test]
    fn patch_updates_co2e_per_unit() {
        let mut p = stub();
        apply_patch(&mut p, &serde_json::json!({"co2ePerUnit": 42.5})).unwrap();
        assert_eq!(p.co2e_per_unit.as_ref().map(|cf| cf.value_kg), Some(42.5));
    }

    #[test]
    fn patch_updates_repairability_score() {
        let mut p = stub();
        apply_patch(&mut p, &serde_json::json!({"repairabilityScore": 7.5})).unwrap();
        assert_eq!(
            p.repairability_score.as_ref().map(|rs| rs.overall),
            Some(7.5)
        );
    }

    #[test]
    fn patch_invalid_sector_data_returns_validation_error() {
        let mut p = stub();
        let err = apply_patch(
            &mut p,
            &serde_json::json!({"sectorData": {"type": "unknown", "garbage": true}}),
        )
        .unwrap_err();
        assert!(matches!(err, DppError::Validation(_)));
    }

    #[test]
    fn patch_empty_object_is_noop() {
        let mut p = stub();
        p.product_name = "Before".into();
        apply_patch(&mut p, &serde_json::json!({})).unwrap();
        assert_eq!(p.product_name, "Before");
    }

    // ── apply_compliance ─────────────────────────────────────────────────────

    #[test]
    fn no_sector_data_is_noop() {
        let mut p = stub(); // sector_data is None → early return
        apply_compliance(&mut p, &NoopRegistry);
        assert!(p.co2e_per_unit.is_none());
        assert!(p.repairability_score.is_none());
    }

    #[test]
    fn local_component_id_parses_only_a_trailing_uuid() {
        use super::local_component_id;
        let u = uuid::Uuid::now_v7();
        assert_eq!(
            local_component_id(&format!("https://id.odal-node.io/dpp/{u}")).map(|p| p.0),
            Some(u)
        );
        // Query/fragment are stripped before parsing.
        assert_eq!(
            local_component_id(&format!("https://id.odal-node.io/dpp/{u}?v=1")).map(|p| p.0),
            Some(u)
        );
        // A non-UUID tail (another operator's opaque URL) resolves to no local id.
        assert!(local_component_id("https://id.other.example/dpp/opaque-slug").is_none());
        assert!(local_component_id("").is_none());
    }
}
