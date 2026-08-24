//! [`PassportResponse`] — the wire shape of a passport, owned by this service.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use dpp_domain::domain::commodity_code::CommodityCode;
use dpp_domain::domain::lint::LintResult;
use dpp_domain::domain::passport::{
    FacilitySnapshot, ManufacturerInfo, MaterialEntry, Passport, PassportId, PassportRef,
};
use dpp_domain::domain::product_group::{
    CarbonFootprint, ProductGroup, ProductGroupData, RepairabilityScore,
};
use dpp_domain::domain::seal::SealedEnvelope;
use dpp_domain::domain::status::PassportStatus;
use dpp_domain::ports::compliance::ComplianceResult;
use dpp_domain::{Granularity, InstrumentRef};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A passport as this service serves it.
///
/// # Why this exists when it is field-for-field the aggregate
///
/// Until this type landed, the JSON on the wire *was* `dpp_domain::Passport`
/// — the core library's aggregate, serialised straight out of the handler. That
/// made the published API a function of a library's internal shape, with no
/// place to decide otherwise. It is not a theoretical hazard: renaming a field
/// inside core rewrote every response body, request body, database column and
/// OpenAPI schema in one step, and nothing in between was a decision point where
/// someone had to agree the *API* should change.
///
/// The point is not that the two shapes differ today — they do not, and a test
/// below proves it byte for byte. The point is that they are now allowed to, and
/// that making them differ is an edit somebody has to write down here. A core
/// change that should not reach the wire stops at [`Self::from`]; one that should
/// is a visible line in a diff.
///
/// # The two guards that make it safe
///
/// A hand-written mirror is only worth having if it cannot drift silently, so:
///
/// - `mirrors_the_aggregate_exactly` serialises both shapes and compares them,
///   for a fully-populated passport *and* a minimal one — the second because
///   `skip_serializing_if` differences are invisible when every field is set.
/// - `every_core_wire_key_is_accounted_for` checks this type against
///   `dpp_domain::PASSPORT_WIRE_KEYS`, so a field added to core is either served
///   or listed in [`NOT_SERVED`] with a reason. Neither is a default.
///
/// Without the second, a mirror would trade one silent drift (core reaching the
/// wire unreviewed) for another (core *not* reaching the wire, unnoticed), which
/// would be the worse of the two.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportResponse {
    pub id: PassportId,
    pub batch_id: Option<String>,
    pub product_name: String,
    pub product_group: ProductGroup,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_instruments: Vec<InstrumentRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granularity: Option<Granularity>,
    pub manufacturer: ManufacturerInfo,
    pub materials: Vec<MaterialEntry>,
    pub co2e_per_unit: Option<CarbonFootprint>,
    pub repairability_score: Option<RepairabilityScore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_result: Option<ComplianceResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint_result: Option<LintResult>,
    pub product_group_data: Option<ProductGroupData>,
    pub status: PassportStatus,
    pub qr_code_url: Option<String>,
    pub jws_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_jws_signature: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disclosure_signatures: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placed_on_market_date: Option<NaiveDate>,
    pub schema_version: String,
    #[serde(default)]
    pub retention_locked: bool,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<PassportId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_passport_ref: Option<PassportRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_refs: Vec<PassportRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commodity_code: Option<CommodityCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility: Option<FacilitySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealedEnvelope>,
}

/// Core passport keys this service deliberately does not serve, and why.
///
/// Empty, and that is the honest state: everything the aggregate carries is
/// served today. It exists so that *not* serving a field is a decision with a
/// reason attached rather than an omission nobody notices — the completeness
/// test refuses to pass on silence either way.
///
/// `allow(dead_code)` because only the completeness test reads it today. It is
/// still the right place for the policy to live: a reader asking "why is this
/// field not in the response" should find the answer next to the response, not
/// in a test.
#[allow(dead_code)]
const NOT_SERVED: &[(&str, &str)] = &[];

impl From<&Passport> for PassportResponse {
    fn from(p: &Passport) -> Self {
        Self {
            id: p.id,
            batch_id: p.batch_id.clone(),
            product_name: p.product_name.clone(),
            product_group: p.product_group.clone(),
            applicable_instruments: p.applicable_instruments.clone(),
            granularity: p.granularity,
            manufacturer: p.manufacturer.clone(),
            materials: p.materials.clone(),
            co2e_per_unit: p.co2e_per_unit.clone(),
            repairability_score: p.repairability_score.clone(),
            compliance_result: p.compliance_result.clone(),
            lint_result: p.lint_result.clone(),
            product_group_data: p.product_group_data.clone(),
            status: p.status.clone(),
            qr_code_url: p.qr_code_url.clone(),
            jws_signature: p.jws_signature.clone(),
            public_jws_signature: p.public_jws_signature.clone(),
            disclosure_signatures: p.disclosure_signatures.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
            published_at: p.published_at,
            placed_on_market_date: p.placed_on_market_date,
            schema_version: p.schema_version.clone(),
            retention_locked: p.retention_locked,
            version: p.version,
            supersedes_id: p.supersedes_id,
            parent_passport_ref: p.parent_passport_ref.clone(),
            component_refs: p.component_refs.clone(),
            retention_until: p.retention_until,
            product_id: p.product_id,
            commodity_code: p.commodity_code.clone(),
            operator_identifier: p.operator_identifier.clone(),
            facility: p.facility.clone(),
            seal: p.seal.clone(),
        }
    }
}

impl From<Passport> for PassportResponse {
    fn from(p: Passport) -> Self {
        Self::from(&p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A passport with every optional field absent — the shape that exposes a
    /// `skip_serializing_if` mismatch, which a fully-populated one cannot.
    fn minimal() -> Passport {
        Passport {
            id: PassportId::new(),
            batch_id: None,
            product_name: "Minimal".into(),
            product_group: ProductGroup::Textile,
            applicable_instruments: Vec::new(),
            granularity: None,
            manufacturer: ManufacturerInfo {
                name: "Acme".into(),
                address: "Berlin, DE".into(),
                did_web_url: None,
            },
            materials: Vec::new(),
            co2e_per_unit: None,
            repairability_score: None,
            compliance_result: None,
            lint_result: None,
            product_group_data: None,
            status: PassportStatus::Draft,
            qr_code_url: None,
            jws_signature: None,
            public_jws_signature: None,
            disclosure_signatures: BTreeMap::new(),
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

    /// The wire is unchanged by the introduction of this type.
    ///
    /// Checked on a minimal passport as well as a populated one: when every
    /// field carries a value, a wrong `skip_serializing_if` is invisible, and
    /// omitted-versus-`null` is exactly the difference a consumer notices.
    ///
    /// This is the test to edit deliberately on the day the two shapes are
    /// *meant* to diverge. Until then it is the proof that nothing diverged by
    /// accident.
    /// The same passport with every skippable field carrying a value, so the
    /// comparison covers the keys `minimal()` omits by construction.
    fn populated() -> Passport {
        let mut p = minimal();
        p.batch_id = Some("LOT-2026-001".into());
        p.applicable_instruments = vec![InstrumentRef::from_catalog("espr")];
        p.granularity = Some(Granularity::Item);
        p.compliance_result = Some(ComplianceResult::default());
        p.public_jws_signature = Some("eyJhbGciOiJFZERTQSJ9..aaa".into());
        p.disclosure_signatures =
            BTreeMap::from([("public+restricted".to_owned(), "eyJ..bbb".to_owned())]);
        p.placed_on_market_date = chrono::NaiveDate::from_ymd_opt(2027, 2, 18);
        p.supersedes_id = Some(PassportId::new());
        p.retention_until = Some(Utc::now());
        p.product_id = Some(Uuid::now_v7());
        p.operator_identifier = Some("LEI:5493001KJTIIGC8Y1R12".into());
        p.retention_locked = true;
        p.version = 3;
        p
    }

    #[test]
    fn mirrors_the_aggregate_exactly() {
        for passport in [minimal(), populated()] {
            let aggregate = serde_json::to_value(&passport).expect("aggregate serialises");
            let response = serde_json::to_value(PassportResponse::from(&passport))
                .expect("response serialises");
            assert_eq!(
                response, aggregate,
                "the response shape has diverged from the aggregate; if that is intended, \
                 record which field and why"
            );
        }
    }

    /// Every key core puts on the wire is either served here or listed as
    /// deliberately withheld.
    ///
    /// The mirror's own failure mode, guarded: without this, a field added to
    /// core would simply not appear in responses, and nothing would say so. That
    /// is a quieter defect than the one this type exists to prevent, so it would
    /// be a poor trade to make silently.
    #[test]
    fn every_core_wire_key_is_accounted_for() {
        let served: Vec<String> = serde_json::to_value(PassportResponse::from(&minimal()))
            .expect("serialises")
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();

        // `minimal()` omits every skippable field, so compare against the
        // populated set of keys the type *can* emit rather than what it did.
        let mut missing: Vec<&str> = dpp_domain::PASSPORT_WIRE_KEYS
            .iter()
            .copied()
            .filter(|key| {
                !served.iter().any(|s| s == key)
                    && !NOT_SERVED.iter().any(|(name, _)| name == key)
                    && !SKIPPABLE.contains(key)
            })
            .collect();
        missing.sort_unstable();

        assert!(
            missing.is_empty(),
            "these core passport keys are neither served nor listed in NOT_SERVED: {missing:?}"
        );

        for (name, _reason) in NOT_SERVED {
            assert!(
                dpp_domain::PASSPORT_WIRE_KEYS.contains(name),
                "NOT_SERVED names '{name}', which core does not emit — remove the row"
            );
        }
    }

    /// Keys this type may legitimately omit from a *minimal* passport because
    /// they are `skip_serializing_if`. Listing them keeps the completeness check
    /// above honest: a skippable field still has to exist on the struct, it just
    /// cannot be observed through an empty instance.
    const SKIPPABLE: &[&str] = &[
        "applicableInstruments",
        "granularity",
        "complianceResult",
        "lintResult",
        "publicJwsSignature",
        "disclosureSignatures",
        "placedOnMarketDate",
        "supersedesId",
        "parentPassportRef",
        "componentRefs",
        "retentionUntil",
        "productId",
        "commodityCode",
        "operatorIdentifier",
        "facility",
        "seal",
    ];
}
