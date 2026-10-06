//! [`CreatePassportRequest`] — the body of `POST /vault/api/v1/dpp`.

use dpp_domain::passport::{ComponentRef, DerivationRef, ManufacturerInfo, MaterialEntry};
use dpp_domain::product_group::{ProductGroup, ProductGroupData};
use serde::{Deserialize, Serialize};

/// The request body for passport creation, as **one** type.
///
/// # Why it lives here rather than beside the handler
///
/// Two services sit on either end of this shape: the vault deserialises it from
/// an inbound body, and the bulk importer serialises it into an outbound one.
/// They held **separate structs** kept in step by a comment reading "Shape must
/// match …", which is not a mechanism — it is a note, and a note cannot fail a
/// build.
///
/// It did not hold. The importer's copy was missing four fields the vault
/// accepted, and one of them was `placedOnMarketDate` — the regulated event that
/// fixes which law governs a product, and the moment its applicable-instrument
/// set is frozen. The same product imported rather than posted got a passport
/// that could not say what it was issued under. Nothing failed; the field simply
/// was not there to send.
///
/// One type makes that class of gap unrepresentable: a field the vault accepts is
/// a field the importer has to decide about, because it will not compile
/// otherwise.
///
/// # What the importer still cannot fill
///
/// Sharing the type does not mean every field arrives from a spreadsheet. A CSV
/// column cannot express a cross-operator passport reference — `derivedFrom`
/// and `componentRefs` each carry a URI *and* a hash of the referenced passport's
/// public signature, and inventing either would produce a link that fails
/// verification. Those stay empty on the import path, and that is a property of
/// CSV, not an oversight.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportRequest {
    pub product_name: String,
    /// EU ESPR product group (dispatch key). Optional — derived from
    /// `productGroupData` when omitted.
    pub product_group: Option<ProductGroup>,
    pub manufacturer: ManufacturerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materials: Option<Vec<MaterialEntry>>,
    pub co2e_per_unit: Option<f64>,
    pub repairability_score: Option<f64>,
    pub product_group_data: Option<ProductGroupData>,
    pub batch_id: Option<String>,
    /// The date this product was placed on the EU market — the regulated
    /// triggering event that fixes which law governs it.
    ///
    /// Optional, and omitting it is not neutral: a determination that depends on
    /// a phase date has no answer without it, and the node will not substitute
    /// today's date to produce one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placed_on_market_date: Option<chrono::NaiveDate>,
    pub schema_version: Option<String>,
    /// Customs tariff classification — HS-6, CN-8 or TARIC-10 digits.
    /// Registration data the EU registry stores and range-checks per product
    /// group. Optional: the regulation qualifies it "where relevant".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commodity_code: Option<String>,
    /// The passport this one replaces, if it is a new version of an existing
    /// record.
    ///
    /// Declared at create because `supersedesId` is a protected field: it is set
    /// by the write that creates the whole record, never by a field patch, so
    /// this is the only request that can carry it. Declaring it here also puts
    /// it where the operator actually knows it — they are creating *this*
    /// passport because it replaces *that* one.
    ///
    /// Recording the link does not retire anything. The predecessor is retired
    /// by `POST /dpp/{predecessorId}/supersede` once this successor is
    /// published, and that route checks the two agree.
    ///
    /// Not the same field `amend` writes. `amend` sets `supersedesId` itself on
    /// a successor it mints from a patch; this is for a successor created
    /// independently, which `amend` cannot express.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<dpp_domain::passport::PassportId>,

    /// Cross-operator predecessors this passport derives from (second-life
    /// successor linkage), each naming the Art. 77(7) operation that produced
    /// this unit from it. Shape-validated on receipt; the hash is checked
    /// against the fetched predecessor at verify time.
    ///
    /// A list, and not the single `parentPassportRef` it replaces, because
    /// Art. 77(7) is plural on both sides — one second-life unit may derive from
    /// several predecessors. The operation is required per entry: the article
    /// attaches different consequences to each, so an edge that does not say
    /// which one occurred records less than it asks for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<DerivationRef>,
    /// Where this unit sits in its **product** life — Annex XIII point 4(c) of
    /// Reg. (EU) 2023/1542.
    ///
    /// Orthogonal to the publication lifecycle: a `repurposed` unit's passport
    /// is `Published` like any other. `None` where the product group does not
    /// call for one, which is every group but battery — only Reg. (EU) 2023/1542
    /// defines this vocabulary, and a textile passport asserting `original`
    /// would be borrowing a battery term for a question its own instrument does
    /// not ask.
    ///
    /// # Why this is a create-time field and not a transition
    ///
    /// Art. 77(7) makes each operation produce a **new** passport, so a
    /// repurposed unit is *created* as `repurposed` with a `derivedFrom` edge
    /// naming the operation that produced it. There is nothing to transition:
    /// the predecessor keeps its own record and its own status.
    ///
    /// It is also the only way to set it. `lifeStatus` is in core's
    /// `PROTECTED_PATCH_FIELDS`, so `PATCH` refuses it — deliberately, because
    /// the field is part of a body that gets signed, and rewriting it after
    /// publication would change what a proof covers.
    ///
    /// 🚨 `waste` is **not** accepted here. It is the one value that happens to a
    /// record which continues, and under Art. 77(7)'s second subparagraph it is
    /// also a responsibility handover — so it belongs to a versioning event with
    /// an audit trail rather than to the creation of a fresh record. Creating a
    /// passport that is already waste would record the end of a life this node
    /// never saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub life_status: Option<dpp_domain::passport::LifeStatus>,
    /// Cross-operator references to this product's constituent passports (its
    /// bill of materials), each optionally qualified by how much of it the
    /// assembly contains and in what role. Shape-validated on receipt; local
    /// cycles and over-depth are refused by the service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_refs: Vec<ComponentRef>,
    /// The serial this passport's GS1 data carrier prints in AI 21, attributed by
    /// the operator.
    ///
    /// Omitted, the carrier prints a default derived from the passport id. An
    /// operator that already serialises its units states that serial here, so the
    /// printed label names the passport under the serial the unit already
    /// carries. Art. 77(3) of Reg. (EU) 2023/1542 puts the choice of this
    /// identifier on the economic operator.
    ///
    /// One to twenty characters of the GS1 CSET 82 set, which is how AI 21 is
    /// defined. Only a passport identified by a GTIN has a GS1 carrier, so the
    /// field is refused on any other.
    ///
    /// Not the manufacturer's `serialNumber`, though an operator may state the
    /// same value for both. Nothing copies one into the other.
    ///
    /// Create-time only. `carrierSerial` is in core's `PROTECTED_PATCH_FIELDS`, so
    /// no update reaches it, and the carrier is stamped at publish. An amendment
    /// carries it forward.
    ///
    /// Unique under its GTIN: a label that names two unrelated passports resolves
    /// to neither, so a serial another passport already holds is refused unless
    /// that passport is the one this replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_serial: Option<String>,
}

/// Why `serial` cannot be printed in AI 21 of a GS1 carrier, or `None` when it can.
///
/// The rule is core's (`dpp_rules::common::identifier::check_gs1_serial`), which
/// `Passport::validate` applies when the passport is written. This is the same
/// rule with a sentence attached, so the create route and the bulk importer say
/// the same thing about the same value, and the importer can name the row. Core
/// words it too, but privately; two copies of the wording are two things that can
/// drift, so there is one here.
#[must_use]
pub fn carrier_serial_problem(serial: &str) -> Option<String> {
    use dpp_rules::common::identifier::{
        Gs1ValueRejection, MAX_GS1_SERIAL_CHARS, check_gs1_serial,
    };

    check_gs1_serial(serial)
        .err()
        .map(|rejection| match rejection {
            Gs1ValueRejection::Empty => "must not be empty".to_owned(),
            Gs1ValueRejection::TooLong { chars } => {
                format!("has {chars} characters; GS1 AI 21 allows at most {MAX_GS1_SERIAL_CHARS}")
            }
            Gs1ValueRejection::OutsideCset82(c) => {
                format!("contains {c:?}, which is outside GS1 CSET 82")
            }
        })
}

#[cfg(test)]
mod carrier_serial_tests {
    use super::carrier_serial_problem;

    /// What GS1 admits in AI 21: one to twenty characters of CSET 82. Letters,
    /// digits and a handful of punctuation marks, but no space.
    #[test]
    fn what_ai_21_admits_is_accepted() {
        for ok in ["1", "SN-2026-0001", "a/b.c_d", &"X".repeat(20)] {
            assert_eq!(carrier_serial_problem(ok), None, "{ok}");
        }
    }

    #[test]
    fn what_ai_21_refuses_is_named() {
        assert_eq!(
            carrier_serial_problem("").as_deref(),
            Some("must not be empty")
        );
        assert!(
            carrier_serial_problem(&"X".repeat(21))
                .is_some_and(|p| p.contains("21 characters") && p.contains("at most 20"))
        );
        // The first character outside the set is the one named, and a space is
        // outside it.
        assert!(carrier_serial_problem("SN 1").is_some_and(|p| p.contains("' '")));
        assert!(carrier_serial_problem("SN#1").is_some_and(|p| p.contains("'#'")));
    }
}
