//! [`CreatePassportRequest`] — the body of `POST /vault/api/v1/dpp`.

use dpp_domain::passport::{ManufacturerInfo, MaterialEntry, PassportRef};
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
/// column cannot express a cross-operator passport reference — `parentPassportRef`
/// and `componentRefs` each carry a URI *and* a hash of the referenced passport's
/// public signature, and inventing either would produce a link that fails
/// verification. Those stay `None`/empty on the import path, and that is a
/// property of CSV, not an oversight.
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
    /// Cross-operator predecessor this passport derives from (second-life
    /// successor linkage). Shape-validated on receipt; the hash is checked
    /// against the fetched parent at verify time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_passport_ref: Option<PassportRef>,
    /// Cross-operator references to this product's constituent passports (its
    /// bill of materials). Shape-validated on receipt; local cycles and
    /// over-depth are refused by the service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_refs: Vec<PassportRef>,
}
