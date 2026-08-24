//! The typed request shape row validators produce, and the error they report.

use dpp_domain::domain::{
    passport::{ManufacturerInfo, MaterialEntry},
    product_group::{ProductGroup, ProductGroupData},
};
use serde::Serialize;

/// Row-level validation error returned to the caller.
#[derive(Debug, Clone)]
pub struct RowError {
    pub row: usize,
    pub field: String,
    pub message: String,
}

/// Serialisable request body sent to `POST /api/v1/dpp` on the vault service.
///
/// Shape must match `dpp-vault::handlers::create::CreateRequest`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportRequest {
    pub product_name: String,
    /// EU ESPR product group (dispatch key). The vault also derives it from `productGroupData`.
    pub product_group: Option<ProductGroup>,
    pub manufacturer: ManufacturerInfo,
    /// Bill of materials parsed from `material_N_*` columns. The vault stores
    /// these on the passport; they are not silently dropped at import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materials: Option<Vec<MaterialEntry>>,
    pub co2e_per_unit: Option<f64>,
    pub repairability_score: Option<f64>,
    pub product_group_data: Option<ProductGroupData>,
    pub batch_id: Option<String>,
    pub schema_version: Option<String>,
    /// The date the product was placed on the EU market.
    ///
    /// **The one field whose absence changes what the passport means.** Every
    /// other omission here loses data; this one loses the *governing law*. Staged
    /// EU obligations attach at placing on the market and do not move afterwards,
    /// so a determination computed without it is computed against the wrong date
    /// for every product not placed on the market today — and the set of
    /// applicable instruments recorded at creation is frozen at this moment too.
    ///
    /// It was absent from this shape while the vault's own create route accepted
    /// it, which made bulk import a quietly lossier path to the same endpoint:
    /// the same product, imported rather than posted, got a passport that could
    /// not say which law applied to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placed_on_market_date: Option<chrono::NaiveDate>,
}
