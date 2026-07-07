//! The typed request shape row validators produce, and the error they report.

use dpp_domain::domain::{
    passport::{ManufacturerInfo, MaterialEntry},
    sector::{Sector, SectorData},
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
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportRequest {
    pub product_name: String,
    /// EU ESPR sector (dispatch key). The vault also derives it from `sectorData`.
    pub sector: Option<Sector>,
    pub manufacturer: ManufacturerInfo,
    /// Bill of materials parsed from `material_N_*` columns. The vault stores
    /// these on the passport; they are not silently dropped at import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materials: Option<Vec<MaterialEntry>>,
    pub co2e_per_unit: Option<f64>,
    pub repairability_score: Option<f64>,
    pub sector_data: Option<SectorData>,
    pub batch_id: Option<String>,
    pub schema_version: Option<String>,
}
