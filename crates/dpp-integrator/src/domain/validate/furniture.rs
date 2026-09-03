//! Furniture row validation.

use std::collections::HashMap;

use dpp_domain::{
    passport::ManufacturerInfo,
    product_group::{FurnitureData, ProductGroup, ProductGroupData},
};

use crate::domain::fields::{
    optional_commodity_code, optional_date, optional_f64, optional_str, parse_gtin, require_str,
};
use crate::domain::request::{CreatePassportRequest, RowError};

use super::Column;

/// The columns this validator reads, in template order. Envelope columns
/// (`placedOnMarketDate`, `commodityCode`) are appended by `columns_for`.
pub(super) const COLUMNS: &[Column] = &[
    Column::required("productName"),
    Column::required("gtin"),
    Column::optional("batchId"),
    Column::required("manufacturerName"),
    Column::required("manufacturerCountry"),
    Column::required("productType"),
    Column::required("primaryMaterial"),
    Column::required("countryOfOrigin"),
    Column::optional("recycledContentPct"),
    Column::optional("repairabilityScore"),
    Column::optional("co2ePerUnitKg"),
    Column::optional("disassemblyInstructionsUrl"),
    Column::optional("endOfLifeInstructions"),
];

/// Validate a single furniture row and convert it to a vault
/// `CreatePassportRequest`.
pub fn validate_furniture_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
    let batch_id = optional_str(row, "batchId");
    let manufacturer_name = require_str(row, "manufacturerName", row_num, &mut errors);
    let manufacturer_country = require_str(row, "manufacturerCountry", row_num, &mut errors);
    let gtin_raw = require_str(row, "gtin", row_num, &mut errors);
    let gtin = parse_gtin(gtin_raw.as_deref(), row_num, &mut errors);
    let product_type = require_str(row, "productType", row_num, &mut errors);
    let primary_material = require_str(row, "primaryMaterial", row_num, &mut errors);
    let country_of_origin = require_str(row, "countryOfOrigin", row_num, &mut errors);
    let recycled = optional_f64(row, "recycledContentPct", row_num, &mut errors);
    let repairability = optional_f64(row, "repairabilityScore", row_num, &mut errors);
    let co2e_per_unit_kg = optional_f64(row, "co2ePerUnitKg", row_num, &mut errors);
    let disassembly = optional_str(row, "disassemblyInstructionsUrl");
    let end_of_life = optional_str(row, "endOfLifeInstructions");

    // Envelope-level, so every product group reads them from the same columns.
    let placed_on_market_date = optional_date(row, "placedOnMarketDate", row_num, &mut errors);
    let commodity_code = optional_commodity_code(row, "commodityCode", row_num, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        product_group: Some(ProductGroup::Furniture),
        manufacturer: ManufacturerInfo {
            name: manufacturer_name
                .expect("field verified present by errors.is_empty() guard above"),
            address: manufacturer_country
                .expect("field verified present by errors.is_empty() guard above"),
            did_web_url: None,
        },
        materials: None,
        co2e_per_unit: None,
        repairability_score: None,
        product_group_data: Some(ProductGroupData::Furniture(FurnitureData {
            gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
            product_type: product_type
                .expect("field verified present by errors.is_empty() guard above"),
            primary_material: primary_material
                .expect("field verified present by errors.is_empty() guard above"),
            country_of_origin: country_of_origin
                .expect("field verified present by errors.is_empty() guard above"),
            recycled_content_pct: recycled,
            repairability_score: repairability,
            co2e_per_unit_kg,
            svhc_substances: None,
            disassembly_instructions_url: disassembly,
            end_of_life_instructions: end_of_life,
        })),
        batch_id,
        schema_version: None,
        placed_on_market_date,
        commodity_code,
        // A CSV cannot express these: each carries a URI *and* a hash of the
        // referenced passport's public signature, and a hash cannot be authored
        // by hand — an invented one produces a link that fails verification.
        // Absent because the format cannot carry them, not by oversight.
        parent_passport_ref: None,
        component_refs: Vec::new(),
    })
}
