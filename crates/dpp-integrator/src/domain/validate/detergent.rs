//! Detergent row validation.

use std::collections::HashMap;

use dpp_domain::{
    passport::ManufacturerInfo,
    product_group::{DetergentData, ProductGroup, ProductGroupData, SurfactantEntry},
};

use crate::domain::fields::{
    optional_bool, optional_carrier_serial, optional_commodity_code, optional_date, optional_f64,
    optional_str, parse_gtin, require_str,
};
use crate::domain::request::{CreatePassportRequest, RowError};

use super::Column;

/// The columns this validator reads, in template order. Envelope columns
/// (`placedOnMarketDate`, `commodityCode`, `carrierSerial`) are appended by `columns_for`.
pub(super) const COLUMNS: &[Column] = &[
    Column::required("productName"),
    Column::required("gtin"),
    Column::optional("batchId"),
    Column::required("manufacturerName"),
    Column::required("manufacturerCountry"),
    Column::required("productType"),
    Column::required("format"),
    Column::required("surfactants"),
    Column::required("countryOfOrigin"),
    Column::optional("co2ePerUnitKg"),
    Column::optional("packagingRecyclable"),
    Column::optional("recommendedDosageMl"),
    Column::optional("biodegradable"),
];

/// Validate a single detergent row and convert it to a vault
/// `CreatePassportRequest`.
pub fn validate_detergent_row(
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
    let format = require_str(row, "format", row_num, &mut errors);
    let country_of_origin = require_str(row, "countryOfOrigin", row_num, &mut errors);

    // surfactants is a JSON array string, the convention textile's
    // `fibreComposition` already uses for a variable-length list in one cell.
    let surfactants_str = require_str(row, "surfactants", row_num, &mut errors);
    let surfactants: Option<Vec<SurfactantEntry>> = surfactants_str.as_deref().and_then(|s| {
        match serde_json::from_str::<Vec<SurfactantEntry>>(s) {
            Ok(list) => {
                if let Err(msg) = dpp_domain::validate_surfactants(&list) {
                    errors.push(RowError {
                        row: row_num,
                        field: "surfactants".into(),
                        message: msg,
                    });
                }
                Some(list)
            }
            Err(e) => {
                errors.push(RowError {
                    row: row_num,
                    field: "surfactants".into(),
                    message: format!("Invalid JSON: {e}"),
                });
                None
            }
        }
    });

    let co2e_per_unit_kg = optional_f64(row, "co2ePerUnitKg", row_num, &mut errors);
    let packaging_recyclable = optional_bool(row, "packagingRecyclable", row_num, &mut errors);
    let recommended_dosage_ml = optional_f64(row, "recommendedDosageMl", row_num, &mut errors);
    let biodegradable = optional_bool(row, "biodegradable", row_num, &mut errors);

    // Envelope-level, so every product group reads them from the same columns.
    let placed_on_market_date = optional_date(row, "placedOnMarketDate", row_num, &mut errors);
    let commodity_code = optional_commodity_code(row, "commodityCode", row_num, &mut errors);
    let carrier_serial = optional_carrier_serial(row, "carrierSerial", row_num, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        product_group: Some(ProductGroup::Detergent),
        manufacturer: ManufacturerInfo {
            name: manufacturer_name
                .expect("field verified present by errors.is_empty() guard above"),
            // This template collects a country and no postal address, so
            // `address` carries the country — as it did before `country`
            // existed. Kept populated because `address` is required and the
            // create route refuses an empty one; the gap is the template's, not
            // this mapping's. The country now also reaches the field that can
            // actually be checked against ISO 3166-1.
            address: manufacturer_country
                .clone()
                .expect("field verified present by errors.is_empty() guard above"),
            registered_trade_name: None,
            electronic_address: None,
            country: manufacturer_country,
            did_web_url: None,
        },
        materials: None,
        co2e_per_unit: None,
        repairability_score: None,
        product_group_data: Some(ProductGroupData::Detergent(DetergentData {
            product_identifier: dpp_domain::identifier::ProductIdentifier::gs1(
                gtin.expect("field verified present by errors.is_empty() guard above"),
            ),
            product_type: product_type
                .expect("field verified present by errors.is_empty() guard above"),
            format: format.expect("field verified present by errors.is_empty() guard above"),
            surfactants: surfactants
                .expect("field verified present by errors.is_empty() guard above"),
            country_of_origin: country_of_origin
                .expect("field verified present by errors.is_empty() guard above"),
            co2e_per_unit_kg,
            packaging_recyclable,
            recommended_dosage_ml,
            biodegradable,
        })),
        batch_id,
        schema_version: None,
        placed_on_market_date,
        commodity_code,
        carrier_serial,
        // An import creates originals, never replacements: a successor is
        // declared deliberately by whoever knows what it replaces.
        supersedes_id: None,
        // A CSV cannot express these: each carries a URI *and* a hash of the
        // referenced passport's public signature, and a hash cannot be authored
        // by hand — an invented one produces a link that fails verification.
        // Absent because the format cannot carry them, not by oversight.
        derived_from: Vec::new(),
        // Empty for the same reason `derived_from` above is. A CSV column
        // cannot express a cross-operator predecessor, and core's lineage rule
        // asks that a status be supported by a derivation edge — so an
        // imported `repurposed` would be exactly the defect that rule catches.
        life_status: None,
        personal_data: Default::default(),
        component_refs: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detergent_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "Eco Laundry Liquid 1L".into()),
            ("gtin".into(), "09506000134352".into()),
            ("manufacturerName".into(), "Sample Clean BV".into()),
            ("manufacturerCountry".into(), "NL".into()),
            ("productType".into(), "laundry".into()),
            ("format".into(), "liquid".into()),
            ("countryOfOrigin".into(), "NL".into()),
            (
                "surfactants".into(),
                r#"[{"name":"Sodium laureth sulfate","biodegradable":true,"concentrationBand":"5-15%"}]"#
                    .into(),
            ),
        ])
    }

    #[test]
    fn empty_row_detergent_returns_err() {
        assert!(validate_detergent_row(&HashMap::new(), 1).is_err());
    }

    #[test]
    fn valid_detergent_row_produces_request() {
        let req = validate_detergent_row(&detergent_row(), 1).expect("valid detergent row");
        assert_eq!(req.product_group, Some(ProductGroup::Detergent));
        assert_eq!(req.manufacturer.country.as_deref(), Some("NL"));
        assert_eq!(req.manufacturer.address, "NL");
        match req.product_group_data.unwrap() {
            ProductGroupData::Detergent(d) => {
                assert_eq!(d.product_identifier.as_str(), "09506000134352");
                assert_eq!(d.surfactants.len(), 1);
                assert_eq!(d.surfactants[0].concentration_band, "5-15%");
            }
            _ => panic!("expected detergent product_group data"),
        }
    }

    #[test]
    fn invalid_surfactants_json_returns_error() {
        let mut row = detergent_row();
        row.insert("surfactants".into(), "not-json".into());
        let errs = validate_detergent_row(&row, 2).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "surfactants"));
    }

    /// The band is a closed set in core's rule, not a free string, so a value
    /// outside it fails the row rather than importing.
    #[test]
    fn a_concentration_band_off_the_scale_is_refused() {
        let mut row = detergent_row();
        row.insert(
            "surfactants".into(),
            r#"[{"name":"Sodium laureth sulfate","biodegradable":true,"concentrationBand":"lots"}]"#
                .into(),
        );
        let errs = validate_detergent_row(&row, 3).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "surfactants"));
    }

    #[test]
    fn detergent_row_bad_gtin_checksum_returns_error() {
        let mut row = detergent_row();
        row.insert("gtin".into(), "09506000134353".into()); // valid is ...352
        let errs = validate_detergent_row(&row, 4).expect_err("bad GTIN checksum must fail");
        assert!(errs.iter().any(|e| e.field == "gtin"));
    }
}
