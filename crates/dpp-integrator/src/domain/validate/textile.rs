//! Textile row validation.

use std::collections::HashMap;

use dpp_domain::domain::{
    passport::ManufacturerInfo,
    sector::{FibreEntry, Sector, SectorData, TextileData},
};

use crate::domain::fields::{optional_f64, require_str, validate_gtin_checksum};
use crate::domain::request::{CreatePassportRequest, RowError};

/// Validate a single textile row and convert it to a vault `CreatePassportRequest`.
pub fn validate_textile_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
    let gtin = require_str(row, "gtin", row_num, &mut errors);
    validate_gtin_checksum(gtin.as_deref(), row_num, &mut errors);
    let batch_id = require_str(row, "batchId", row_num, &mut errors);
    let manufacturer_name = require_str(row, "manufacturerName", row_num, &mut errors);
    let manufacturer_country = require_str(row, "manufacturerCountry", row_num, &mut errors);
    let country_of_manufacturing = require_str(row, "countryOfManufacturing", row_num, &mut errors);
    let care_instructions = require_str(row, "careInstructions", row_num, &mut errors);
    let chemical_compliance_standard =
        require_str(row, "chemicalComplianceStandard", row_num, &mut errors);

    // fibreComposition is a JSON array string
    let fibre_composition_str = require_str(row, "fibreComposition", row_num, &mut errors);
    let fibres: Option<Vec<FibreEntry>> = fibre_composition_str.as_deref().and_then(|s| {
        match serde_json::from_str::<Vec<FibreEntry>>(s) {
            Ok(f) => {
                if let Err(msg) = dpp_domain::validate_fibre_composition(&f) {
                    errors.push(RowError {
                        row: row_num,
                        field: "fibreComposition".into(),
                        message: msg,
                    });
                }
                Some(f)
            }
            Err(e) => {
                errors.push(RowError {
                    row: row_num,
                    field: "fibreComposition".into(),
                    message: format!("Invalid JSON: {e}"),
                });
                None
            }
        }
    });

    let recycled_content_pct = optional_f64(row, "recycledContentPct", row_num, &mut errors);
    let repair_score = optional_f64(row, "repairScore", row_num, &mut errors);
    let carbon_footprint = optional_f64(row, "carbonFootprintKgCo2e", row_num, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    let textile_data = SectorData::Textile(TextileData {
        gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
        fibre_composition: fibres.expect("field verified present by errors.is_empty() guard above"),
        country_of_manufacturing: country_of_manufacturing
            .expect("field verified present by errors.is_empty() guard above"),
        care_instructions: care_instructions
            .expect("field verified present by errors.is_empty() guard above"),
        chemical_compliance_standard: chemical_compliance_standard
            .expect("field verified present by errors.is_empty() guard above"),
        recycled_content_pct,
        repair_score,
        carbon_footprint_kg_co2e: carbon_footprint,
        water_use_litres: None,
        microplastic_shedding_mg_per_wash: None,
        durability_score: None,
        expected_wash_cycles: None,
        country_of_raw_material_origin: None,
        svhc_substances: None,
        allergens: None,
        substances_of_concern: None,
        recyclability_class: None,
        end_of_life_instructions: None,
        reuse_condition: None,
        prior_use_cycles: None,
        disassembly_instructions: None,
        spare_parts_available: None,
        product_weight_grams: None,
        repair_history_url: None,
        repair_count: None,
        pef_score: None,
    });

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        sector: Some(Sector::Textile),
        manufacturer: ManufacturerInfo {
            name: manufacturer_name
                .expect("field verified present by errors.is_empty() guard above"),
            address: manufacturer_country
                .expect("field verified present by errors.is_empty() guard above"),
            did_web_url: None,
        },
        materials: None,
        co2e_per_unit: carbon_footprint,
        repairability_score: repair_score,
        sector_data: Some(textile_data),
        batch_id,
        schema_version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_row_textile_returns_err() {
        assert!(validate_textile_row(&HashMap::new(), 1).is_err());
    }

    /// The both-case lookup is general: a fully snake_case **textile** row
    /// validates without any per-field alias list (the original camelCase-only
    /// validator would have rejected it).
    #[test]
    fn snake_case_textile_row_validates_via_normalized_lookup() {
        let row = HashMap::from([
            ("product_name".to_string(), "Organic Cotton Tee".to_string()),
            ("gtin".to_string(), "09506000134352".to_string()),
            ("batch_id".to_string(), "BATCH-T-001".to_string()),
            ("manufacturer_name".to_string(), "EcoWear".to_string()),
            ("manufacturer_country".to_string(), "BD".to_string()),
            ("country_of_manufacturing".to_string(), "BD".to_string()),
            (
                "care_instructions".to_string(),
                "30C machine wash".to_string(),
            ),
            (
                "chemical_compliance_standard".to_string(),
                "OEKO-TEX 100".to_string(),
            ),
            (
                "fibre_composition".to_string(),
                r#"[{"fibre":"cotton","pct":100}]"#.to_string(),
            ),
        ]);
        let req = validate_textile_row(&row, 1).expect("snake_case textile row should validate");
        assert_eq!(req.product_name, "Organic Cotton Tee");
        assert_eq!(req.manufacturer.name, "EcoWear");
        assert_eq!(req.manufacturer.address, "BD");
    }

    fn textile_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "Organic Cotton Tee".into()),
            ("gtin".into(), "09506000134352".into()),
            ("batchId".into(), "BATCH-T-001".into()),
            ("manufacturerName".into(), "EcoWear".into()),
            ("manufacturerCountry".into(), "BD".into()),
            ("countryOfManufacturing".into(), "BD".into()),
            ("careInstructions".into(), "30°C machine wash".into()),
            ("chemicalComplianceStandard".into(), "OEKO-TEX 100".into()),
            (
                "fibreComposition".into(),
                r#"[{"fibre":"cotton","pct":100}]"#.into(),
            ),
        ])
    }

    #[test]
    fn valid_textile_row_produces_request() {
        let row = textile_row();
        let req = validate_textile_row(&row, 1).expect("valid row should succeed");
        assert_eq!(req.product_name, "Organic Cotton Tee");
        match req.sector_data.unwrap() {
            SectorData::Textile(t) => {
                assert_eq!(t.gtin, "09506000134352");
                assert_eq!(t.fibre_composition.len(), 1);
                assert_eq!(t.fibre_composition[0].fibre, "cotton");
            }
            _ => panic!("expected textile sector data"),
        }
    }

    /// Regression: textile was the one sector validator that skipped the GTIN
    /// checksum, so a malformed GTIN passed straight through the import
    /// pipeline unchecked while every other sector already rejected it.
    #[test]
    fn textile_row_bad_gtin_checksum_returns_error() {
        let mut row = textile_row();
        row.insert("gtin".into(), "09506000134353".into()); // valid is ...352
        let errs = validate_textile_row(&row, 3).expect_err("bad GTIN checksum must fail");
        assert!(errs.iter().any(|e| e.field == "gtin"));
    }

    #[test]
    fn invalid_fibre_json_returns_error() {
        let mut row = textile_row();
        row.insert("fibreComposition".into(), "not-json".into());
        let errs = validate_textile_row(&row, 5).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "fibreComposition"));
    }

    #[test]
    fn fibre_pct_sum_not_100_returns_error() {
        let mut row = textile_row();
        row.insert(
            "fibreComposition".into(),
            r#"[{"fibre":"cotton","pct":60},{"fibre":"polyester","pct":30}]"#.into(),
        );
        let errs = validate_textile_row(&row, 6).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "fibreComposition"));
    }
}
