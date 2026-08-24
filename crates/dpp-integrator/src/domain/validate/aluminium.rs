//! Aluminium row validation.

use std::collections::HashMap;

use dpp_domain::domain::{
    passport::ManufacturerInfo,
    product_group::{AluminiumData, ProductGroup, ProductGroupData, ProductionRoute},
};

use crate::domain::fields::{optional_f64, optional_str, parse_gtin, require_f64, require_str};
use crate::domain::request::{CreatePassportRequest, RowError};

/// Validate a single aluminium row and convert it to a vault `CreatePassportRequest`.
///
/// Expected CSV columns: `productName`, `batchId` (opt), `manufacturerName`,
/// `manufacturerCountry`, `gtin`, `alloyGrade`, `productionRoute`,
/// `co2ePerTonneKg`, `recycledContentPct`, `countryOfOrigin`,
/// `annualProductionTonnes` (opt).
pub fn validate_aluminium_row(
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
    let alloy_grade = require_str(row, "alloyGrade", row_num, &mut errors);
    let production_route_raw = require_str(row, "productionRoute", row_num, &mut errors);
    let co2e = require_f64(row, "co2ePerTonneKg", row_num, &mut errors);
    let recycled = require_f64(row, "recycledContentPct", row_num, &mut errors);
    let country_of_origin = require_str(row, "countryOfOrigin", row_num, &mut errors);
    let annual = optional_f64(row, "annualProductionTonnes", row_num, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    let production_route: ProductionRoute = serde_json::from_value(serde_json::Value::String(
        production_route_raw.expect("field verified present by errors.is_empty() guard above"),
    ))
    .unwrap_or(ProductionRoute::Other);

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        product_group: Some(ProductGroup::Aluminium),
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
        product_group_data: Some(ProductGroupData::Aluminium(AluminiumData {
            gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
            alloy_grade: alloy_grade
                .expect("field verified present by errors.is_empty() guard above"),
            production_route,
            co2e_per_tonne_kg: co2e
                .expect("field verified present by errors.is_empty() guard above"),
            recycled_content_pct: recycled
                .expect("field verified present by errors.is_empty() guard above"),
            country_of_origin: country_of_origin
                .expect("field verified present by errors.is_empty() guard above"),
            annual_production_tonnes: annual,
        })),
        batch_id,
        schema_version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_row_aluminium_returns_err() {
        assert!(validate_aluminium_row(&HashMap::new(), 1).is_err());
    }

    fn aluminium_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "6xxx Extrusion".into()),
            ("manufacturerName".into(), "Hydro ASA".into()),
            ("manufacturerCountry".into(), "NO".into()),
            ("gtin".into(), "09506000134352".into()),
            ("alloyGrade".into(), "6xxx".into()),
            ("productionRoute".into(), "secondary-recycled".into()),
            ("co2ePerTonneKg".into(), "2.1".into()),
            ("recycledContentPct".into(), "75.0".into()),
            ("countryOfOrigin".into(), "NO".into()),
        ])
    }

    #[test]
    fn valid_aluminium_row_produces_request() {
        let row = aluminium_row();
        let req = validate_aluminium_row(&row, 1).expect("valid aluminium row");
        assert_eq!(req.product_group, Some(ProductGroup::Aluminium));
        match req.product_group_data.unwrap() {
            ProductGroupData::Aluminium(d) => {
                assert_eq!(d.recycled_content_pct, 75.0);
                assert!(matches!(
                    d.production_route,
                    ProductionRoute::SecondaryRecycled
                ));
            }
            _ => panic!("expected aluminium product_group data"),
        }
    }
}
