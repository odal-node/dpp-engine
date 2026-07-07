//! Steel row validation.

use std::collections::HashMap;

use dpp_domain::domain::{
    passport::ManufacturerInfo,
    sector::{ProductionRoute, Sector, SectorData, SteelData},
};

use crate::domain::fields::{optional_f64, optional_str, require_f64, require_str};
use crate::domain::request::{CreatePassportRequest, RowError};

/// Validate a single steel row and convert it to a vault `CreatePassportRequest`.
///
/// Expected CSV columns: `productName`, `batchId` (opt), `manufacturerName`,
/// `manufacturerCountry`, `gtin`, `co2ePerTonneSteel`, `recycledScrapContentPct`,
/// `productCategory`, `countryOfProduction`, `productionRoute`,
/// `annualProductionTonnes` (opt).
pub fn validate_steel_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
    let batch_id = optional_str(row, "batchId");
    let manufacturer_name = require_str(row, "manufacturerName", row_num, &mut errors);
    let manufacturer_country = require_str(row, "manufacturerCountry", row_num, &mut errors);
    let gtin = require_str(row, "gtin", row_num, &mut errors);
    let co2e = require_f64(row, "co2ePerTonneSteel", row_num, &mut errors);
    let recycled = require_f64(row, "recycledScrapContentPct", row_num, &mut errors);
    let product_category = require_str(row, "productCategory", row_num, &mut errors);
    let country_of_production = require_str(row, "countryOfProduction", row_num, &mut errors);
    let production_route_raw = require_str(row, "productionRoute", row_num, &mut errors);
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
        sector: Some(Sector::Steel),
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
        sector_data: Some(SectorData::Steel(SteelData {
            gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
            co2e_per_tonne_steel: co2e
                .expect("field verified present by errors.is_empty() guard above"),
            recycled_scrap_content_pct: recycled
                .expect("field verified present by errors.is_empty() guard above"),
            product_category: product_category
                .expect("field verified present by errors.is_empty() guard above"),
            country_of_production: country_of_production
                .expect("field verified present by errors.is_empty() guard above"),
            production_route,
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
    fn empty_row_steel_returns_err() {
        assert!(validate_steel_row(&HashMap::new(), 1).is_err());
    }

    fn steel_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "Hot-Rolled Coil".into()),
            ("manufacturerName".into(), "Thyssen Steel".into()),
            ("manufacturerCountry".into(), "DE".into()),
            ("gtin".into(), "09506000134352".into()),
            ("co2ePerTonneSteel".into(), "1.85".into()),
            ("recycledScrapContentPct".into(), "28.0".into()),
            ("productCategory".into(), "flat".into()),
            ("countryOfProduction".into(), "DE".into()),
            ("productionRoute".into(), "electric-arc".into()),
        ])
    }

    #[test]
    fn valid_steel_row_produces_request() {
        let row = steel_row();
        let req = validate_steel_row(&row, 1).expect("valid steel row");
        assert_eq!(req.sector, Some(Sector::Steel));
        match req.sector_data.unwrap() {
            SectorData::Steel(d) => {
                assert_eq!(d.co2e_per_tonne_steel, 1.85);
                assert!(matches!(d.production_route, ProductionRoute::ElectricArc));
            }
            _ => panic!("expected steel sector data"),
        }
    }

    #[test]
    fn steel_row_missing_field_returns_error() {
        let mut row = steel_row();
        row.remove("co2ePerTonneSteel");
        let errs = validate_steel_row(&row, 2).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "co2ePerTonneSteel"));
    }
}
