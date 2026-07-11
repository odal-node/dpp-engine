//! Tyre row validation.

use std::collections::HashMap;

use dpp_domain::domain::{
    passport::ManufacturerInfo,
    sector::{Sector, SectorData, TyreData},
};

use crate::domain::fields::{
    optional_f64, optional_str, require_f64, require_str, validate_gtin_checksum,
};
use crate::domain::request::{CreatePassportRequest, RowError};

/// Validate a single tyre row and convert it to a vault `CreatePassportRequest`.
///
/// Expected CSV columns: `productName`, `batchId` (opt), `manufacturerName`,
/// `manufacturerCountry`, `gtin`, `tyreClass`, `fuelEfficiencyClass`,
/// `wetGripClass`, `externalRollingNoiseDb`,
/// `noisePerformanceClass` (opt), `rollingResistanceNPerKn` (opt),
/// `recycledRubberPct` (opt), `co2ePerTyreKg` (opt).
pub fn validate_tyre_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
    let batch_id = optional_str(row, "batchId");
    let manufacturer_name = require_str(row, "manufacturerName", row_num, &mut errors);
    let manufacturer_country = require_str(row, "manufacturerCountry", row_num, &mut errors);
    let gtin = require_str(row, "gtin", row_num, &mut errors);
    validate_gtin_checksum(gtin.as_deref(), row_num, &mut errors);
    let tyre_class = require_str(row, "tyreClass", row_num, &mut errors);
    let fuel_class = require_str(row, "fuelEfficiencyClass", row_num, &mut errors);
    let wet_class = require_str(row, "wetGripClass", row_num, &mut errors);
    let noise_db = require_f64(row, "externalRollingNoiseDb", row_num, &mut errors);
    let noise_class = optional_str(row, "noisePerformanceClass");
    let rolling_res = optional_f64(row, "rollingResistanceNPerKn", row_num, &mut errors);
    let recycled_rubber = optional_f64(row, "recycledRubberPct", row_num, &mut errors);
    let co2e = optional_f64(row, "co2ePerTyreKg", row_num, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        sector: Some(Sector::Tyre),
        manufacturer: ManufacturerInfo {
            name: manufacturer_name
                .expect("field verified present by errors.is_empty() guard above"),
            address: manufacturer_country
                .expect("field verified present by errors.is_empty() guard above"),
            did_web_url: None,
        },
        materials: None,
        co2e_per_unit: co2e,
        repairability_score: None,
        sector_data: Some(SectorData::Tyre(TyreData {
            gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
            tyre_class: tyre_class
                .expect("field verified present by errors.is_empty() guard above"),
            fuel_efficiency_class: fuel_class
                .expect("field verified present by errors.is_empty() guard above"),
            wet_grip_class: wet_class
                .expect("field verified present by errors.is_empty() guard above"),
            external_rolling_noise_db: noise_db
                .expect("field verified present by errors.is_empty() guard above"),
            noise_performance_class: noise_class,
            rolling_resistance_n_per_kn: rolling_res,
            recycled_rubber_pct: recycled_rubber,
            co2e_per_tyre_kg: co2e,
        })),
        batch_id,
        schema_version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_row_tyre_returns_err() {
        assert!(validate_tyre_row(&HashMap::new(), 1).is_err());
    }

    fn tyre_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "EcoContact 6".into()),
            ("manufacturerName".into(), "Continental AG".into()),
            ("manufacturerCountry".into(), "DE".into()),
            ("gtin".into(), "09506000134352".into()),
            ("tyreClass".into(), "C1".into()),
            ("fuelEfficiencyClass".into(), "B".into()),
            ("wetGripClass".into(), "A".into()),
            ("externalRollingNoiseDb".into(), "68.0".into()),
        ])
    }

    #[test]
    fn valid_tyre_row_produces_request() {
        let row = tyre_row();
        let req = validate_tyre_row(&row, 1).expect("valid tyre row");
        assert_eq!(req.sector, Some(Sector::Tyre));
        match req.sector_data.unwrap() {
            SectorData::Tyre(d) => {
                assert_eq!(d.tyre_class, "C1");
                assert_eq!(d.external_rolling_noise_db, 68.0);
            }
            _ => panic!("expected tyre sector data"),
        }
    }
}
