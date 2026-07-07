//! Battery row validation.

use std::collections::HashMap;

use dpp_domain::domain::{
    gtin::Gtin,
    passport::ManufacturerInfo,
    sector::{
        BatteryChemistry, BatteryData, BatteryType, CarbonFootprintClass, Sector, SectorData,
    },
};

use crate::domain::fields::{
    aliased, optional_f64, optional_str, parse_materials, require_aliased, require_f64,
    require_str, require_u32,
};
use crate::domain::request::{CreatePassportRequest, RowError};

/// Validate a single battery row and convert it to a vault `CreatePassportRequest`.
pub fn validate_battery_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
    let gtin_raw = require_str(row, "gtin", row_num, &mut errors);
    let batch_id = require_str(row, "batchId", row_num, &mut errors);
    // Manufacturer headers vary across templates (camelCase vs snake_case, and
    // `manufacturerCountry` vs a full `manufacturer_address`). Accept all aliases.
    let manufacturer_name = require_aliased(
        row,
        &["manufacturerName", "manufacturer_name"],
        "manufacturerName",
        row_num,
        &mut errors,
    );
    let manufacturer_address = require_aliased(
        row,
        &[
            "manufacturerCountry",
            "manufacturerAddress",
            "manufacturer_country",
            "manufacturer_address",
        ],
        "manufacturerCountry",
        row_num,
        &mut errors,
    );
    let did_web_url = aliased(
        row,
        &[
            "didWebUrl",
            "manufacturerDidWebUrl",
            "manufacturer_didWebUrl",
        ],
    )
    .cloned();
    let battery_chemistry = require_str(row, "batteryChemistry", row_num, &mut errors);

    let nominal_voltage_v = require_f64(row, "nominalVoltageV", row_num, &mut errors);
    let nominal_capacity_ah = require_f64(row, "nominalCapacityAh", row_num, &mut errors);
    let expected_lifetime_cycles = require_u32(row, "expectedLifetimeCycles", row_num, &mut errors);
    let co2e_per_unit_kg = require_f64(row, "co2ePerUnitKg", row_num, &mut errors);

    // Validate GTIN (14 digits, correct GS1 mod-10 check digit) if the value was present.
    let gtin = gtin_raw.and_then(|g| match Gtin::parse(&g) {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(RowError {
                row: row_num,
                field: "gtin".into(),
                message: e.to_string(),
            });
            None
        }
    });

    // ── Extended Annex XIII fields (optional) — previously dropped on import ──
    let recycled_cobalt = optional_f64(row, "recycledContentCobaltPct", row_num, &mut errors);
    let recycled_lithium = optional_f64(row, "recycledContentLithiumPct", row_num, &mut errors);
    let recycled_nickel = optional_f64(row, "recycledContentNickelPct", row_num, &mut errors);
    let recycled_lead = optional_f64(row, "recycledContentLeadPct", row_num, &mut errors);
    let state_of_health = optional_f64(row, "stateOfHealthPct", row_num, &mut errors);
    let rated_capacity_kwh = optional_f64(row, "ratedCapacityKwh", row_num, &mut errors);
    let battery_weight_kg = optional_f64(row, "batteryWeightKg", row_num, &mut errors);
    let operating_temp_min_c = optional_f64(row, "operatingTempMinC", row_num, &mut errors);
    let operating_temp_max_c = optional_f64(row, "operatingTempMaxC", row_num, &mut errors);
    let round_trip_efficiency_pct =
        optional_f64(row, "roundTripEfficiencyPct", row_num, &mut errors);
    let due_diligence_url = optional_str(row, "dueDiligenceUrl");
    let carbon_footprint_class = optional_str(row, "carbonFootprintClass").and_then(|s| {
        serde_json::from_value::<CarbonFootprintClass>(serde_json::Value::String(s)).ok()
    });
    let battery_type = optional_str(row, "batteryType")
        .and_then(|s| serde_json::from_value::<BatteryType>(serde_json::Value::String(s)).ok());

    let repairability_score = optional_f64(row, "repairabilityScore", row_num, &mut errors);
    let materials = parse_materials(row);

    if !errors.is_empty() {
        return Err(errors);
    }

    let chemistry_raw =
        battery_chemistry.expect("field verified present by errors.is_empty() guard above");
    let battery_chemistry_parsed: BatteryChemistry =
        serde_json::from_value(serde_json::Value::String(chemistry_raw))
            .unwrap_or(BatteryChemistry::Other);

    let battery_data = SectorData::Battery(BatteryData {
        gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
        battery_chemistry: battery_chemistry_parsed,
        nominal_voltage_v: nominal_voltage_v
            .expect("field verified present by errors.is_empty() guard above"),
        nominal_capacity_ah: nominal_capacity_ah
            .expect("field verified present by errors.is_empty() guard above"),
        expected_lifetime_cycles: expected_lifetime_cycles
            .expect("field verified present by errors.is_empty() guard above"),
        co2e_per_unit_kg: co2e_per_unit_kg
            .expect("field verified present by errors.is_empty() guard above"),
        recycled_content_cobalt_pct: recycled_cobalt,
        recycled_content_lithium_pct: recycled_lithium,
        recycled_content_nickel_pct: recycled_nickel,
        recycled_content_lead_pct: recycled_lead,
        state_of_health_pct: state_of_health,
        rated_capacity_kwh,
        carbon_footprint_class,
        due_diligence_url,
        battery_type,
        battery_weight_kg,
        operating_temp_min_c,
        operating_temp_max_c,
        round_trip_efficiency_pct,
        cathode_material: None,
        anode_material: None,
        electrolyte_material: None,
        critical_raw_materials: None,
        disassembly_instructions_url: None,
        soh_methodology: None,
        rated_energy_wh: None,
        internal_resistance_mohm: None,
        manufacturing_date: None,
        manufacturing_place: None,
        battery_model_id: None,
        battery_passport_number: None,
    });

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        sector: Some(Sector::Battery),
        manufacturer: ManufacturerInfo {
            name: manufacturer_name
                .expect("field verified present by errors.is_empty() guard above"),
            address: manufacturer_address
                .expect("field verified present by errors.is_empty() guard above"),
            did_web_url,
        },
        materials: (!materials.is_empty()).then_some(materials),
        co2e_per_unit: None, // vault derives from BatteryData
        repairability_score,
        sector_data: Some(battery_data),
        batch_id,
        schema_version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Empty-row smoke test: guard must return Err, not panic.
    #[test]
    fn empty_row_battery_returns_err() {
        assert!(validate_battery_row(&HashMap::new(), 1).is_err());
    }

    fn battery_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "EV Battery 48V".into()),
            ("gtin".into(), "09506000134352".into()),
            ("batchId".into(), "BATCH-2026-001".into()),
            ("manufacturerName".into(), "Acme Energy".into()),
            ("manufacturerCountry".into(), "DE".into()),
            ("batteryChemistry".into(), "LFP".into()),
            ("nominalVoltageV".into(), "48.0".into()),
            ("nominalCapacityAh".into(), "100.0".into()),
            ("expectedLifetimeCycles".into(), "3000".into()),
            ("co2ePerUnitKg".into(), "85.4".into()),
        ])
    }

    #[test]
    fn valid_battery_row_produces_request() {
        let row = battery_row();
        let req = validate_battery_row(&row, 1).expect("valid row should succeed");
        assert_eq!(req.product_name, "EV Battery 48V");
        assert_eq!(req.sector, Some(Sector::Battery));
        match req.sector_data.unwrap() {
            SectorData::Battery(b) => {
                assert_eq!(b.gtin.as_str(), "09506000134352");
                assert_eq!(b.battery_chemistry, BatteryChemistry::Lfp);
                assert_eq!(b.nominal_voltage_v, 48.0);
            }
            _ => panic!("expected battery sector data"),
        }
    }

    #[test]
    fn missing_required_field_returns_error_with_field_name() {
        let mut row = battery_row();
        row.remove("productName");
        let errs = validate_battery_row(&row, 2).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "productName"));
    }

    #[test]
    fn invalid_gtin_returns_error() {
        let mut row = battery_row();
        row.insert("gtin".into(), "1234".into()); // too short
        let errs = validate_battery_row(&row, 3).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "gtin"));
    }

    #[test]
    fn non_numeric_voltage_returns_error() {
        let mut row = battery_row();
        row.insert("nominalVoltageV".into(), "N/A".into());
        let errs = validate_battery_row(&row, 4).expect_err("should fail");
        assert!(errs.iter().any(|e| e.field == "nominalVoltageV"));
        assert!(errs.iter().any(|e| e.message.contains("N/A")));
    }

    /// Regression: the extended Annex XIII columns and the `material_N_*` bill of
    /// materials must survive import (snake_case manufacturer aliases included),
    /// rather than being silently dropped as they were before.
    #[test]
    fn battery_row_maps_extended_fields_and_materials_with_aliases() {
        let row = HashMap::from([
            ("productName".into(), "Odal Reference Battery LFP-48".into()),
            ("gtin".into(), "09506000134352".into()),
            ("batchId".into(), "BATCH-2026-Q2-007".into()),
            ("manufacturer_name".into(), "GreenCell GmbH".into()),
            (
                "manufacturer_address".into(),
                "Prenzlauer Berg 12, 10405 Berlin, DE".into(),
            ),
            (
                "manufacturer_didWebUrl".into(),
                "https://greencell.example/.well-known/did.json".into(),
            ),
            ("batteryChemistry".into(), "LFP".into()),
            ("nominalVoltageV".into(), "48.0".into()),
            ("nominalCapacityAh".into(), "100.0".into()),
            ("expectedLifetimeCycles".into(), "3000".into()),
            ("co2ePerUnitKg".into(), "45.2".into()),
            ("recycledContentCobaltPct".into(), "0.0".into()),
            ("recycledContentLithiumPct".into(), "12.5".into()),
            ("recycledContentNickelPct".into(), "0.0".into()),
            ("stateOfHealthPct".into(), "100.0".into()),
            ("ratedCapacityKwh".into(), "4.8".into()),
            ("repairabilityScore".into(), "7.5".into()),
            ("material_1_name".into(), "Lithium Iron Phosphate".into()),
            ("material_1_weightKg".into(), "1.20".into()),
            ("material_1_recycledPct".into(), "12.5".into()),
            ("material_1_originCountry".into(), "CN".into()),
            ("material_2_name".into(), "Graphite".into()),
            ("material_2_weightKg".into(), "0.40".into()),
        ]);
        let req = validate_battery_row(&row, 1).expect("valid extended battery row");

        // Manufacturer aliases resolved (snake_case + full address + did:web).
        assert_eq!(req.manufacturer.name, "GreenCell GmbH");
        assert!(req.manufacturer.address.contains("Berlin"));
        assert_eq!(
            req.manufacturer.did_web_url.as_deref(),
            Some("https://greencell.example/.well-known/did.json")
        );
        assert_eq!(req.repairability_score, Some(7.5));

        // Bill of materials parsed (blank trailing slots skipped).
        let materials = req.materials.expect("materials parsed");
        assert_eq!(materials.len(), 2);
        assert_eq!(materials[0].name, "Lithium Iron Phosphate");
        assert_eq!(materials[0].weight_kg, 1.20);
        assert_eq!(materials[0].recycled_pct, Some(12.5));
        assert_eq!(materials[0].origin_country.as_deref(), Some("CN"));

        // Extended battery fields carried through (no longer dropped).
        match req.sector_data.unwrap() {
            SectorData::Battery(b) => {
                assert_eq!(b.recycled_content_lithium_pct, Some(12.5));
                assert_eq!(b.recycled_content_cobalt_pct, Some(0.0));
                assert_eq!(b.recycled_content_nickel_pct, Some(0.0));
                assert_eq!(b.state_of_health_pct, Some(100.0));
                assert_eq!(b.rated_capacity_kwh, Some(4.8));
            }
            _ => panic!("expected battery sector data"),
        }
    }
}
