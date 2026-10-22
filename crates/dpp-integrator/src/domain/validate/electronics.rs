//! Electronics row validation.

use std::collections::HashMap;

use dpp_domain::{
    passport::ManufacturerInfo,
    product_group::{
        DeviceType, ElectronicsData, EnergyEfficiencyClass, ProductGroup, ProductGroupData,
        data::electronics::IndexScopeExclusion,
    },
};

use crate::domain::fields::{
    optional_bool, optional_carrier_serial, optional_commodity_code, optional_date, optional_f64,
    optional_str, optional_u32, parse_gtin, require_f64, require_str,
};
use crate::domain::request::{CreatePassportRequest, RowError};

use super::Column;

/// The columns this validator reads, in template order. Envelope columns
/// (`placedOnMarketDate`, `commodityCode`, `carrierSerial`) are appended by `columns_for`.
///
/// The structured optional fields (`repairabilityScore`,
/// `repairabilityIndexInputs`, `svhcSubstances`, `criticalRawMaterials`) are not
/// offered, as no other product group's importer offers its `svhcSubstances`.
pub(super) const COLUMNS: &[Column] = &[
    Column::required("productName"),
    Column::required("gtin"),
    Column::optional("batchId"),
    Column::required("manufacturerName"),
    Column::required("manufacturerCountry"),
    Column::required("productCategory"),
    Column::required("energyEfficiencyClass"),
    Column::required("co2ePerUnitKg"),
    Column::optional("indexScopeExclusion"),
    Column::optional("sparePartsAvailable"),
    Column::optional("repairManualUrl"),
    Column::optional("disassemblyInstructionsUrl"),
    Column::optional("rohsCompliant"),
    Column::optional("recycledContentPct"),
    Column::optional("standbyPowerW"),
    Column::optional("expectedLifetimeYears"),
    Column::optional("firmwareUpdateUntil"),
];

/// Validate a single electronics row and convert it to a vault
/// `CreatePassportRequest`.
pub fn validate_electronics_row(
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

    // Parsed by core's own `Deserialize`, so the accepted set is the enum's and
    // the refusal names it: serde's message lists every variant.
    let product_category =
        require_str(row, "productCategory", row_num, &mut errors).and_then(|s| {
            match serde_json::from_value::<DeviceType>(serde_json::Value::String(s.clone())) {
                Ok(d) => Some(d),
                Err(e) => {
                    errors.push(RowError {
                        row: row_num,
                        field: "productCategory".into(),
                        message: format!("{s:?} is not an electronics device type: {e}"),
                    });
                    None
                }
            }
        });

    // `EnergyEfficiencyClass` deserialises *any* unrecognised string to `Other`,
    // which the schema then refuses. Refused here instead, so the operator is
    // told which row, rather than a typo importing as a class no label carries.
    let energy_efficiency_class = require_str(row, "energyEfficiencyClass", row_num, &mut errors)
        .and_then(|s| {
            match serde_json::from_value::<EnergyEfficiencyClass>(serde_json::Value::String(
                s.clone(),
            )) {
                Ok(c) if c != EnergyEfficiencyClass::Other => Some(c),
                _ => {
                    errors.push(RowError {
                        row: row_num,
                        field: "energyEfficiencyClass".into(),
                        message: format!(
                            "{s:?} is not an energy label class — expected one of A, B, C, D, E, F, G"
                        ),
                    });
                    None
                }
            }
        });

    let co2e_per_unit_kg = require_f64(row, "co2ePerUnitKg", row_num, &mut errors);

    // Absent means "not excluded", never "unknown", so a value that does not
    // parse is refused rather than dropped: dropping it would silently withdraw
    // an exclusion the operator meant to claim.
    let index_scope_exclusion = optional_str(row, "indexScopeExclusion").and_then(|s| {
        match serde_json::from_value::<IndexScopeExclusion>(serde_json::Value::String(s.clone())) {
            Ok(x) => Some(x),
            Err(e) => {
                errors.push(RowError {
                    row: row_num,
                    field: "indexScopeExclusion".into(),
                    message: format!("{s:?} is not a repairability index exclusion: {e}"),
                });
                None
            }
        }
    });

    let spare_parts_available = optional_bool(row, "sparePartsAvailable", row_num, &mut errors);
    let repair_manual_url = optional_str(row, "repairManualUrl");
    let disassembly_instructions_url = optional_str(row, "disassemblyInstructionsUrl");
    let rohs_compliant = optional_bool(row, "rohsCompliant", row_num, &mut errors);
    let recycled_content_pct = optional_f64(row, "recycledContentPct", row_num, &mut errors);
    let standby_power_w = optional_f64(row, "standbyPowerW", row_num, &mut errors);
    let expected_lifetime_years = optional_u32(row, "expectedLifetimeYears", row_num, &mut errors);
    // A date column, stored as the start of that day in UTC: the date the
    // operator wrote is the date that reads back.
    let firmware_update_until = optional_date(row, "firmwareUpdateUntil", row_num, &mut errors)
        .map(|d| d.and_time(chrono::NaiveTime::MIN).and_utc());

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
        product_group: Some(ProductGroup::Electronics),
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
        product_group_data: Some(ProductGroupData::Electronics(ElectronicsData {
            product_identifier: dpp_domain::identifier::ProductIdentifier::gs1(
                gtin.expect("field verified present by errors.is_empty() guard above"),
            ),
            product_category: product_category
                .expect("field verified present by errors.is_empty() guard above"),
            energy_efficiency_class: energy_efficiency_class
                .expect("field verified present by errors.is_empty() guard above"),
            co2e_per_unit_kg: co2e_per_unit_kg
                .expect("field verified present by errors.is_empty() guard above"),
            repairability_score: None,
            repairability_index_inputs: None,
            index_scope_exclusion,
            spare_parts_available,
            repair_manual_url,
            disassembly_instructions_url,
            svhc_substances: None,
            rohs_compliant,
            critical_raw_materials: None,
            recycled_content_pct,
            standby_power_w,
            expected_lifetime_years,
            firmware_update_until,
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

    fn electronics_row() -> HashMap<String, String> {
        HashMap::from([
            ("productName".into(), "Pocket Phone 5".into()),
            ("gtin".into(), "09506000134352".into()),
            ("manufacturerName".into(), "Sample Devices GmbH".into()),
            ("manufacturerCountry".into(), "DE".into()),
            ("productCategory".into(), "smartphone".into()),
            ("energyEfficiencyClass".into(), "B".into()),
            ("co2ePerUnitKg".into(), "48.5".into()),
        ])
    }

    #[test]
    fn empty_row_electronics_returns_err() {
        assert!(validate_electronics_row(&HashMap::new(), 1).is_err());
    }

    #[test]
    fn valid_electronics_row_produces_request() {
        let mut row = electronics_row();
        row.insert("indexScopeExclusion".into(), "rollable-display".into());
        row.insert("expectedLifetimeYears".into(), "5".into());
        row.insert("firmwareUpdateUntil".into(), "2031-06-30".into());
        let req = validate_electronics_row(&row, 1).expect("valid electronics row");
        assert_eq!(req.product_group, Some(ProductGroup::Electronics));
        assert_eq!(req.manufacturer.country.as_deref(), Some("DE"));
        assert_eq!(req.manufacturer.address, "DE");
        match req.product_group_data.unwrap() {
            ProductGroupData::Electronics(d) => {
                assert_eq!(d.product_category, DeviceType::Smartphone);
                assert_eq!(d.energy_efficiency_class, EnergyEfficiencyClass::B);
                assert_eq!(d.co2e_per_unit_kg, 48.5);
                assert_eq!(
                    d.index_scope_exclusion,
                    Some(IndexScopeExclusion::RollableDisplay)
                );
                assert_eq!(d.expected_lifetime_years, Some(5));
                assert_eq!(
                    d.firmware_update_until.map(|t| t.date_naive().to_string()),
                    Some("2031-06-30".to_owned())
                );
            }
            _ => panic!("expected electronics product_group data"),
        }
    }

    #[test]
    fn an_unknown_device_type_is_refused_with_the_accepted_set() {
        let mut row = electronics_row();
        row.insert("productCategory".into(), "phablet".into());
        let errs = validate_electronics_row(&row, 2).expect_err("unknown device type must fail");
        let err = errs
            .iter()
            .find(|e| e.field == "productCategory")
            .expect("the error names the column");
        assert!(
            err.message.contains("other-mobile-phone"),
            "the refusal should list core's accepted values, got: {}",
            err.message
        );
    }

    /// `EnergyEfficiencyClass` has a `#[serde(other)]` catch-all, so a plain
    /// deserialise accepts any string. The row must still be refused.
    #[test]
    fn an_energy_class_off_the_label_scale_is_refused_not_caught_as_other() {
        for bad in ["Z", "a", "Other", "A+"] {
            let mut row = electronics_row();
            row.insert("energyEfficiencyClass".into(), bad.into());
            let errs =
                validate_electronics_row(&row, 3).expect_err("a class off the A–G scale must fail");
            assert!(
                errs.iter().any(|e| e.field == "energyEfficiencyClass"),
                "{bad:?} was not refused"
            );
        }
    }

    #[test]
    fn an_unknown_index_scope_exclusion_is_refused_not_dropped() {
        let mut row = electronics_row();
        row.insert("indexScopeExclusion".into(), "foldable".into());
        let errs = validate_electronics_row(&row, 4).expect_err("unknown exclusion must fail");
        assert!(errs.iter().any(|e| e.field == "indexScopeExclusion"));
    }

    #[test]
    fn electronics_row_bad_gtin_checksum_returns_error() {
        let mut row = electronics_row();
        row.insert("gtin".into(), "09506000134353".into()); // valid is ...352
        let errs = validate_electronics_row(&row, 5).expect_err("bad GTIN checksum must fail");
        assert!(errs.iter().any(|e| e.field == "gtin"));
    }
}
