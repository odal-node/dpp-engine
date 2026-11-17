//! Battery row validation.

use std::collections::HashMap;

use dpp_domain::{
    identifier::gtin::Gtin,
    passport::ManufacturerInfo,
    product_group::{
        BatteryChemistry, BatteryData, BatteryType, CarbonFootprintClass,
        DueDiligenceOperatorScope, ProductGroup, ProductGroupData,
    },
};

use dpp_rules::batteries::{
    battery_facts::BatteryFacts,
    passport_content::{MissingFact, undetermined_fields},
};

use crate::domain::battery_fields::{
    parse_battery_status, parse_component_part_numbers, parse_composition,
    parse_critical_raw_materials, parse_dynamic_performance, parse_hazardous_substances,
    parse_state_of_health, parse_temperature_range,
};
use crate::domain::fields::{
    aliased, optional_carrier_serial, optional_commodity_code, optional_date, optional_f64,
    optional_str, parse_materials, require_aliased, require_f64, require_str, require_u32,
};
use crate::domain::request::{CreatePassportRequest, RowError};

use super::Column;

/// The columns this validator reads, in template order. Envelope columns
/// (`placedOnMarketDate`, `commodityCode`, `carrierSerial`) are appended by `columns_for`.
pub(super) const COLUMNS: &[Column] = &[
    Column::required("productName"),
    Column::required("gtin"),
    Column::required("batchId"),
    Column::required("manufacturerName"),
    Column::required("manufacturerCountry"),
    Column::required("batteryChemistry"),
    Column::required("batteryType"),
    Column::required("nominalVoltageV"),
    Column::required("nominalCapacityAh"),
    Column::required("expectedLifetimeCycles"),
    Column::optional("co2ePerUnitKg"),
    // Per-metal, not aggregate. `recycledContentPct` stood here and was read by
    // nothing: the template advertised a column the importer silently ignored,
    // so an operator who filled it in lost the value with no error. Annex XIII
    // asks per metal and the validator has always parsed it that way — the
    // column list was the half that never caught up.
    Column::optional("recycledContentCobaltPct"),
    Column::optional("recycledContentLithiumPct"),
    Column::optional("recycledContentNickelPct"),
    Column::optional("recycledContentLeadPct"),
    // Read by `validate_battery_row` since before this list existed, and absent
    // from it — so the generated template omitted twelve fields the importer
    // accepts, which an operator could only discover by reading the validator.
    Column::optional("stateOfHealthPct"),
    Column::optional("ratedCapacityKwh"),
    Column::optional("batteryWeightKg"),
    Column::optional("operatingTempMinC"),
    Column::optional("operatingTempMaxC"),
    Column::optional("roundTripEfficiencyPct"),
    Column::optional("dueDiligenceUrl"),
    Column::optional("dueDiligenceOperatorScope"),
    Column::optional("carbonFootprintClass"),
    Column::optional("repairabilityScore"),
];

/// Validate a single battery row and convert it to a vault `CreatePassportRequest`.
pub fn validate_battery_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
    let gtin_raw = require_str(row, "gtin", row_num, &mut errors);
    let batch_id = require_str(row, "batchId", row_num, &mut errors);
    // Manufacturer headers vary across templates in casing (camelCase vs
    // snake_case), so each group below accepts both spellings.
    let manufacturer_name = require_aliased(
        row,
        &["manufacturerName", "manufacturer_name"],
        "manufacturerName",
        row_num,
        &mut errors,
    );
    // Read as two groups rather than one merged alias list. The headers mean
    // different things — `manufacturerCountry` states a country, and
    // `manufacturerAddress` a postal address — and merging them meant a row's
    // value landed in `address` with nothing downstream able to tell which of
    // the two it held. `ManufacturerInfo::country` is the field that can be
    // checked against ISO 3166-1, so the distinction has somewhere to go.
    let manufacturer_country =
        aliased(row, &["manufacturerCountry", "manufacturer_country"]).cloned();
    let manufacturer_postal =
        aliased(row, &["manufacturerAddress", "manufacturer_address"]).cloned();
    // Still one required field between them, reported under the same canonical
    // name as before, so a template that supplies either keeps importing.
    if manufacturer_country.is_none() && manufacturer_postal.is_none() {
        errors.push(RowError {
            row: row_num,
            field: "manufacturerCountry".to_owned(),
            message: "manufacturerCountry is required".to_owned(),
        });
    }
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
    let co2e_per_unit_kg = optional_f64(row, "co2ePerUnitKg", row_num, &mut errors);

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
    // The operator's Art. 47 declaration. Closed, as core's own parse is: a value
    // that is not one of the two is refused with its row, never read as either
    // answer, and an empty cell is an undeclared operator rather than an error.
    let due_diligence_operator_scope =
        optional_str(row, "dueDiligenceOperatorScope").and_then(|s| {
            match serde_json::from_value::<DueDiligenceOperatorScope>(serde_json::Value::String(
                s.clone(),
            )) {
                Ok(scope) => Some(scope),
                Err(_) => {
                    errors.push(RowError {
                        row: row_num,
                        field: "dueDiligenceOperatorScope".into(),
                        message: format!(
                            "{s:?} is not an Art. 47 declaration — expected one of: subject, \
                             belowTurnoverThreshold"
                        ),
                    });
                    None
                }
            }
        });
    let carbon_footprint_class = optional_str(row, "carbonFootprintClass").and_then(|s| {
        serde_json::from_value::<CarbonFootprintClass>(serde_json::Value::String(s)).ok()
    });
    // Required and closed since Annex VI Part A: a battery without a type is not
    // a battery this regulation recognises, and there is no honest default to
    // pick. An unrecognised value is reported with the accepted set rather than
    // silently dropped to `None`, which is what the old optional parse did — a
    // typo used to produce a passport missing a mandatory field instead of a
    // failed row.
    let battery_type = require_str(row, "batteryType", row_num, &mut errors).and_then(|s| {
        match serde_json::from_value::<BatteryType>(serde_json::Value::String(s.clone())) {
            Ok(t) => Some(t),
            Err(_) => {
                errors.push(RowError {
                    row: row_num,
                    field: "batteryType".into(),
                    message: format!(
                        "{s:?} is not a battery type recognised by Annex VI Part A — expected one \
                         of: portable, industrial, ev, lmt, starting-lighting-ignition"
                    ),
                });
                None
            }
        }
    });

    let repairability_score = optional_f64(row, "repairabilityScore", row_num, &mut errors);
    let materials = parse_materials(row);

    // Envelope-level, so every product group reads them from the same columns.
    let placed_on_market_date = optional_date(row, "placedOnMarketDate", row_num, &mut errors);
    let commodity_code = optional_commodity_code(row, "commodityCode", row_num, &mut errors);
    let carrier_serial = optional_carrier_serial(row, "carrierSerial", row_num, &mut errors);

    // A battery whose content rules turn on its placing date cannot publish
    // without one: core's publish gate refuses it at `/placedOnMarketDate`. The
    // row is refused here instead, by asking core the same question, so an import
    // never creates a draft that can only fail later. The operator's Art. 47
    // declaration is passed as read, and core asks for the date before it looks
    // at the declaration. Second-life status is not passed: core infers that
    // limb from `batteryStatus` privately, so a re-used, repurposed or
    // remanufactured battery is asked for its date here although publish would
    // not need it.
    if placed_on_market_date.is_none() && !errors.iter().any(|e| e.field == "placedOnMarketDate") {
        let category = battery_type
            .as_ref()
            .and_then(|t| serde_json::to_value(t).ok())
            .and_then(|v| v.as_str().map(str::to_owned));
        if let Some(category) = category {
            let facts = BatteryFacts {
                placed_on_market: None,
                operator_scope: due_diligence_operator_scope.map(Into::into),
                ..BatteryFacts::default()
            };
            if undetermined_fields(&category, facts)
                .any(|(_, fact)| fact == MissingFact::PlacingDate)
            {
                errors.push(RowError {
                    row: row_num,
                    field: "placedOnMarketDate".into(),
                    message: format!(
                        "required for a {category} battery: whether its due diligence report \
                         is owed depends on the date it was placed on the market, and a \
                         passport without it cannot be published"
                    ),
                });
            }
        }
    }

    // The Annex VI Part A / Annex XIII columns the per-category templates carry.
    //
    // Read here, above the guard, rather than inline in the struct below: a
    // malformed number has to reach `errors` while `errors` is still checked. A
    // parse further down would push into a vector nothing looks at again, and
    // the bad cell would import as an absent value — the silent data loss this
    // whole change exists to stop.
    let manufacturing_date = optional_date(row, "manufacturingDate", row_num, &mut errors);
    let minimal_voltage = optional_f64(row, "minimalVoltageV", row_num, &mut errors);
    let maximum_voltage = optional_f64(row, "maximumVoltageV", row_num, &mut errors);
    let original_power = optional_f64(row, "originalPowerCapabilityW", row_num, &mut errors);
    let power_limit_min = optional_f64(row, "powerLimitMinW", row_num, &mut errors);
    let power_limit_max = optional_f64(row, "powerLimitMaxW", row_num, &mut errors);
    let renewable_content = optional_f64(row, "renewableContentPct", row_num, &mut errors);
    let internal_cell_resistance =
        optional_f64(row, "internalCellResistanceMohm", row_num, &mut errors);
    let internal_pack_resistance =
        optional_f64(row, "internalPackResistanceMohm", row_num, &mut errors);
    let initial_rte = optional_f64(row, "initialRoundTripEfficiencyPct", row_num, &mut errors);
    let rte_half_life = optional_f64(
        row,
        "roundTripEfficiencyAtHalfCycleLifePct",
        row_num,
        &mut errors,
    );
    let cycle_life_c_rate = optional_f64(row, "cycleLifeTestCRate", row_num, &mut errors);
    let capacity_threshold = optional_f64(
        row,
        "capacityThresholdForExhaustionPct",
        row_num,
        &mut errors,
    );
    let cathode = parse_composition(row, "cathode", row_num, &mut errors);
    let anode = parse_composition(row, "anode", row_num, &mut errors);
    let electrolyte = parse_composition(row, "electrolyte", row_num, &mut errors);
    let critical_raw = parse_critical_raw_materials(row, row_num, &mut errors);
    let hazardous_substances = parse_hazardous_substances(row, row_num, &mut errors);
    let not_in_use_temperature_range = parse_temperature_range(row, row_num, &mut errors);
    let dynamic_performance = parse_dynamic_performance(row, row_num, &mut errors);
    // Named for the block, not the percentage: `state_of_health` above is the
    // legacy `stateOfHealthPct` scalar and shadowing it silently swapped the two.
    let state_of_health_block = match parse_state_of_health(row, row_num, &mut errors) {
        Ok(soh) => soh,
        Err(message) => {
            errors.push(RowError {
                row: row_num,
                field: "stateOfHealth".to_owned(),
                message: message.to_owned(),
            });
            None
        }
    };

    if !errors.is_empty() {
        return Err(errors);
    }

    let chemistry_raw =
        battery_chemistry.expect("field verified present by errors.is_empty() guard above");
    let battery_chemistry_parsed: BatteryChemistry =
        serde_json::from_value(serde_json::Value::String(chemistry_raw))
            .unwrap_or(BatteryChemistry::Other);

    let battery_data = ProductGroupData::Battery(Box::new(BatteryData {
        product_identifier: dpp_domain::identifier::ProductIdentifier::gs1(
            gtin.expect("field verified present by errors.is_empty() guard above"),
        ),
        battery_chemistry: battery_chemistry_parsed,
        nominal_voltage_v: nominal_voltage_v
            .expect("field verified present by errors.is_empty() guard above"),
        nominal_capacity_ah: nominal_capacity_ah
            .expect("field verified present by errors.is_empty() guard above"),
        expected_lifetime_cycles,
        co2e_per_unit_kg,
        recycled_content_cobalt_pct: recycled_cobalt,
        recycled_content_lithium_pct: recycled_lithium,
        recycled_content_nickel_pct: recycled_nickel,
        recycled_content_lead_pct: recycled_lead,
        state_of_health_pct: state_of_health,
        rated_capacity_kwh,
        carbon_footprint_class,
        due_diligence_url,
        battery_type: battery_type
            .expect("field verified present by errors.is_empty() guard above"),
        battery_weight_kg,
        operating_temp_min_c,
        operating_temp_max_c,
        round_trip_efficiency_pct,
        cathode_material: cathode,
        anode_material: anode,
        electrolyte_material: electrolyte,
        critical_raw_materials: critical_raw,
        disassembly_instructions_url: optional_str(row, "disassemblyInstructionsUrl"),
        // No column, deliberately: the methodology behind a state-of-health
        // figure is prose an operator publishes per model, not per row, and the
        // guidance does not ask for it as a data point.
        soh_methodology: None,
        // Not read from the row. The envelope's `placedOnMarketDate` carries the
        // date for every product group, and core reads either place.
        placed_on_market_date: None,
        // Core reads the declaration for a battery placed on the market from
        // 18 August 2027, and refuses that battery's first publish until it is
        // declared.
        due_diligence_operator_scope,
        carbon_footprint_class_ruleset_id: None,
        carbon_footprint_class_ruleset_version: None,
        recycled_content_reporting_year: None,
        expected_lifetime: None,
        rated_energy_wh: None,
        internal_resistance_mohm: None,
        state_of_health: state_of_health_block,
        // A manufacturing *date* in the CSV, a timestamp on the model. Anchored
        // at midnight UTC rather than at the moment of import: the operator
        // stated a day, and inventing a time of day would be data they did not
        // supply — one that would also differ between two imports of the same row.
        manufacturing_date: manufacturing_date
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|naive| naive.and_utc()),
        manufacturing_place: optional_str(row, "manufacturingPlace"),
        battery_model_id: optional_str(row, "batteryModelId"),
        battery_passport_number: optional_str(row, "batteryPassportNumber"),
        // The remainder of Annex VI Part A and the Annex XIII point 1–3 tiers.
        //
        // These were every one `None` "until the template gains a column", and
        // the template never did — which is why a battery imported from the
        // first-party template could be created and then never published. The
        // per-category templates carry them now; `domain::battery_template` is
        // the contract, and a test there proves it covers `mandatory_fields`.
        //
        // Listed individually rather than defaulted because `BatteryData` derives
        // no `Default` — deliberately, since the same release made `battery_type`
        // required and closed. That means a future Annex field cannot slip into
        // an import as an unnoticed `None`: it breaks this literal, and someone
        // has to decide whether the template should carry it.
        battery_status: parse_battery_status(row),
        capacity_threshold_for_exhaustion_pct: capacity_threshold,
        component_part_numbers: parse_component_part_numbers(row),
        cycle_life_test_c_rate: cycle_life_c_rate,
        dynamic_performance,
        eu_declaration_of_conformity: optional_str(row, "euDeclarationOfConformity"),
        expected_lifetime_reference_test: optional_str(row, "expectedLifetimeReferenceTest"),
        hazardous_substances,
        initial_round_trip_efficiency_pct: initial_rte,
        internal_cell_resistance_mohm: internal_cell_resistance,
        internal_pack_resistance_mohm: internal_pack_resistance,
        marking_information: optional_str(row, "markingInformation"),
        maximum_voltage_v: maximum_voltage,
        minimal_voltage_v: minimal_voltage,
        not_in_use_temperature_range,
        not_in_use_temperature_reference_test: optional_str(
            row,
            "notInUseTemperatureReferenceTest",
        ),
        original_power_capability_w: original_power,
        power_limit_max_w: power_limit_max,
        power_limit_min_w: power_limit_min,
        renewable_content_pct: renewable_content,
        round_trip_efficiency_at_half_cycle_life_pct: rte_half_life,
        safety_measures: optional_str(row, "safetyMeasures"),
        spare_parts_contacts: optional_str(row, "sparePartsContacts"),
        test_report_results: optional_str(row, "testReportResults"),
        usable_extinguishing_agent: optional_str(row, "usableExtinguishingAgent"),
        waste_battery_information: optional_str(row, "wasteBatteryInformation"),
        // Still without a column, deliberately. `hazardSymbol` is the Art. 13(5)
        // cadmium/lead marking, which `markingInformation` already carries as
        // prose; the two temperature ranges beyond not-in-use and the commercial
        // warranty are not mandatory for any category; and usage history is
        // per-battery telemetry no import row can hold.
        hazard_symbol: None,
        commercial_warranty_period_months: None,
        power_temperature_range: None,
        usage_history: None,
        voltage_temperature_range: None,
    }));

    Ok(CreatePassportRequest {
        product_name: product_name
            .expect("field verified present by errors.is_empty() guard above"),
        product_group: Some(ProductGroup::Battery),
        manufacturer: ManufacturerInfo {
            name: manufacturer_name
                .expect("field verified present by errors.is_empty() guard above"),
            // A real postal address when the row carried one, otherwise the
            // country, which is what this field held for every battery row
            // before `country` existed. `address` is required and the create
            // route refuses an empty one, so it is never left blank.
            address: manufacturer_postal
                .or_else(|| manufacturer_country.clone())
                .expect("field verified present by errors.is_empty() guard above"),
            registered_trade_name: None,
            electronic_address: None,
            country: manufacturer_country,
            did_web_url,
        },
        materials: (!materials.is_empty()).then_some(materials),
        co2e_per_unit: None, // vault derives from BatteryData
        repairability_score,
        product_group_data: Some(battery_data),
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
            ("batteryType".into(), "industrial".into()),
            ("nominalVoltageV".into(), "48.0".into()),
            ("nominalCapacityAh".into(), "100.0".into()),
            ("expectedLifetimeCycles".into(), "3000".into()),
            ("co2ePerUnitKg".into(), "85.4".into()),
            ("placedOnMarketDate".into(), "2027-02-18".into()),
        ])
    }

    #[test]
    fn valid_battery_row_produces_request() {
        let row = battery_row();
        let req = validate_battery_row(&row, 1).expect("valid row should succeed");
        assert_eq!(req.product_name, "EV Battery 48V");
        // This template supplies a country header and no postal address, so the
        // country reaches the field that can be checked against ISO 3166-1.
        // `address` keeps carrying it too: it is required, the create route
        // refuses an empty one, and this template has nothing better to put
        // there.
        assert_eq!(req.manufacturer.country.as_deref(), Some("DE"));
        assert_eq!(req.manufacturer.address, "DE");
        assert_eq!(req.product_group, Some(ProductGroup::Battery));
        match req.product_group_data.unwrap() {
            ProductGroupData::Battery(b) => {
                assert_eq!(b.product_identifier.as_str(), "09506000134352");
                assert_eq!(b.battery_chemistry, BatteryChemistry::Lfp);
                assert_eq!(b.nominal_voltage_v, 48.0);
            }
            _ => panic!("expected battery product_group data"),
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

    /// The operator's Art. 47 declaration reaches the battery data as the core
    /// type, under the two spellings core defines.
    #[test]
    fn a_declared_operator_scope_is_read_as_core_declares_it() {
        for (wire, expected) in [
            ("subject", DueDiligenceOperatorScope::Subject),
            (
                "belowTurnoverThreshold",
                DueDiligenceOperatorScope::BelowTurnoverThreshold,
            ),
        ] {
            let mut row = battery_row();
            row.insert("dueDiligenceOperatorScope".into(), wire.into());
            let req = validate_battery_row(&row, 1).expect("a declared scope is a valid row");
            match req.product_group_data.unwrap() {
                ProductGroupData::Battery(b) => {
                    assert_eq!(b.due_diligence_operator_scope, Some(expected), "{wire}");
                }
                _ => panic!("expected battery product_group data"),
            }
        }
    }

    /// An unrecognised declaration is refused, naming its row and column. It is
    /// not read as either answer: an undeclared operator and an exempt one are
    /// different things to core.
    #[test]
    fn an_unknown_operator_scope_is_refused_naming_its_row() {
        let mut row = battery_row();
        row.insert("dueDiligenceOperatorScope".into(), "exempt".into());
        let errs = validate_battery_row(&row, 7).expect_err("an unknown declaration is refused");
        assert!(
            errs.iter().any(|e| e.row == 7
                && e.field == "dueDiligenceOperatorScope"
                && e.message.contains("exempt")),
            "{errs:?}"
        );
    }

    /// A battery whose due diligence answer turns on its placing date is refused
    /// at import without one, naming its row, since publish would refuse it.
    #[test]
    fn a_battery_whose_report_turns_on_its_date_is_refused_without_one() {
        for category in ["ev", "lmt", "industrial"] {
            let mut row = battery_row();
            row.insert("batteryType".into(), category.into());
            row.remove("placedOnMarketDate");
            let errs = validate_battery_row(&row, 9).expect_err("a dateless row is refused");
            assert!(
                errs.iter()
                    .any(|e| e.row == 9 && e.field == "placedOnMarketDate"),
                "{category}: {errs:?}"
            );
        }
    }

    /// The refusal asks core, so it follows core's order: the date is asked
    /// before the operator's Art. 47 declaration, since a battery placed before
    /// 18 August 2027 is never asked for one. A declared exemption therefore does
    /// not excuse a missing date.
    #[test]
    fn a_declared_exemption_does_not_excuse_a_missing_date() {
        let mut row = battery_row();
        row.remove("placedOnMarketDate");
        row.insert(
            "dueDiligenceOperatorScope".into(),
            "belowTurnoverThreshold".into(),
        );
        let errs = validate_battery_row(&row, 4).expect_err("the date is still asked for");
        assert!(
            errs.iter()
                .any(|e| e.row == 4 && e.field == "placedOnMarketDate"),
            "{errs:?}"
        );
    }

    /// A portable battery carries no passport, so no content rule turns on its
    /// date and its row imports without one.
    #[test]
    fn a_portable_battery_imports_without_its_date() {
        let mut portable = battery_row();
        portable.remove("placedOnMarketDate");
        portable.insert("batteryType".into(), "portable".into());
        validate_battery_row(&portable, 1).expect("a portable battery needs no date");
    }

    /// A malformed date is reported once, as malformed, and not a second time as
    /// missing.
    #[test]
    fn a_malformed_placing_date_is_reported_once() {
        let mut row = battery_row();
        row.insert("placedOnMarketDate".into(), "18/02/2027".into());
        let errs = validate_battery_row(&row, 3).expect_err("a malformed date is refused");
        let date_errors = errs
            .iter()
            .filter(|e| e.field == "placedOnMarketDate")
            .count();
        assert_eq!(date_errors, 1, "{errs:?}");
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
            ("manufacturer_name".into(), "Example Batteries GmbH".into()),
            (
                "manufacturer_address".into(),
                "Prenzlauer Berg 12, 10405 Berlin, DE".into(),
            ),
            (
                "manufacturer_didWebUrl".into(),
                "https://batteries.example/.well-known/did.json".into(),
            ),
            ("batteryChemistry".into(), "LFP".into()),
            ("batteryType".into(), "industrial".into()),
            ("nominalVoltageV".into(), "48.0".into()),
            ("nominalCapacityAh".into(), "100.0".into()),
            ("expectedLifetimeCycles".into(), "3000".into()),
            ("co2ePerUnitKg".into(), "45.2".into()),
            ("placedOnMarketDate".into(), "2027-02-18".into()),
            ("recycledContentCobaltPct".into(), "0.0".into()),
            ("recycledContentLithiumPct".into(), "12.5".into()),
            ("recycledContentNickelPct".into(), "0.0".into()),
            ("stateOfHealthPct".into(), "100.0".into()),
            ("ratedCapacityKwh".into(), "4.8".into()),
            ("repairabilityScore".into(), "7.5".into()),
            ("material_1_name".into(), "Lithium Iron Phosphate".into()),
            ("material_1_weightKg".into(), "1.20".into()),
            ("material_1_recycledPct".into(), "12.5".into()),
            ("material_1_countryOfOrigin".into(), "CN".into()),
            ("material_2_name".into(), "Graphite".into()),
            ("material_2_weightKg".into(), "0.40".into()),
        ]);
        let req = validate_battery_row(&row, 1).expect("valid extended battery row");

        // Manufacturer aliases resolved (snake_case + full address + did:web).
        assert_eq!(req.manufacturer.name, "Example Batteries GmbH");
        assert!(req.manufacturer.address.contains("Berlin"));
        // A postal-address header states an address and not a country, so
        // nothing is invented for `country` — the whole point of reading the two
        // header groups apart. Asserting `address` alone would pass either way,
        // since it falls back to the country when no address is supplied.
        assert_eq!(req.manufacturer.country, None);
        assert_eq!(
            req.manufacturer.did_web_url.as_deref(),
            Some("https://batteries.example/.well-known/did.json")
        );
        assert_eq!(req.repairability_score, Some(7.5));

        // Bill of materials parsed (blank trailing slots skipped).
        let materials = req.materials.expect("materials parsed");
        assert_eq!(materials.len(), 2);
        assert_eq!(materials[0].name, "Lithium Iron Phosphate");
        assert_eq!(materials[0].weight_kg, 1.20);
        assert_eq!(materials[0].recycled_pct, Some(12.5));
        assert_eq!(materials[0].country_of_origin.as_deref(), Some("CN"));

        // Extended battery fields carried through (no longer dropped).
        match req.product_group_data.unwrap() {
            ProductGroupData::Battery(b) => {
                assert_eq!(b.recycled_content_lithium_pct, Some(12.5));
                assert_eq!(b.recycled_content_cobalt_pct, Some(0.0));
                assert_eq!(b.recycled_content_nickel_pct, Some(0.0));
                assert_eq!(b.state_of_health_pct, Some(100.0));
                assert_eq!(b.rated_capacity_kwh, Some(4.8));
            }
            _ => panic!("expected battery product_group data"),
        }
    }
}
