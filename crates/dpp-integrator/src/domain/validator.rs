//! Row-level validation for each supported import sector.
//! Converts raw CSV/XLSX string maps into typed `CreatePassportRequest` values.

use std::collections::HashMap;

use dpp_domain::domain::{
    gtin::Gtin,
    passport::{ManufacturerInfo, MaterialEntry},
    sector::{
        AluminiumData, BatteryChemistry, BatteryData, BatteryType, CarbonFootprintClass,
        FibreEntry, ProductionRoute, Sector, SectorData, SteelData, TextileData, TyreData,
    },
};
use serde::Serialize;

// ─── Output type ─────────────────────────────────────────────────────────────

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

// ─── Battery validation ───────────────────────────────────────────────────────

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

// ─── Textile validation ───────────────────────────────────────────────────────

/// Validate a single textile row and convert it to a vault `CreatePassportRequest`.
pub fn validate_textile_row(
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();

    let product_name = require_str(row, "productName", row_num, &mut errors);
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

// ─── Steel validation ─────────────────────────────────────────────────────────

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

// ─── Aluminium validation ─────────────────────────────────────────────────────

/// Validate a single aluminium row and convert it to a vault `CreatePassportRequest`.
///
/// Expected CSV columns: `productName`, `batchId` (opt), `manufacturerName`,
/// `manufacturerCountry`, `gtin`, `alloyGrade`, `productionRoute`,
/// `co2ePerTonneKg`, `recycledContentPct`, `countryOfProduction`,
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
    let gtin = require_str(row, "gtin", row_num, &mut errors);
    let alloy_grade = require_str(row, "alloyGrade", row_num, &mut errors);
    let production_route_raw = require_str(row, "productionRoute", row_num, &mut errors);
    let co2e = require_f64(row, "co2ePerTonneKg", row_num, &mut errors);
    let recycled = require_f64(row, "recycledContentPct", row_num, &mut errors);
    let country_of_production = require_str(row, "countryOfProduction", row_num, &mut errors);
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
        sector: Some(Sector::Aluminium),
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
        sector_data: Some(SectorData::Aluminium(AluminiumData {
            gtin: gtin.expect("field verified present by errors.is_empty() guard above"),
            alloy_grade: alloy_grade
                .expect("field verified present by errors.is_empty() guard above"),
            production_route,
            co2e_per_tonne_kg: co2e
                .expect("field verified present by errors.is_empty() guard above"),
            recycled_content_pct: recycled
                .expect("field verified present by errors.is_empty() guard above"),
            country_of_production: country_of_production
                .expect("field verified present by errors.is_empty() guard above"),
            annual_production_tonnes: annual,
        })),
        batch_id,
        schema_version: None,
    })
}

// ─── Tyre validation ──────────────────────────────────────────────────────────

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

// ─── Field extraction helpers ─────────────────────────────────────────────────

/// Normalize a header key for case/separator-insensitive matching: drop
/// non-alphanumerics (`_`, `-`, spaces) and lowercase. So `manufacturerName`,
/// `manufacturer_name`, and `Manufacturer Name` all map to `manufacturername`.
fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Look up a field tolerantly: exact key first, then a case/separator-insensitive
/// match. This lets **every** sector validator accept both camelCase and
/// snake_case headers (`manufacturerName` ≡ `manufacturer_name`) with no per-field
/// alias lists. Semantically-different headers (e.g. `manufacturerCountry` vs a
/// full `manufacturer_address`) still need explicit aliases via [`aliased`].
fn get_field<'a>(row: &'a HashMap<String, String>, field: &str) -> Option<&'a String> {
    if let Some(v) = row.get(field) {
        return Some(v);
    }
    let target = normalize_key(field);
    row.iter()
        .find(|(k, _)| normalize_key(k) == target)
        .map(|(_, v)| v)
}

fn require_str(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<String> {
    match get_field(row, field).filter(|v| !v.trim().is_empty()) {
        Some(v) => Some(v.clone()),
        None => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("{field} is required"),
            });
            None
        }
    }
}

fn require_f64(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<f64> {
    let raw = require_str(row, field, row_num, errors)?;
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() => Some(v),
        Ok(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a finite number, got '{raw}'"),
            });
            None
        }
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a number, got '{raw}'"),
            });
            None
        }
    }
}

fn require_u32(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<u32> {
    let raw = require_str(row, field, row_num, errors)?;
    match raw.parse::<u32>() {
        Ok(v) => Some(v),
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a positive integer, got '{raw}'"),
            });
            None
        }
    }
}

fn optional_f64(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<f64> {
    let raw = get_field(row, field).filter(|v| !v.trim().is_empty())?;
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() => Some(v),
        Ok(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a finite number, got '{raw}'"),
            });
            None
        }
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a number, got '{raw}'"),
            });
            None
        }
    }
}

fn optional_str(row: &HashMap<String, String>, field: &str) -> Option<String> {
    get_field(row, field)
        .filter(|v| !v.trim().is_empty())
        .cloned()
}

/// First present, non-empty value among header `aliases`. Each alias is matched
/// case/separator-insensitively via [`get_field`], so the list only needs to
/// cover *semantic* variants (e.g. `manufacturerCountry` vs `manufacturerAddress`).
fn aliased<'a>(row: &'a HashMap<String, String>, aliases: &[&str]) -> Option<&'a String> {
    aliases
        .iter()
        .find_map(|k| get_field(row, k).filter(|v| !v.trim().is_empty()))
}

/// Required string accepting any of `aliases`; reports the error under `canonical`.
fn require_aliased(
    row: &HashMap<String, String>,
    aliases: &[&str],
    canonical: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<String> {
    match aliased(row, aliases) {
        Some(v) => Some(v.clone()),
        None => {
            errors.push(RowError {
                row: row_num,
                field: canonical.to_owned(),
                message: format!("{canonical} is required"),
            });
            None
        }
    }
}

/// Maximum `material_N_*` column groups parsed from a row.
const MAX_MATERIAL_COLUMNS: usize = 10;

/// Parse `material_N_name` / `_weightKg` / `_recycledPct` / `_originCountry`
/// column groups into a bill of materials. Groups with a blank name are skipped
/// (handles trailing empty material slots in templates).
fn parse_materials(row: &HashMap<String, String>) -> Vec<MaterialEntry> {
    let mut out = Vec::new();
    for i in 1..=MAX_MATERIAL_COLUMNS {
        let name =
            match get_field(row, &format!("material_{i}_name")).filter(|v| !v.trim().is_empty()) {
                Some(n) => n.clone(),
                None => continue,
            };
        let weight_kg = get_field(row, &format!("material_{i}_weightKg"))
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(0.0);
        let recycled_pct = get_field(row, &format!("material_{i}_recycledPct"))
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite());
        let origin_country = get_field(row, &format!("material_{i}_originCountry"))
            .filter(|v| !v.trim().is_empty())
            .cloned();
        out.push(MaterialEntry {
            name,
            weight_kg,
            recycled_pct,
            origin_country,
        });
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Empty-row smoke tests: guard must return Err, not panic.
    #[test]
    fn empty_row_battery_returns_err() {
        assert!(validate_battery_row(&HashMap::new(), 1).is_err());
    }

    #[test]
    fn empty_row_textile_returns_err() {
        assert!(validate_textile_row(&HashMap::new(), 1).is_err());
    }

    #[test]
    fn empty_row_steel_returns_err() {
        assert!(validate_steel_row(&HashMap::new(), 1).is_err());
    }

    #[test]
    fn empty_row_aluminium_returns_err() {
        assert!(validate_aluminium_row(&HashMap::new(), 1).is_err());
    }

    #[test]
    fn empty_row_tyre_returns_err() {
        assert!(validate_tyre_row(&HashMap::new(), 1).is_err());
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

    #[test]
    fn get_field_matches_snake_and_camel() {
        let row = HashMap::from([("manufacturer_name".to_string(), "Acme".to_string())]);
        assert_eq!(
            get_field(&row, "manufacturerName").map(String::as_str),
            Some("Acme")
        );
        assert_eq!(
            get_field(&row, "manufacturer_name").map(String::as_str),
            Some("Acme")
        );
        assert_eq!(
            get_field(&row, "MANUFACTURERNAME").map(String::as_str),
            Some("Acme")
        );
        assert!(get_field(&row, "somethingElse").is_none());
    }

    /// The both-case lookup is general: a fully snake_case **textile** row
    /// validates without any per-field alias list (the original camelCase-only
    /// validator would have rejected it).
    #[test]
    fn snake_case_textile_row_validates_via_normalized_lookup() {
        let row = HashMap::from([
            ("product_name".to_string(), "Organic Cotton Tee".to_string()),
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
                assert_eq!(t.fibre_composition.len(), 1);
                assert_eq!(t.fibre_composition[0].fibre, "cotton");
            }
            _ => panic!("expected textile sector data"),
        }
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
            ("countryOfProduction".into(), "NO".into()),
        ])
    }

    #[test]
    fn valid_aluminium_row_produces_request() {
        let row = aluminium_row();
        let req = validate_aluminium_row(&row, 1).expect("valid aluminium row");
        assert_eq!(req.sector, Some(Sector::Aluminium));
        match req.sector_data.unwrap() {
            SectorData::Aluminium(d) => {
                assert_eq!(d.recycled_content_pct, 75.0);
                assert!(matches!(
                    d.production_route,
                    ProductionRoute::SecondaryRecycled
                ));
            }
            _ => panic!("expected aluminium sector data"),
        }
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
