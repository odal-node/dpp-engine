use std::path::Path;

use dpp_domain::{
    domain::sector::{FibreEntry, Sector, SectorData, TextileData},
    ports::compliance::{ComplianceRegistry, ComplianceStatus},
};
use dpp_plugin_traits::{
    METRIC_CO2E_SCORE, METRIC_RECYCLED_CONTENT_PCT, METRIC_REPAIRABILITY_INDEX,
    PluginComplianceStatus, PluginResult,
};

use crate::{WasmPluginHost, plugin_result_to_compliance};

// Sector → catalog key mapping is `Sector::catalog_key()` in dpp-core (tested there).

// ── plugin_result_to_compliance() ────────────────────────────────────────

#[test]
fn converts_compliant_status() {
    let pr = PluginResult::new(PluginComplianceStatus::Compliant)
        .with_metric(METRIC_CO2E_SCORE, 42.0)
        .with_metric(METRIC_REPAIRABILITY_INDEX, 7.5)
        .with_metric(METRIC_RECYCLED_CONTENT_PCT, 30.0);
    let cr = plugin_result_to_compliance(&pr);
    assert_eq!(cr.compliance_status, ComplianceStatus::Compliant);
    assert_eq!(cr.co2e_score, Some(42.0));
    assert_eq!(cr.repairability_index, Some(7.5));
    assert_eq!(cr.recycled_content_pct, Some(30.0));
}

#[test]
fn converts_non_compliant_status() {
    let pr = PluginResult::new(PluginComplianceStatus::NonCompliant);
    let cr = plugin_result_to_compliance(&pr);
    assert_eq!(cr.compliance_status, ComplianceStatus::NonCompliant);
}

#[test]
fn converts_passthrough_status() {
    let pr = PluginResult::new(PluginComplianceStatus::PassthroughNoValidation);
    let cr = plugin_result_to_compliance(&pr);
    assert_eq!(
        cr.compliance_status,
        ComplianceStatus::PassthroughNoValidation
    );
}

#[test]
fn converts_not_assessed_status() {
    let pr = PluginResult::new(PluginComplianceStatus::NotAssessed);
    let cr = plugin_result_to_compliance(&pr);
    assert_eq!(cr.compliance_status, ComplianceStatus::NotAssessed);
}

#[test]
fn not_implemented_status_round_trips() {
    let pr = PluginResult::new(PluginComplianceStatus::NotImplemented);
    let cr = plugin_result_to_compliance(&pr);
    assert_eq!(cr.compliance_status, ComplianceStatus::NotImplemented);
}

#[test]
fn maps_plugin_findings_into_compliance_result() {
    use dpp_plugin_traits::PluginFinding;
    let pr = PluginResult::new(PluginComplianceStatus::NotAssessed)
        .with_warning(PluginFinding::new(
            "battery.recycled_content.cobalt_below_2031_target",
            "/recycledContentCobaltPct",
            "below target",
        ))
        .with_violation(PluginFinding::new("test.binding", "/x", "blocks"));
    let cr = plugin_result_to_compliance(&pr);
    assert_eq!(cr.warnings.len(), 1);
    assert_eq!(
        cr.warnings[0].code,
        "battery.recycled_content.cobalt_below_2031_target"
    );
    assert_eq!(cr.warnings[0].field, "/recycledContentCobaltPct");
    assert_eq!(cr.violations.len(), 1);
    assert_eq!(cr.violations[0].code, "test.binding");
}

// ── WasmPluginHost (no plugins loaded) ───────────────────────────────────

#[test]
fn empty_host_has_no_plugins() {
    let host = WasmPluginHost::new();
    assert!(!host.has_any_plugin());
}

#[test]
fn empty_host_reports_no_sector_plugin() {
    use dpp_domain::ports::plugin_host_port::PluginHost;
    let host = WasmPluginHost::new();
    assert!(!host.has_plugin(&Sector::Battery));
    assert!(!host.has_plugin(&Sector::Textile));
    assert!(!host.has_plugin(&Sector::Steel));
}

#[test]
fn empty_host_compliance_returns_passthrough() {
    let host = WasmPluginHost::new();
    let data = SectorData::Textile(TextileData {
        fibre_composition: vec![FibreEntry {
            fibre: "Cotton".into(),
            pct: 100.0,
            country_of_origin: None,
        }],
        country_of_manufacturing: "DE".into(),
        care_instructions: "Machine wash".into(),
        chemical_compliance_standard: "OEKO-TEX 100".into(),
        recycled_content_pct: None,
        repair_score: None,
        carbon_footprint_kg_co2e: None,
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
    let result = ComplianceRegistry::compute(&host, Sector::Textile, &data).unwrap();
    assert_eq!(
        result.compliance_status,
        ComplianceStatus::PassthroughNoValidation
    );
    assert!(result.co2e_score.is_none());
}

#[test]
fn default_trait_creates_empty_host() {
    let host = WasmPluginHost::default();
    assert!(!host.has_any_plugin());
}

// ── discover_plugins() ──────────────────────────────────────────────────

#[test]
fn discover_returns_empty_for_missing_dir() {
    let result = crate::loader::discover_plugins(Path::new("/nonexistent/dir"));
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn discover_returns_empty_for_empty_dir() {
    let tmp = std::env::temp_dir().join(format!("odal-test-empty-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).unwrap();
    let result = crate::loader::discover_plugins(&tmp);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn discover_finds_wasm_files() {
    let tmp = std::env::temp_dir().join(format!("odal-test-plugins-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("sector-textile.wasm"), b"fake").unwrap();
    std::fs::write(tmp.join("sector-battery.wasm"), b"fake").unwrap();
    std::fs::write(tmp.join("readme.txt"), b"not a plugin").unwrap();

    let result = crate::loader::discover_plugins(&tmp).unwrap();
    assert_eq!(result.len(), 2);

    let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"textile"));
    assert!(keys.contains(&"battery"));

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn discover_strips_sector_prefix() {
    let tmp = std::env::temp_dir().join(format!("odal-test-prefix-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("sector-steel.wasm"), b"fake").unwrap();

    let result = crate::loader::discover_plugins(&tmp).unwrap();
    assert_eq!(result[0].0, "steel");

    std::fs::remove_dir_all(&tmp).ok();
}

// ── enrich_input() ───────────────────────────────────────────────────────

#[test]
fn enrich_input_adds_is_in_force_flag() {
    use crate::host::enrich_input;
    let input = serde_json::json!({"gtin": "12345678901234", "co2ePerUnitKg": 1.5});
    let enriched = enrich_input(input, "battery");
    // Must contain the injected flag (battery is in-force).
    assert!(enriched.get("__isInForce").is_some());
    assert!(enriched.get("gtin").is_some(), "original fields preserved");
}

#[test]
fn enrich_input_non_object_passes_through() {
    use crate::host::enrich_input;
    let input = serde_json::json!("not an object");
    let enriched = enrich_input(input.clone(), "battery");
    assert_eq!(enriched, input, "non-object input must not be modified");
}

// ── generate_passport_payload() ──────────────────────────────────────────

#[test]
fn generate_passport_payload_no_plugin_returns_unknown_sector() {
    let host = WasmPluginHost::new();
    let data = SectorData::Textile(TextileData {
        fibre_composition: vec![FibreEntry {
            fibre: "Cotton".into(),
            pct: 100.0,
            country_of_origin: None,
        }],
        country_of_manufacturing: "DE".into(),
        care_instructions: "Machine wash".into(),
        chemical_compliance_standard: "OEKO-TEX 100".into(),
        recycled_content_pct: None,
        repair_score: None,
        carbon_footprint_kg_co2e: None,
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
    let result = host.generate_passport_payload(&Sector::Textile, &data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        err.kind,
        dpp_domain::ports::compliance::ComplianceErrorKind::UnknownSector
    );
}

// ── runtime ──────────────────────────────────────────────────────────────

#[test]
fn build_engine_succeeds() {
    let engine = crate::runtime::build_engine();
    assert!(engine.is_ok());
}

#[test]
fn build_store_has_fuel() {
    let engine = crate::runtime::build_engine().unwrap();
    let store = crate::runtime::build_store(&engine, None, None).unwrap();
    assert!(store.get_fuel().unwrap() > 0);
}

#[test]
fn build_store_fuel_equals_default() {
    let engine = crate::runtime::build_engine().unwrap();
    let store = crate::runtime::build_store(&engine, None, None).unwrap();
    assert_eq!(store.get_fuel().unwrap(), crate::runtime::DEFAULT_FUEL);
}

/// Regression (W-9): the 64 MiB memory cap must be enforced by the sandbox.
///
/// A plugin starting with 1 page (64 KiB) that attempts to grow by 1024 pages
/// reaches 1025 pages = 67_174_400 bytes which exceeds `DEFAULT_MEMORY_CAP_BYTES`
/// (67_108_864). The `memory.grow` instruction must return -1 (growth refused),
/// not succeed and not cause an OOM on the host.
#[test]
fn memory_growth_beyond_cap_is_refused() {
    let engine = crate::runtime::build_engine().unwrap();
    let mut store = crate::runtime::build_store(&engine, None, None).unwrap();

    // WAT: starts with 1 page, tries to grow by 1024 pages → total 1025 pages
    // (67_174_400 bytes) which exceeds the 64 MiB cap.
    let wat_src = r#"
        (module
          (memory 1)
          (func (export "try_grow") (result i32)
            i32.const 1024
            memory.grow)
        )
    "#;

    let wasm = wat::parse_str(wat_src).expect("parse WAT");
    let module = wasmtime::Module::new(&engine, &wasm).expect("compile WAT module");
    let linker = wasmtime::Linker::<crate::runtime::HostState>::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate WAT module");

    let grow = instance
        .get_typed_func::<(), i32>(&mut store, "try_grow")
        .expect("get try_grow func");

    let result = grow.call(&mut store, ()).expect("call try_grow");

    assert_eq!(
        result, -1,
        "memory.grow beyond 64 MiB cap must return -1 (growth refused)"
    );
}
