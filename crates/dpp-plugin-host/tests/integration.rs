//! Integration tests for `dpp-plugin-host`.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-plugin-host --features integration-tests -- --nocapture
//! ```
//!
//! These tests compile minimal WAT (WebAssembly Text Format) modules at test
//! time to exercise the full load → sandbox → invoke pipeline without needing
//! pre-built `.wasm` sector plugin binaries.

#![cfg(feature = "integration-tests")]

use std::io::Write as IoWrite;

use dpp_domain::{
    domain::sector::{Sector, SectorData},
    ports::compliance::ComplianceRegistry,
};
use dpp_plugin_host::{
    WasmPluginHost,
    loader::{LoadedPlugin, discover_plugins},
    runtime::build_engine,
};

// ---------------------------------------------------------------------------
// WAT fixtures
// ---------------------------------------------------------------------------

/// A minimal compliant plugin:
/// - `alloc` returns a fixed offset (4096) — well past the response data.
/// - `dealloc` is a no-op (bump allocator never frees).
/// - `calculate_metrics` ignores its inputs and returns a hardcoded AbiResult
///   envelope at offset 0, length 55. The data segment at offset 0 holds the
///   response.
///
/// JSON: `{"ok":{"complianceStatus":"PASSTHROUGH_NO_VALIDATION"}}`  (55 bytes)
const PASSTHROUGH_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"ok\":{\"complianceStatus\":\"PASSTHROUGH_NO_VALIDATION\"}}")

  (func (export "alloc") (param i32) (result i32)
    i32.const 4096)

  (func (export "dealloc") (param i32) (param i32))

  (func (export "calculate_metrics") (param i32) (param i32) (result i64)
    ;; packed return: (out_ptr=0 << 32) | out_len=55
    i64.const 55)
)
"#;

/// A plugin that attempts to grow memory past the 64 MiB `ResourceLimiter` cap.
///
/// `memory.grow 1600` requests 100 MiB (1600 × 64 KiB). The limiter must
/// reject this and return -1.  If the limiter is absent, growth succeeds and
/// the WAT hits `unreachable`, making the test fail.  When the limiter works
/// correctly, the WAT takes the rejection path and returns the standard
/// passthrough AbiResult — but `invoke_calculate` then sees `memory_capped`
/// and surfaces the denial as an error (see `memory_cap_rejects_*`).
const MEMORY_OVERFLOW_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"ok\":{\"complianceStatus\":\"PASSTHROUGH_NO_VALIDATION\"}}")

  (func (export "alloc") (param i32) (result i32)
    i32.const 4096)

  (func (export "dealloc") (param i32) (param i32))

  (func (export "calculate_metrics") (param i32) (param i32) (result i64)
    ;; Request 1600 pages (100 MiB) — over the 64 MiB ResourceLimiter cap.
    ;; memory.grow returns -1 when rejected, a non-negative page count on success.
    i32.const 1600
    memory.grow
    i32.const -1
    i32.ne
    if
      ;; Growth succeeded — limiter is absent. Trap so the test fails loudly.
      unreachable
    end
    ;; Growth was correctly rejected. Return the standard passthrough result.
    i64.const 55)
)
"#;

/// A plugin whose `calculate_metrics` loops forever — used to verify the fuel
/// metering sandbox kills the invocation rather than hanging the host.
const INFINITE_LOOP_WAT: &str = r#"
(module
  (memory (export "memory") 1)

  (func (export "alloc") (param i32) (result i32)
    i32.const 4096)

  (func (export "dealloc") (param i32) (param i32))

  (func (export "calculate_metrics") (param i32) (param i32) (result i64)
    (loop $spin (br $spin))
    i64.const 0)
)
"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compile_wat_to_temp_file(wat_src: &str) -> tempfile::NamedTempFile {
    let wasm_bytes = wat::parse_str(wat_src).expect("WAT parse failed");
    let mut f = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("tempfile create failed");
    f.write_all(&wasm_bytes).expect("write wasm bytes failed");
    f.flush().expect("flush failed");
    f
}

/// Load a plugin the same way [`LoadedPlugin::from_file`] with `trusted_key:
/// None` used to, before unsigned loading required an explicit opt-in. These
/// tests load throwaway WAT fixtures, not real sector plugins, so unsigned
/// loading is the correct mode here — opt in for the duration of the call.
///
/// SAFETY: mutates a process-global env var; sound because nextest runs each
/// `#[test]` in its own process (unlike `cargo test`, which would race this
/// across threads in the same binary).
fn load_unsigned_test_plugin(
    engine: &wasmtime::Engine,
    path: &std::path::Path,
    sector_key: &str,
) -> anyhow::Result<LoadedPlugin> {
    unsafe { std::env::set_var("ALLOW_UNSIGNED_PLUGINS", "true") };
    LoadedPlugin::from_file(engine, path, sector_key, None)
}

fn battery_sector_data() -> SectorData {
    // Minimal battery input — the passthrough plugin ignores it but the host
    // still serialises it and writes it to Wasm memory, exercising that path.
    use dpp_domain::domain::{
        gtin::Gtin,
        sector::{BatteryChemistry, BatteryData},
    };
    SectorData::Battery(BatteryData {
        gtin: Gtin::parse("09506000134352").unwrap(),
        battery_chemistry: BatteryChemistry::Lfp,
        nominal_voltage_v: 400.0,
        nominal_capacity_ah: 100.0,
        expected_lifetime_cycles: 3000,
        co2e_per_unit_kg: 150.0,
        recycled_content_cobalt_pct: None,
        recycled_content_lithium_pct: None,
        recycled_content_nickel_pct: None,
        state_of_health_pct: None,
        rated_capacity_kwh: Some(40.0),
        carbon_footprint_class: None,
        due_diligence_url: None,
        cathode_material: None,
        anode_material: None,
        electrolyte_material: None,
        critical_raw_materials: None,
        disassembly_instructions_url: None,
        soh_methodology: None,
        operating_temp_min_c: None,
        operating_temp_max_c: None,
        rated_energy_wh: None,
        recycled_content_lead_pct: None,
        battery_weight_kg: None,
        battery_type: None,
        round_trip_efficiency_pct: None,
        internal_resistance_mohm: None,
        manufacturing_date: None,
        manufacturing_place: None,
        battery_model_id: None,
        battery_passport_number: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn passthrough_when_no_plugin_registered_for_sector() {
    let host = WasmPluginHost::new();
    let result = ComplianceRegistry::compute(&host, Sector::Battery, &battery_sector_data());
    let r = result.expect("passthrough must not error");
    assert!(
        matches!(
            r.compliance_status,
            dpp_domain::ports::compliance::ComplianceStatus::PassthroughNoValidation
        ),
        "empty host must return PassthroughNoValidation"
    );
    assert!(r.co2e_score.is_none());
    assert!(r.repairability_index.is_none());
}

#[test]
fn load_wat_plugin_and_invoke_calculate() {
    let engine = build_engine().expect("build engine failed");
    let tmp = compile_wat_to_temp_file(PASSTHROUGH_WAT);

    let plugin = load_unsigned_test_plugin(&engine, tmp.path(), "battery")
        .expect("LoadedPlugin::from_file failed");

    let input = serde_json::json!({"chemistry": "LFP", "capacityKwh": 10.0});
    let result = plugin
        .invoke_calculate(&input)
        .expect("invoke_calculate failed");

    assert!(
        matches!(
            result.compliance_status,
            dpp_domain::ports::compliance::ComplianceStatus::PassthroughNoValidation
        ),
        "WAT passthrough plugin must return PassthroughNoValidation; got {:?}",
        result.compliance_status
    );
}

#[test]
fn register_plugin_and_compute_via_host() {
    let engine = build_engine().expect("build engine");
    let tmp = compile_wat_to_temp_file(PASSTHROUGH_WAT);

    let plugin = load_unsigned_test_plugin(&engine, tmp.path(), "battery")
        .expect("LoadedPlugin::from_file failed");

    let host = WasmPluginHost::new();
    host.register("battery".into(), plugin);

    assert!(
        host.has_any_plugin(),
        "host should report a registered plugin"
    );

    let result = ComplianceRegistry::compute(&host, Sector::Battery, &battery_sector_data())
        .expect("compute failed");
    assert!(
        matches!(
            result.compliance_status,
            dpp_domain::ports::compliance::ComplianceStatus::PassthroughNoValidation
        ),
        "registered passthrough plugin must return PassthroughNoValidation"
    );
}

#[test]
fn fuel_exhaustion_returns_error_not_panic() {
    let engine = build_engine().expect("build engine");
    let tmp = compile_wat_to_temp_file(INFINITE_LOOP_WAT);

    let plugin = load_unsigned_test_plugin(&engine, tmp.path(), "battery")
        .expect("LoadedPlugin::from_file failed");

    let input = serde_json::json!({});
    let result = plugin.invoke_calculate(&input);

    assert!(
        result.is_err(),
        "infinite-loop plugin must return Err (fuel exhaustion), not hang or panic"
    );
    let err_msg = result.unwrap_err().to_string().to_lowercase();
    // Wasmtime surfaces fuel exhaustion as a trap (older) or "error while
    // executing" (Wasmtime ≥45). Any execution-termination message confirms
    // the sandbox killed the invocation rather than hanging the host.
    assert!(
        err_msg.contains("fuel")
            || err_msg.contains("trap")
            || err_msg.contains("out of")
            || err_msg.contains("executing"),
        "error must indicate sandbox termination, got: {err_msg}"
    );
}

/// Regression (W-9): the `ResourceLimiter` in `build_store` must enforce the
/// 64 MiB memory cap.  `MEMORY_OVERFLOW_WAT` requests 100 MiB; the limiter
/// denies it (`memory.grow` → -1, no host OOM) and sets `memory_capped`, which
/// `invoke_calculate` surfaces as a fail-closed error whose message contains
/// "memory cap" (runtime.rs / loader.rs contract; the host emits
/// PLUGIN_MEM_CAPPED off it). If the limiter were absent, the WAT would trap
/// via `unreachable` instead. Either way the invocation must NOT return `Ok`.
#[test]
fn memory_cap_rejects_over_budget_allocation() {
    let engine = build_engine().expect("build engine");
    let tmp = compile_wat_to_temp_file(MEMORY_OVERFLOW_WAT);

    let plugin = load_unsigned_test_plugin(&engine, tmp.path(), "battery")
        .expect("LoadedPlugin::from_file failed");

    let input = serde_json::json!({});
    let result = plugin.invoke_calculate(&input);

    let err = result
        .expect_err("over-budget growth must fail closed, not return Ok")
        .to_string()
        .to_lowercase();
    assert!(
        err.contains("memory cap"),
        "error must indicate the memory cap was hit, got: {err}"
    );
}

#[test]
fn discover_plugins_finds_wasm_files_in_dir() {
    let dir = tempfile::tempdir().expect("tempdir failed");

    // Create two fake .wasm files and one non-.wasm file.
    let wasm_bytes = wat::parse_str(PASSTHROUGH_WAT).expect("parse WAT");
    std::fs::write(dir.path().join("sector-battery.wasm"), &wasm_bytes).unwrap();
    std::fs::write(dir.path().join("sector-textile.wasm"), &wasm_bytes).unwrap();
    std::fs::write(dir.path().join("readme.txt"), b"ignored").unwrap();

    let found = discover_plugins(dir.path()).expect("discover_plugins failed");

    assert_eq!(found.len(), 2, "should find exactly 2 .wasm files");

    let keys: Vec<&str> = found.iter().map(|(k, _)| k.as_str()).collect();
    assert!(
        keys.contains(&"battery"),
        "should strip 'sector-' prefix → 'battery'"
    );
    assert!(
        keys.contains(&"textile"),
        "should strip 'sector-' prefix → 'textile'"
    );
}

#[test]
fn discover_plugins_empty_dir_returns_empty_vec() {
    let dir = tempfile::tempdir().expect("tempdir failed");
    let found = discover_plugins(dir.path()).expect("discover_plugins failed");
    assert!(found.is_empty());
}

#[test]
fn discover_plugins_nonexistent_dir_returns_empty_vec() {
    let path = std::path::Path::new("/nonexistent/plugins/dir");
    let found = discover_plugins(path).expect("should return Ok([]) for missing dir");
    assert!(found.is_empty());
}
