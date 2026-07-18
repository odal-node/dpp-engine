use std::path::Path;
use std::sync::Arc;

use dpp_domain::{
    domain::sector::{FibreEntry, Sector, SectorData, TextileData},
    ports::compliance::{ComplianceRegistry, ComplianceStatus},
};
use dpp_plugin_traits::{
    METRIC_CO2E_SCORE, METRIC_RECYCLED_CONTENT_PCT, METRIC_REPAIRABILITY_INDEX,
    PluginComplianceStatus, PluginResult,
};

use dpp_common::plugin_admin::{PluginAdmin, PluginInstallError};

use crate::loader::LoadedPlugin;
use crate::runtime::build_engine;
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
        gtin: "09506000134352".into(),
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
        gtin: "09506000134352".into(),
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

// ── hot-reload: atomic swap under load + last-good on rejection ────────────

/// Build a minimal sector plugin whose `describe()` advertises the given ABI
/// version and whose `calculate_metrics` returns a fixed `co2e_score` (so two
/// builds are behaviourally distinguishable). Input is ignored — the exports
/// return pointers into canned `data` segments, mirroring the loader-test
/// fixtures. An `abi_major` ahead of the host makes the load gate refuse it.
fn plugin_wasm(abi_major: u32, abi_minor: u32, co2e: f64) -> Vec<u8> {
    let describe = format!(
        r#"{{"abiVersion":{{"major":{abi_major},"minor":{abi_minor}}},"supportedSchemas":[],"capabilities":[]}}"#
    );
    let calc =
        format!(r#"{{"ok":{{"complianceStatus":"COMPLIANT","metrics":{{"co2e_score":{co2e}}}}}}}"#);
    let describe_off = 4096u32;
    let calc_off = 8192u32;
    let pack = |o: u32, l: u32| (((o as u64) << 32) | l as u64) as i64;
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let wat = format!(
        r#"(module
  (memory (export "memory") 2)
  (data (i32.const {describe_off}) "{d}")
  (data (i32.const {calc_off}) "{c}")
  (func (export "alloc") (param i32) (result i32) i32.const 1024)
  (func (export "dealloc") (param i32) (param i32))
  (func (export "describe") (result i64) i64.const {dp})
  (func (export "calculate_metrics") (param i32) (param i32) (result i64) i64.const {cp})
)"#,
        d = esc(&describe),
        c = esc(&calc),
        dp = pack(describe_off, describe.len() as u32),
        cp = pack(calc_off, calc.len() as u32),
    );
    wat::parse_str(&wat).expect("hot-reload fixture WAT must parse")
}

fn write_wasm(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Load a fixture in dev mode (no publisher key). Mirrors the loader tests'
/// convention; every caller sets the same env value so concurrent sets are benign.
fn load_dev(engine: &wasmtime::Engine, path: &Path) -> LoadedPlugin {
    unsafe { std::env::set_var("DPP_ALLOW_UNSIGNED_PLUGINS", "true") };
    LoadedPlugin::from_file(engine, path, "battery", None).expect("dev-mode load")
}

/// Green test (the ruleset hot-swap shape, reused): while worker threads hammer
/// the registered plugin, a v2 is swapped in mid-flight — no invocation may fail,
/// and the swap is observed live (v1 before, v2 after).
#[test]
fn hot_swap_under_load_never_drops_a_request() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let v1_path = write_wasm(&dir, "sector-battery.wasm", &plugin_wasm(1, 0, 1.5));

    let host = Arc::new(WasmPluginHost::new());
    host.register("battery".into(), load_dev(&engine, &v1_path));

    let input = serde_json::json!({});
    let errors = Arc::new(AtomicUsize::new(0));
    let v1_seen = Arc::new(AtomicU64::new(0));
    let v2_seen = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let host = host.clone();
        let errors = errors.clone();
        let v1_seen = v1_seen.clone();
        let v2_seen = v2_seen.clone();
        let input = input.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..300 {
                match host.get_plugin("battery") {
                    Some(p) => match p.invoke_calculate(&input) {
                        Ok(r) => {
                            let v = r.co2e_score.unwrap_or(f64::NAN);
                            if (v - 1.5).abs() < 1e-9 {
                                v1_seen.fetch_add(1, Ordering::Relaxed);
                            } else if (v - 2.5).abs() < 1e-9 {
                                v2_seen.fetch_add(1, Ordering::Relaxed);
                            } else {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    None => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Swap only once v1 has been observed live, so the flip is genuinely
    // concurrent. Bounded so a broken fixture fails an assertion instead of hanging.
    let start = std::time::Instant::now();
    while v1_seen.load(Ordering::Relaxed) == 0
        && start.elapsed() < std::time::Duration::from_secs(5)
    {
        std::thread::yield_now();
    }
    let v2_path = write_wasm(&dir, "sector-battery-v2.wasm", &plugin_wasm(1, 0, 2.5));
    host.reload_plugin(load_dev(&engine, &v2_path));

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "no invocation may fail across a hot-swap"
    );
    assert!(
        v1_seen.load(Ordering::Relaxed) > 0,
        "v1 must have served before the swap"
    );
    assert!(
        v2_seen.load(Ordering::Relaxed) > 0,
        "v2 must have served after the swap (live flip)"
    );

    let final_score = host
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&input)
        .unwrap()
        .co2e_score
        .unwrap();
    assert!(
        (final_score - 2.5).abs() < 1e-9,
        "final state must be the swapped-in v2"
    );
}

/// Green test: an artifact that fails the load gate never reaches the swap, so
/// the previously bound plugin keeps serving (last-good discipline). Here the
/// replacement is ABI-incompatible; the same holds for any `from_file` failure
/// (bad signature, non-compiling module) — all reject before `reload_plugin`.
#[test]
fn rejected_reload_leaves_previous_plugin_serving() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let v1_path = write_wasm(&dir, "sector-battery.wasm", &plugin_wasm(1, 0, 1.5));

    let host = WasmPluginHost::new();
    host.register("battery".into(), load_dev(&engine, &v1_path));

    // A replacement declaring a future major ABI: the load gate refuses it.
    let bad_path = write_wasm(&dir, "sector-battery-bad.wasm", &plugin_wasm(2, 0, 9.9));
    unsafe { std::env::set_var("DPP_ALLOW_UNSIGNED_PLUGINS", "true") };
    let rejected = LoadedPlugin::from_file(&engine, &bad_path, "battery", None);
    assert!(
        rejected.is_err(),
        "ABI-incompatible artifact must be refused before any swap"
    );

    // v1 is still bound and serving its original result.
    let score = host
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!(
        (score - 1.5).abs() < 1e-9,
        "the previous plugin must keep serving after a rejected reload"
    );
}

// ── runtime install (verify → persist → swap) + restart convergence ────────

/// Detached signature bytes over `SHA-256(wasm)`, as `install` expects.
fn sign_wasm(key: &ed25519_dalek::SigningKey, wasm: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(wasm);
    key.sign(&digest).to_bytes().to_vec()
}

/// Mimic `dpp-node`'s boot load loop against a persisted plugins dir — a fresh
/// host that re-discovers and re-verifies what a prior install wrote.
fn reboot(
    engine: &wasmtime::Engine,
    dir: &Path,
    key: &ed25519_dalek::VerifyingKey,
) -> WasmPluginHost {
    let host = WasmPluginHost::new();
    for (sector, path) in crate::loader::discover_plugins(dir).unwrap() {
        let plugin = LoadedPlugin::from_file(engine, &path, &sector, Some(key)).unwrap();
        host.register(sector, plugin);
    }
    host
}

#[test]
fn install_verifies_persists_and_serves() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let host = WasmPluginHost::with_runtime(
        engine,
        Some(signer.verifying_key()),
        dir.path().to_path_buf(),
    );

    let wasm = plugin_wasm(1, 0, 1.5);
    let sig = sign_wasm(&signer, &wasm);
    let report = host
        .install("battery", wasm, sig, false)
        .expect("a correctly signed plugin must install");
    assert_eq!(report.sector, "battery");
    assert_eq!(report.abi_version, "1.0");

    // Serving.
    let score = host
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!((score - 1.5).abs() < 1e-9);

    // Persisted so a restart re-loads it, and no staging dir left behind.
    assert!(dir.path().join("sector-battery.wasm").exists());
    assert!(dir.path().join("sector-battery.wasm.sig").exists());
    let leftover: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".staging-"))
        .collect();
    assert!(leftover.is_empty(), "staging dir must be cleaned up");
}

/// Green test #5: a node restart converges to the installed set.
#[test]
fn install_then_restart_converges_to_installed_set() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let pubkey = signer.verifying_key();

    let host = WasmPluginHost::with_runtime(engine.clone(), Some(pubkey), dir.path().to_path_buf());
    let wasm = plugin_wasm(1, 0, 2.5);
    let sig = sign_wasm(&signer, &wasm);
    host.install("battery", wasm, sig, false).expect("install");

    // Fresh host, same dir + pinned key → must serve the installed plugin.
    let rebooted = reboot(&engine, dir.path(), &pubkey);
    let score = rebooted
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!(
        (score - 2.5).abs() < 1e-9,
        "a restart must re-load the installed plugin"
    );
}

/// Last-good: a rejected install never overwrites the live file or the registry.
#[test]
fn install_rejecting_bad_signature_keeps_previous() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let host = WasmPluginHost::with_runtime(
        engine,
        Some(signer.verifying_key()),
        dir.path().to_path_buf(),
    );

    // Good v1 installed and serving.
    let v1 = plugin_wasm(1, 0, 1.5);
    let v1_sig = sign_wasm(&signer, &v1);
    host.install("battery", v1, v1_sig, false)
        .expect("v1 install");

    // v2 signed by the wrong key → rejected before any swap or overwrite.
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let v2 = plugin_wasm(1, 0, 2.5);
    let bad_sig = sign_wasm(&wrong, &v2);
    let err = host.install("battery", v2, bad_sig, false).unwrap_err();
    assert!(matches!(err, PluginInstallError::Rejected(_)), "got: {err}");

    // v1 still serving.
    let score = host
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!(
        (score - 1.5).abs() < 1e-9,
        "the previous plugin must survive a rejected install"
    );

    // And a restart still converges to v1 (the live file was not overwritten).
    let rebooted = reboot(
        &build_engine().unwrap(),
        dir.path(),
        &signer.verifying_key(),
    );
    let rescore = rebooted
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!((rescore - 1.5).abs() < 1e-9, "on-disk file must remain v1");
}

#[test]
fn install_not_supported_on_passthrough_host() {
    let host = WasmPluginHost::new();
    let err = host
        .install("battery", vec![0u8; 8], vec![0u8; 64], false)
        .unwrap_err();
    assert!(
        matches!(err, PluginInstallError::NotSupported),
        "got: {err}"
    );
}

/// A crafted sector key must not escape the plugins directory (path traversal),
/// even from an admin caller — it is rejected before any file is written.
#[test]
fn install_rejects_path_traversal_sector() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
    let host = WasmPluginHost::with_runtime(
        engine,
        Some(signer.verifying_key()),
        dir.path().to_path_buf(),
    );

    let wasm = plugin_wasm(1, 0, 1.5);
    let sig = sign_wasm(&signer, &wasm);
    for bad in ["../../evil", "a/b", "a\\b", "Battery", "sector.evil", ""] {
        let err = host
            .install(bad, wasm.clone(), sig.clone(), false)
            .unwrap_err();
        assert!(
            matches!(err, PluginInstallError::Rejected(_)),
            "sector '{bad}' must be rejected, got: {err}"
        );
    }
    // No file was created anywhere in (or escaping) the plugins dir.
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "a rejected sector must not create any file"
    );
}

// ── AOT: signed precompiled `.cwasm` install ──────────────────────────────

/// Precompile a `.wasm` into this engine's AOT (`.cwasm`) bytes.
fn precompile(engine: &wasmtime::Engine, wasm: &[u8]) -> Vec<u8> {
    engine
        .precompile_module(wasm)
        .expect("engine must precompile the fixture")
}

#[test]
fn install_precompiled_cwasm_serves_and_persists() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let host = WasmPluginHost::with_runtime(
        engine.clone(),
        Some(signer.verifying_key()),
        dir.path().to_path_buf(),
    );

    let cwasm = precompile(&engine, &plugin_wasm(1, 0, 3.5));
    let sig = sign_wasm(&signer, &cwasm);
    let report = host
        .install("battery", cwasm, sig, true)
        .expect("a signed, engine-compatible .cwasm must install");
    assert_eq!(report.sector, "battery");

    let score = host
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!((score - 3.5).abs() < 1e-9);

    // Persisted as `.cwasm` (not `.wasm`).
    assert!(dir.path().join("sector-battery.cwasm").exists());
    assert!(dir.path().join("sector-battery.cwasm.sig").exists());
    assert!(!dir.path().join("sector-battery.wasm").exists());
}

/// Restart convergence holds for AOT too: a fresh host deserializes the
/// persisted `.cwasm` and serves it.
#[test]
fn install_precompiled_then_restart_converges() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
    let pubkey = signer.verifying_key();
    let host = WasmPluginHost::with_runtime(engine.clone(), Some(pubkey), dir.path().to_path_buf());

    let cwasm = precompile(&engine, &plugin_wasm(1, 0, 4.5));
    let sig = sign_wasm(&signer, &cwasm);
    host.install("battery", cwasm, sig, true).expect("install");

    let rebooted = reboot(&engine, dir.path(), &pubkey);
    let score = rebooted
        .get_plugin("battery")
        .unwrap()
        .invoke_calculate(&serde_json::json!({}))
        .unwrap()
        .co2e_score
        .unwrap();
    assert!(
        (score - 4.5).abs() < 1e-9,
        "restart must re-load the .cwasm"
    );
}

/// Green test #4: an artifact that is not a valid precompiled module for this
/// engine is refused (deserialize's embedded engine/target compatibility check),
/// even when its signature is valid — it never loads. Feeding plain `.wasm`
/// bytes down the precompiled path stands in for a foreign-engine/version
/// `.cwasm`: both fail the same header check.
#[test]
fn install_rejects_incompatible_precompiled_artifact() {
    let engine = build_engine().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
    let host = WasmPluginHost::with_runtime(
        engine,
        Some(signer.verifying_key()),
        dir.path().to_path_buf(),
    );

    // Correctly signed, but the bytes are a plain module, not a precompiled
    // artifact for this engine — so `precompiled = true` must be rejected.
    let not_cwasm = plugin_wasm(1, 0, 1.5);
    let sig = sign_wasm(&signer, &not_cwasm);
    let err = host.install("battery", not_cwasm, sig, true).unwrap_err();
    assert!(matches!(err, PluginInstallError::Rejected(_)), "got: {err}");

    // Nothing was installed or persisted.
    assert!(host.get_plugin("battery").is_none());
    assert!(!dir.path().join("sector-battery.cwasm").exists());
}
