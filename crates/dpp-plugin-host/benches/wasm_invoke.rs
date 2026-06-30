//! Criterion benchmarks for Wasm plugin invocation throughput.
//!
//! Run with:
//! ```sh
//! cargo bench -p dpp-plugin-host
//! ```

use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::Command;

use criterion::{Criterion, criterion_group, criterion_main};
use dpp_plugin_host::{loader::LoadedPlugin, runtime::build_engine};
use wasmtime::Module;

/// Minimal passthrough plugin (WAT) — returns hardcoded AbiResult envelope.
/// 55 bytes: `{"ok":{"complianceStatus":"PASSTHROUGH_NO_VALIDATION"}}`
const PASSTHROUGH_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"ok\":{\"complianceStatus\":\"PASSTHROUGH_NO_VALIDATION\"}}")

  (func (export "alloc") (param i32) (result i32)
    i32.const 4096)

  (func (export "dealloc") (param i32) (param i32))

  (func (export "calculate_metrics") (param i32) (param i32) (result i64)
    i64.const 55)
)
"#;

fn compile_wat(wat_src: &str) -> tempfile::NamedTempFile {
    let wasm_bytes = wat::parse_str(wat_src).expect("WAT parse failed");
    let mut f = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("tempfile failed");
    f.write_all(&wasm_bytes).unwrap();
    f.flush().unwrap();
    f
}

fn wasm_benchmarks(c: &mut Criterion) {
    let engine = build_engine().expect("build engine");
    let tmp = compile_wat(PASSTHROUGH_WAT);
    let plugin =
        LoadedPlugin::from_file(&engine, tmp.path(), "battery", None).expect("load plugin");

    let small_input = serde_json::json!({"chemistry": "LFP", "capacityKwh": 10.0});
    let large_input = serde_json::json!({
        "chemistry": "NMC811",
        "capacityKwh": 100.0,
        "nominalVoltage": 400.0,
        "modules": (0..50).map(|i| serde_json::json!({
            "moduleId": format!("mod-{i:03}"),
            "cells": 96,
            "temperatureC": 25.0 + (i as f64) * 0.1
        })).collect::<Vec<_>>()
    });

    c.bench_function("wasm_invoke_small_input", |b| {
        b.iter(|| plugin.invoke_calculate(&small_input).unwrap());
    });

    c.bench_function("wasm_invoke_large_input", |b| {
        b.iter(|| plugin.invoke_calculate(&large_input).unwrap());
    });

    // Module instantiation benchmark (cold start).
    c.bench_function("wasm_load_and_invoke", |b| {
        b.iter(|| {
            let p = LoadedPlugin::from_file(&engine, tmp.path(), "battery", None).unwrap();
            p.invoke_calculate(&small_input).unwrap();
        });
    });
}

/// Build the real `sector-battery` plugin to wasm32-wasip1 and return its path.
///
/// Returns `None` (after a warning) if the build fails — e.g. the wasm32-wasip1
/// target is not installed — so the WAT floor benches still run. Now that the
/// host wires sandboxed WASI, this real plugin actually instantiates; the WAT
/// benches measure the host round-trip floor, these measure battery logic.
fn build_battery_wasm() -> Option<PathBuf> {
    // dpp-engine/crates/dpp-plugin-host → Odal-Node → dpp-core/plugins/sector-battery
    let plugin_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dpp-core/plugins/sector-battery");
    match Command::new(env!("CARGO"))
        .current_dir(&plugin_dir)
        .args(["build", "--release", "--target", "wasm32-wasip1"])
        .status()
    {
        Ok(s) if s.success() => {
            let wasm = plugin_dir.join("target/wasm32-wasip1/release/sector_battery.wasm");
            wasm.is_file().then_some(wasm)
        }
        _ => {
            eprintln!(
                "skipping battery_* benches: failed to build sector-battery.wasm \
                 (is the wasm32-wasip1 target installed? `rustup target add wasm32-wasip1`)"
            );
            None
        }
    }
}

/// Benchmarks against the real `sector-battery` plugin (EU Battery Regulation
/// logic), so §1.3 can be quoted as a battery figure rather than the WAT floor.
fn battery_benchmarks(c: &mut Criterion) {
    let Some(wasm) = build_battery_wasm() else {
        return;
    };
    let engine = build_engine().expect("build engine");
    let plugin =
        LoadedPlugin::from_file(&engine, &wasm, "battery", None).expect("load battery plugin");
    let wasm_bytes = std::fs::read(&wasm).expect("read battery wasm");

    // Valid Battery Regulation input — passes the plugin's `validate_input`.
    let small_input = serde_json::json!({
        "gtin": "12345678901231",
        "batteryChemistry": "LFP",
        "nominalVoltageV": 48.0,
        "nominalCapacityAh": 100.0,
        "expectedLifetimeCycles": 3000,
        "co2ePerUnitKg": 85.4,
        "recycledContentCobaltPct": 16.0,
        "recycledContentLithiumPct": 6.0
    });
    // Same valid base padded with a large ignored array, to measure payload-size
    // scaling: the validator checks named fields only and ignores extras.
    let large_input = {
        let mut v = small_input.clone();
        v["telemetry"] = serde_json::json!(
            (0..200)
                .map(|i| serde_json::json!({
                    "cycle": i,
                    "sohPct": 100.0 - (i as f64) * 0.01,
                    "tempC": 25.0 + (i as f64) * 0.05
                }))
                .collect::<Vec<_>>()
        );
        v
    };

    // Cold-start cost #1: cranelift compilation of the (LTO'd) module. Bytes are
    // read once so this isolates compile from disk I/O. Paid once per plugin at
    // boot — the host caches the resulting `Module` in `LoadedPlugin`.
    c.bench_function("battery_module_compile", |b| {
        b.iter(|| Module::new(&engine, &wasm_bytes).unwrap());
    });

    // Per-request cost: re-instantiate the already-compiled module + invoke.
    // (`invoke_calculate` builds a fresh store/linker and instantiates the
    // cached `Module` each call — it does NOT recompile.)
    c.bench_function("battery_invoke_small_input", |b| {
        b.iter(|| plugin.invoke_calculate(&small_input).unwrap());
    });

    c.bench_function("battery_invoke_large_input", |b| {
        b.iter(|| plugin.invoke_calculate(&large_input).unwrap());
    });

    // Full cold path for reference: compile + describe-probe + invoke. Should
    // ≈ battery_module_compile + battery_invoke_small_input (+ the probe).
    c.bench_function("battery_load_and_invoke", |b| {
        b.iter(|| {
            let p = LoadedPlugin::from_file(&engine, &wasm, "battery", None).unwrap();
            p.invoke_calculate(&small_input).unwrap();
        });
    });
}

criterion_group!(benches, wasm_benchmarks, battery_benchmarks);
criterion_main!(benches);
