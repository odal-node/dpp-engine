//! Criterion benchmarks for Wasm plugin invocation throughput.
//!
//! Run with:
//! ```sh
//! rustup target add wasm32-wasip1 # for the `sdk_*` benches
//! cargo bench -p dpp-plugin-host
//! ```
//!
//! Every plugin these benches load is signed with a throwaway key and loaded
//! against it, the way `tests/sdk_abi.rs` does, so they take the verified path a
//! production plugin takes and need no `ALLOW_UNSIGNED_PLUGINS`.

use std::path::{Path, PathBuf};
use std::process::Command;

use criterion::{Criterion, criterion_group, criterion_main};
use dpp_plugin_host::{loader::LoadedPlugin, runtime::build_engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
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

/// Compile `wat_src` to `passthrough.wasm` in `dir` and return its path.
fn compile_wat(wat_src: &str, dir: &Path) -> PathBuf {
    let path = dir.join("passthrough.wasm");
    let wasm_bytes = wat::parse_str(wat_src).expect("WAT parse failed");
    std::fs::write(&path, wasm_bytes).expect("write wasm");
    path
}

/// Sign `wasm` the way a publisher does: a detached Ed25519 signature over its
/// SHA-256, written to `{wasm}.sig`. Returns the key the host must pin.
///
/// The host refuses an unsigned plugin unless `ALLOW_UNSIGNED_PLUGINS` is set,
/// and setting it means mutating the process environment. Signing instead loads
/// the plugin through the same verified path a production one takes. This repeats
/// `sign_fixture` in `tests/sdk_abi.rs`: a bench and a test target share no code.
fn sign(wasm: &Path) -> VerifyingKey {
    let key = SigningKey::from_bytes(&[11; 32]);
    let bytes = std::fs::read(wasm).expect("read wasm to sign");
    let signature = key.sign(&Sha256::digest(&bytes));
    let mut sig_path = wasm.as_os_str().to_owned();
    sig_path.push(".sig");
    std::fs::write(PathBuf::from(sig_path), signature.to_bytes()).expect("write .sig");
    key.verifying_key()
}

fn wasm_benchmarks(c: &mut Criterion) {
    let engine = build_engine().expect("build engine");
    let dir = tempfile::TempDir::new().expect("tempdir");
    let wasm = compile_wat(PASSTHROUGH_WAT, dir.path());
    let publisher = sign(&wasm);
    let plugin =
        LoadedPlugin::from_file(&engine, &wasm, "battery", Some(&publisher)).expect("load plugin");

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

    // Module instantiation benchmark (cold start), signature check included.
    c.bench_function("wasm_load_and_invoke", |b| {
        b.iter(|| {
            let p = LoadedPlugin::from_file(&engine, &wasm, "battery", Some(&publisher)).unwrap();
            p.invoke_calculate(&small_input).unwrap();
        });
    });
}

/// Build the `abi-echo` fixture to wasm32-wasip1 and return its path.
///
/// The fixture is an `export_plugin!` plugin built against the published
/// `dpp-plugin-sdk` at the version this workspace pins, the same crate
/// `tests/sdk_abi.rs` drives, so these benches read nothing from outside this
/// repository. It is detached from the workspace and builds into its own
/// `target/`.
///
/// Returns `None` (after a warning) if the build fails — e.g. the wasm32-wasip1
/// target is not installed — so the WAT floor benches still run. The WAT benches
/// measure the host round-trip floor; these add what the SDK-generated ABI costs
/// on top of it. The fixture echoes its input, so they do not measure any
/// product group's rules.
fn build_sdk_fixture_wasm() -> Option<PathBuf> {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/abi-echo");
    match Command::new(env!("CARGO"))
        .current_dir(&fixture_dir)
        .args(["build", "--release", "--target", "wasm32-wasip1"])
        .status()
    {
        Ok(s) if s.success() => {
            let wasm = fixture_dir.join("target/wasm32-wasip1/release/abi_echo.wasm");
            wasm.is_file().then_some(wasm)
        }
        _ => {
            eprintln!(
                "skipping sdk_* benches: failed to build the abi-echo fixture \
                 (is the wasm32-wasip1 target installed? `rustup target add wasm32-wasip1`)"
            );
            None
        }
    }
}

/// Benchmarks against a real SDK-generated plugin: the macro's linear-memory
/// packing, `describe`, and a cranelift compile of an LTO'd module.
fn sdk_benchmarks(c: &mut Criterion) {
    let Some(wasm) = build_sdk_fixture_wasm() else {
        return;
    };
    let engine = build_engine().expect("build engine");
    let publisher = sign(&wasm);
    let plugin = LoadedPlugin::from_file(&engine, &wasm, "abi-echo", Some(&publisher))
        .expect("load sdk fixture");
    let wasm_bytes = std::fs::read(&wasm).expect("read fixture wasm");

    // The fixture's `validate_input` wants a numeric `co2e` and ignores the rest.
    let small_input = serde_json::json!({ "co2e": 85.4 });
    // Same valid base padded with a large ignored array, to measure payload-size
    // scaling.
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
    c.bench_function("sdk_module_compile", |b| {
        b.iter(|| Module::new(&engine, &wasm_bytes).unwrap());
    });

    // Per-request cost: re-instantiate the already-compiled module + invoke.
    // (`invoke_calculate` builds a fresh store/linker and instantiates the
    // cached `Module` each call — it does NOT recompile.)
    c.bench_function("sdk_invoke_small_input", |b| {
        b.iter(|| plugin.invoke_calculate(&small_input).unwrap());
    });

    c.bench_function("sdk_invoke_large_input", |b| {
        b.iter(|| plugin.invoke_calculate(&large_input).unwrap());
    });

    // Full cold path for reference: signature check + compile + describe-probe +
    // invoke. Should ≈ sdk_module_compile + sdk_invoke_small_input (+ the probe
    // and the signature check).
    c.bench_function("sdk_load_and_invoke", |b| {
        b.iter(|| {
            let p = LoadedPlugin::from_file(&engine, &wasm, "abi-echo", Some(&publisher)).unwrap();
            p.invoke_calculate(&small_input).unwrap();
        });
    });
}

criterion_group!(benches, wasm_benchmarks, sdk_benchmarks);
criterion_main!(benches);
