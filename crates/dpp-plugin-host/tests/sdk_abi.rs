//! Real-ABI integration test for the SDK `export_plugin!` macro.
//!
//! Compiles the minimal `abi-echo` fixture (`tests/fixtures/abi-echo`) to
//! wasm32-wasip1 and drives the SDK-generated ABI through the real wasmtime
//! host. Unlike the WAT fixtures in `integration.rs` — which hand-roll a fake
//! ABI and hardcode the packed return value — this exercises the macro's actual
//! linear-memory packing end-to-end: `alloc`/`dealloc`, `write_output`/
//! `read_input`, and the `describe`/`calculate_metrics`/`generate_passport`
//! exports as emitted by `export_plugin!`.
//!
//! Run with:
//! ```sh
//! rustup target add wasm32-wasip1
//! cargo test -p dpp-plugin-host --features wasm-fixture-tests --test sdk_abi
//! ```

#![cfg(feature = "wasm-fixture-tests")]

use std::path::{Path, PathBuf};
use std::process::Command;

use dpp_plugin_host::{loader::LoadedPlugin, runtime::build_engine};
use dpp_plugin_traits::AbiVersion;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Compile the `abi-echo` fixture to wasm32-wasip1 and return the artifact path.
///
/// The fixture is a workspace-detached crate, so this builds into its own
/// `target/` dir — no contention with the dpp-engine workspace target.
fn build_fixture_wasm() -> PathBuf {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/abi-echo");
    let status = Command::new(env!("CARGO"))
        .current_dir(&fixture_dir)
        .args(["build", "--release", "--target", "wasm32-wasip1"])
        .status()
        .expect("failed to spawn cargo to build the abi-echo fixture");
    assert!(
        status.success(),
        "abi-echo fixture failed to compile to wasm32-wasip1 \
         (is the target installed? `rustup target add wasm32-wasip1`)"
    );
    let wasm = fixture_dir.join("target/wasm32-wasip1/release/abi_echo.wasm");
    assert!(
        wasm.is_file(),
        "expected fixture wasm at {}",
        wasm.display()
    );
    wasm
}

/// Sign `wasm` the way a publisher does: a detached Ed25519 signature over its
/// SHA-256, written to `{wasm}.sig`. Returns the key the host must pin.
///
/// The host refuses an unsigned plugin unless `ALLOW_UNSIGNED_PLUGINS` is set,
/// and setting it means mutating the process environment. Signing instead loads
/// the fixture through the same verified path a production plugin takes.
fn sign_fixture(wasm: &Path) -> VerifyingKey {
    let key = SigningKey::from_bytes(&[11; 32]);
    let bytes = std::fs::read(wasm).expect("read fixture wasm");
    let signature = key.sign(&Sha256::digest(&bytes));
    let mut sig_path = wasm.as_os_str().to_owned();
    sig_path.push(".sig");
    std::fs::write(PathBuf::from(sig_path), signature.to_bytes()).expect("write fixture .sig");
    key.verifying_key()
}

/// One test, one fixture build: a single `#[test]` avoids parallel cargo
/// invocations racing on the fixture's target dir.
#[test]
fn sdk_generated_abi_round_trips_through_host() {
    let engine = build_engine().expect("build engine");
    let wasm = build_fixture_wasm();
    let publisher = sign_fixture(&wasm);

    // `from_file` calls the macro-generated `describe` export and caches the
    // result — proving `describe` + alloc/dealloc + write_output round-trip
    // from a real `export_plugin!` plugin (not a hardcoded WAT return).
    let plugin = LoadedPlugin::from_file(&engine, &wasm, "abi-echo", Some(&publisher))
        .expect("load real SDK-generated plugin");
    assert!(plugin.signature_verified());

    let caps = &plugin.capabilities;
    assert_eq!(
        caps.abi_version,
        AbiVersion::current(),
        "describe() must report the current ABI version"
    );
    assert_eq!(caps.supported_schemas.len(), 1);
    assert_eq!(caps.supported_schemas[0].max_version, "1.0.0");

    // `calculate_metrics` on valid input: drives alloc → memory.write → call →
    // read packed `(ptr << 32) | len` → dealloc against the macro's real
    // `write_output`, then surfaces the co2e metric back out.
    let ok = plugin
        .invoke_calculate(&serde_json::json!({ "co2e": 42.5 }))
        .expect("calculate on valid input");
    assert_eq!(ok.co2e_score, Some(42.5));

    // The error envelope round-trips too: invalid input → `AbiResult::Error` →
    // host surfaces it as `Err`, not a panic or a garbage result.
    let err = plugin.invoke_calculate(&serde_json::json!({ "missing": "co2e" }));
    assert!(
        err.is_err(),
        "plugin AbiResult::Error must surface as Err, got {err:?}"
    );

    // `generate_passport`: the passthrough payload survives the full round-trip.
    let payload = plugin
        .invoke_generate_passport(&serde_json::json!({ "co2e": 1.0, "tag": "echo" }))
        .expect("generate_passport on valid input");
    assert_eq!(payload["tag"], "echo");
    assert_eq!(payload["co2e"], 1.0);
}
