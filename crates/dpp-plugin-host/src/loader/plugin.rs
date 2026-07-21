//! `LoadedPlugin`: a compiled, signature-verified sector plugin ready to be
//! instantiated per-request, plus the raw ABI call plumbing it needs.

use std::path::Path;

use anyhow::{Context, Result};
use dpp_common::event_codes;
use ed25519_dalek::VerifyingKey;
use wasmtime::{Engine, Instance, Linker, Module, Store};

use dpp_domain::ports::compliance::ComplianceResult;
use dpp_plugin_traits::{AbiResult, PluginCapabilities, PluginResult, check_compatibility};

use super::signing::verify_plugin_signature;
use crate::host::plugin_result_to_compliance;
use crate::runtime::{DEFAULT_FUEL, DEFAULT_MEMORY_CAP_BYTES, HostState, build_store};

/// Maximum bytes accepted from any plugin ABI output (4 MiB).
const MAX_ABI_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Whether unsigned plugin loading is explicitly opted into, from the
/// `DPP_ALLOW_UNSIGNED_PLUGINS` value. Pure (takes the value) so it is testable
/// without mutating the process-global environment.
fn unsigned_allowed(env_value: Option<&str>) -> bool {
    matches!(env_value, Some(v) if v.eq_ignore_ascii_case("true"))
}

/// Map a wasmtime call error, giving a fuel-exhaustion trap a distinct,
/// host-controlled `"fuel exhausted"` prefix. Sandbox metrics are then classified
/// from this prefix (and the host's `"memory cap exceeded"` bail), never by
/// string-matching plugin-controlled error text — a plugin's structured error
/// surfaces as `"plugin reported an error: …"` and so cannot spoof either signal.
fn map_call_error(e: wasmtime::Error) -> anyhow::Error {
    if e.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::OutOfFuel) {
        anyhow::anyhow!("fuel exhausted: plugin exceeded its fuel budget")
    } else {
        anyhow::anyhow!("{e}")
    }
}

/// A compiled, in-memory sector plugin ready to be instantiated per-request.
pub struct LoadedPlugin {
    engine: Engine,
    module: Module,
    pub sector_key: String,
    /// Capability declaration cached from `describe()` at load time.
    /// Used to configure per-invocation resource limits without an extra
    /// Wasm round-trip.
    pub capabilities: PluginCapabilities,
}

impl LoadedPlugin {
    /// Compile a `.wasm` file into a `LoadedPlugin`.
    ///
    /// If `trusted_key` is `Some`, the loader verifies a detached Ed25519
    /// signature in `{path}.sig` over the SHA-256 digest of the `.wasm` file.
    /// If verification fails or the `.sig` file is missing, loading is refused.
    ///
    /// If `trusted_key` is `None`, signature verification is skipped. This is
    /// intended **only** for development and testing. Production deployments
    /// must always provide a key.
    pub fn from_file(
        engine: &Engine,
        path: &Path,
        sector_key: &str,
        trusted_key: Option<&VerifyingKey>,
    ) -> Result<Self> {
        if let Some(key) = trusted_key {
            if let Err(e) = verify_plugin_signature(path, key) {
                tracing::warn!(
                    code = event_codes::PLUGIN_REFUSED,
                    path = %path.display(),
                    sector = sector_key,
                    error = %e,
                    "Wasm plugin refused — signature verification failed"
                );
                return Err(e);
            }
        } else {
            // No trusted key configured. Unsigned loading is a development-only
            // convenience and must be explicitly opted into — otherwise a
            // misconfigured production deploy would silently run unverified
            // plugins. Fail closed unless `DPP_ALLOW_UNSIGNED_PLUGINS=true`.
            let allow_unsigned =
                unsigned_allowed(std::env::var("DPP_ALLOW_UNSIGNED_PLUGINS").ok().as_deref());
            if !allow_unsigned {
                return Err(anyhow::anyhow!(
                    "refusing to load unsigned plugin {}: no trusted key is configured and \
                     DPP_ALLOW_UNSIGNED_PLUGINS is not set (production must provide a key)",
                    path.display()
                ));
            }
            tracing::warn!(
                path = %path.display(),
                "loading Wasm plugin WITHOUT signature verification \
                 (DPP_ALLOW_UNSIGNED_PLUGINS=true) — not safe for production"
            );
        }

        // A `.cwasm` artifact is a precompiled (AOT) module: deserialize it
        // rather than compile. Everything else — signature policy above, the
        // describe()/ABI gate below — is identical for both kinds.
        let is_precompiled = path.extension().and_then(|e| e.to_str()) == Some("cwasm");
        let module = if is_precompiled {
            tracing::info!(path = %path.display(), sector = sector_key, "loading precompiled plugin (.cwasm)");
            // Read the bytes and deserialize from memory rather than
            // `deserialize_file` (which mmaps and would keep the file open — on
            // Windows that blocks the install's promote-by-rename step).
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
            // SAFETY: the artifact's signature was verified against the pinned
            // publisher key above (or the operator explicitly opted into unsigned
            // dev mode), so the bytes are authentic rather than attacker-forged —
            // the precondition `Module::deserialize` requires. wasmtime
            // additionally validates its embedded engine/target/config header and
            // returns an error (not UB) when this node's engine cannot load it.
            unsafe {
                Module::deserialize(engine, &bytes).map_err(|e| {
                    anyhow::anyhow!("incompatible precompiled artifact {}: {e}", path.display())
                })?
            }
        } else {
            tracing::info!(path = %path.display(), sector = sector_key, "compiling Wasm plugin");
            Module::from_file(engine, path)
                .map_err(|e| anyhow::anyhow!("failed to compile {}: {e}", path.display()))?
        };

        // Call describe() once at load time to cache capabilities and derive
        // per-invocation resource limits without an extra round-trip per call.
        // Falls back to host defaults if the export is absent (e.g. test WAT fixtures).
        let capabilities = {
            let mut probe_store = build_store(engine, None, None)
                .map_err(|e| anyhow::anyhow!("failed to create probe store: {e}"))?;
            let probe_linker = crate::host_funcs::build_linker(engine)
                .map_err(|e| anyhow::anyhow!("failed to build probe linker: {e}"))?;
            let probe_instance = probe_linker
                .instantiate(&mut probe_store, &module)
                .map_err(|e| anyhow::anyhow!("failed to instantiate plugin for describe(): {e}"))?;
            match call_describe(&mut probe_store, &probe_instance) {
                Ok(caps) => caps,
                Err(e) => {
                    tracing::warn!(
                        sector = sector_key,
                        error = %e,
                        "plugin missing describe() — using host defaults for resource limits"
                    );
                    PluginCapabilities {
                        abi_version: dpp_plugin_traits::AbiVersion::current(),
                        supported_schemas: vec![],
                        capabilities: vec![],
                        min_host_version: None,
                        max_fuel: None,
                        max_memory_bytes: None,
                    }
                }
            }
        };

        tracing::debug!(
            sector = sector_key,
            abi_major = capabilities.abi_version.major,
            abi_minor = capabilities.abi_version.minor,
            "plugin describe() cached"
        );

        // Fail-closed ABI gate. The host must not register a plugin whose
        // declared ABI/host-version contract it cannot honour — otherwise a
        // future-major plugin would load and then trap or misbehave at dispatch.
        // No schema is requested and no capability is required here: this gate
        // answers only "can this host run this plugin's ABI at all" (dispatch-time
        // schema selection is a separate concern). The `describe`-missing fallback
        // above synthesises the host's own current ABI, so unversioned dev/test
        // fixtures still pass.
        let compat = check_compatibility(&capabilities, None, &[]);
        if !compat.is_compatible() {
            tracing::warn!(
                code = event_codes::PLUGIN_REFUSED,
                path = %path.display(),
                sector = sector_key,
                report = ?compat,
                "Wasm plugin refused — ABI incompatible with host"
            );
            return Err(anyhow::anyhow!(
                "plugin '{sector_key}' refused — ABI incompatible with host: {compat:?}"
            ));
        }

        Ok(Self {
            engine: engine.clone(),
            module,
            sector_key: sector_key.to_owned(),
            capabilities,
        })
    }

    /// Instantiate the plugin and call its `calculate_metrics` export.
    ///
    /// Resource limits are derived from the cached `capabilities` and capped
    /// at the host defaults so a plugin cannot claim more than the host allows.
    pub fn invoke_calculate(&self, input: &serde_json::Value) -> Result<ComplianceResult> {
        let fuel = self
            .capabilities
            .max_fuel
            .map(|f| f.min(DEFAULT_FUEL))
            .unwrap_or(DEFAULT_FUEL);
        let memory = self
            .capabilities
            .max_memory_bytes
            .map(|m| (m as usize).min(DEFAULT_MEMORY_CAP_BYTES))
            .unwrap_or(DEFAULT_MEMORY_CAP_BYTES);

        let mut store: Store<HostState> = build_store(&self.engine, Some(fuel), Some(memory))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let linker: Linker<HostState> =
            crate::host_funcs::build_linker(&self.engine).map_err(|e| anyhow::anyhow!("{e}"))?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let json_str = serde_json::to_string(input)?;
        let call_result = call_calculate(&mut store, &instance, &json_str);
        if store.data().memory_capped {
            anyhow::bail!(
                "memory cap exceeded: plugin attempted to exceed {} bytes",
                store.data().memory_cap_bytes
            );
        }
        let result_json = call_result?;

        // The SDK ABI returns an `AbiResult` envelope: `{ok: PluginResult}` or `{error}`.
        let outcome: AbiResult = serde_json::from_str(&result_json)
            .context("plugin returned invalid JSON from calculate_metrics")?;
        let pr: PluginResult = match outcome {
            AbiResult::Ok(value) => serde_json::from_value(value)
                .context("plugin AbiResult.ok was not a valid PluginResult")?,
            AbiResult::Error(e) => anyhow::bail!("plugin reported an error: {e}"),
        };
        Ok(plugin_result_to_compliance(&pr))
    }

    /// Instantiate the plugin and call its `generate_passport` export.
    ///
    /// Returns the raw passport payload JSON value as returned by the plugin.
    /// The caller is responsible for structural validation of the result.
    pub fn invoke_generate_passport(
        &self,
        input: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let fuel = self
            .capabilities
            .max_fuel
            .map(|f| f.min(DEFAULT_FUEL))
            .unwrap_or(DEFAULT_FUEL);
        let memory = self
            .capabilities
            .max_memory_bytes
            .map(|m| (m as usize).min(DEFAULT_MEMORY_CAP_BYTES))
            .unwrap_or(DEFAULT_MEMORY_CAP_BYTES);

        let mut store: Store<HostState> = build_store(&self.engine, Some(fuel), Some(memory))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let linker: Linker<HostState> =
            crate::host_funcs::build_linker(&self.engine).map_err(|e| anyhow::anyhow!("{e}"))?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let json_str = serde_json::to_string(input)?;
        let call_result = call_generate_passport(&mut store, &instance, &json_str);
        if store.data().memory_capped {
            anyhow::bail!(
                "memory cap exceeded: plugin attempted to exceed {} bytes",
                store.data().memory_cap_bytes
            );
        }
        let result_json = call_result?;

        let outcome: AbiResult = serde_json::from_str(&result_json)
            .context("plugin returned invalid JSON from generate_passport")?;
        match outcome {
            AbiResult::Ok(value) => Ok(value),
            AbiResult::Error(e) => {
                anyhow::bail!("plugin generate_passport reported an error: {e}")
            }
        }
    }
}

/// Call the plugin's `describe` export (no input) and parse the returned JSON
/// as [`PluginCapabilities`].
///
/// `describe` returns a packed `(ptr << 32) | len` u64 into the plugin's linear
/// memory. The output is size-clamped to [`MAX_ABI_OUTPUT_BYTES`] before the
/// buffer is allocated.
fn call_describe(store: &mut Store<HostState>, instance: &Instance) -> Result<PluginCapabilities> {
    let w = |e: wasmtime::Error| anyhow::anyhow!("{e}");
    let dealloc = instance
        .get_typed_func::<(u32, u32), ()>(&mut *store, "dealloc")
        .map_err(|_| anyhow::anyhow!("plugin missing 'dealloc' export"))?;
    let describe = instance
        .get_typed_func::<(), u64>(&mut *store, "describe")
        .map_err(|_| anyhow::anyhow!("plugin missing 'describe' export"))?;
    let memory = instance
        .get_memory(&mut *store, "memory")
        .context("plugin missing 'memory' export")?;

    let packed = describe.call(&mut *store, ()).map_err(w)?;
    let out_ptr = (packed >> 32) as usize;
    let out_len = (packed & 0xFFFF_FFFF) as usize;

    anyhow::ensure!(
        out_len <= MAX_ABI_OUTPUT_BYTES,
        "plugin describe() output too large: {out_len} bytes (max {MAX_ABI_OUTPUT_BYTES})"
    );

    let mut out_buf = vec![0u8; out_len];
    memory
        .read(&mut *store, out_ptr, &mut out_buf)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    dealloc
        .call(&mut *store, (out_ptr as u32, out_len as u32))
        .map_err(w)?;

    let json = String::from_utf8(out_buf).context("plugin describe() output is not valid UTF-8")?;
    serde_json::from_str(&json)
        .context("plugin describe() returned invalid PluginCapabilities JSON")
}

/// Minimal ABI: write input JSON into Wasm memory, call the export, read output back.
fn call_generate_passport(
    store: &mut Store<HostState>,
    instance: &Instance,
    input_json: &str,
) -> Result<String> {
    let w = |e: wasmtime::Error| anyhow::anyhow!("{e}");
    let alloc = instance
        .get_typed_func::<u32, u32>(&mut *store, "alloc")
        .map_err(|_| anyhow::anyhow!("plugin missing 'alloc' export"))?;
    let dealloc = instance
        .get_typed_func::<(u32, u32), ()>(&mut *store, "dealloc")
        .map_err(|_| anyhow::anyhow!("plugin missing 'dealloc' export"))?;
    let generate = instance
        .get_typed_func::<(u32, u32), u64>(&mut *store, "generate_passport")
        .map_err(|_| anyhow::anyhow!("plugin missing 'generate_passport' export"))?;
    let memory = instance
        .get_memory(&mut *store, "memory")
        .context("plugin missing 'memory' export")?;

    let input_bytes = input_json.as_bytes();
    let input_len = input_bytes.len() as u32;
    let input_ptr = alloc.call(&mut *store, input_len).map_err(w)?;

    memory
        .write(&mut *store, input_ptr as usize, input_bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let packed = generate
        .call(&mut *store, (input_ptr, input_len))
        .map_err(map_call_error)?;
    let out_ptr = (packed >> 32) as usize;
    let out_len = (packed & 0xFFFF_FFFF) as usize;

    anyhow::ensure!(
        out_len <= MAX_ABI_OUTPUT_BYTES,
        "plugin generate_passport output too large: {out_len} bytes (max {MAX_ABI_OUTPUT_BYTES})"
    );

    let mut out_buf = vec![0u8; out_len];
    memory
        .read(&mut *store, out_ptr, &mut out_buf)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let result =
        String::from_utf8(out_buf).context("plugin generate_passport output is not valid UTF-8")?;

    dealloc
        .call(&mut *store, (out_ptr as u32, out_len as u32))
        .map_err(w)?;
    dealloc
        .call(&mut *store, (input_ptr, input_len))
        .map_err(w)?;

    Ok(result)
}

/// Minimal ABI: write input JSON into Wasm memory, call the export, read output back.
fn call_calculate(
    store: &mut Store<HostState>,
    instance: &Instance,
    input_json: &str,
) -> Result<String> {
    // Locate the three required exports
    let w = |e: wasmtime::Error| anyhow::anyhow!("{e}");
    let alloc = instance
        .get_typed_func::<u32, u32>(&mut *store, "alloc")
        .map_err(|_| anyhow::anyhow!("plugin missing 'alloc' export"))?;
    let dealloc = instance
        .get_typed_func::<(u32, u32), ()>(&mut *store, "dealloc")
        .map_err(|_| anyhow::anyhow!("plugin missing 'dealloc' export"))?;
    let calculate = instance
        .get_typed_func::<(u32, u32), u64>(&mut *store, "calculate_metrics")
        .map_err(|_| anyhow::anyhow!("plugin missing 'calculate_metrics' export"))?;
    let memory = instance
        .get_memory(&mut *store, "memory")
        .context("plugin missing 'memory' export")?;

    let input_bytes = input_json.as_bytes();
    let input_len = input_bytes.len() as u32;
    let input_ptr = alloc.call(&mut *store, input_len).map_err(w)?;

    memory
        .write(&mut *store, input_ptr as usize, input_bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Returns a packed (ptr << 32 | len) u64
    let packed = calculate
        .call(&mut *store, (input_ptr, input_len))
        .map_err(map_call_error)?;
    let out_ptr = (packed >> 32) as usize;
    let out_len = (packed & 0xFFFF_FFFF) as usize;

    anyhow::ensure!(
        out_len <= MAX_ABI_OUTPUT_BYTES,
        "plugin calculate_metrics output too large: {out_len} bytes (max {MAX_ABI_OUTPUT_BYTES})"
    );

    let mut out_buf = vec![0u8; out_len];
    memory
        .read(&mut *store, out_ptr, &mut out_buf)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let result = String::from_utf8(out_buf).context("plugin output is not valid UTF-8")?;

    dealloc
        .call(&mut *store, (out_ptr as u32, out_len as u32))
        .map_err(w)?;
    dealloc
        .call(&mut *store, (input_ptr, input_len))
        .map_err(w)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::build_engine;
    use dpp_domain::ports::compliance::ComplianceStatus;
    use dpp_plugin_traits::PluginCapability;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    const DESCRIBE_JSON: &str = r#"{"abiVersion":{"major":1,"minor":0},"supportedSchemas":[],"capabilities":["compute_metrics"],"maxFuel":500000,"maxMemoryBytes":1048576}"#;
    // A plugin declaring a future major ABI the host cannot honour.
    const DESCRIBE_JSON_ABI_MAJOR_2: &str =
        r#"{"abiVersion":{"major":2,"minor":0},"supportedSchemas":[],"capabilities":[]}"#;
    const CALC_OK_JSON: &str =
        r#"{"ok":{"complianceStatus":"COMPLIANT","metrics":{"co2e_score":1.5}}}"#;
    const CALC_ERR_JSON: &str = r#"{"error":{"Internal":"boom"}}"#;
    const GEN_OK_JSON: &str = r#"{"ok":{"productName":"Test Widget"}}"#;

    fn wat_escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    fn pack(offset: u32, len: u32) -> i64 {
        (((offset as u64) << 32) | (len as u64)) as i64
    }

    /// Builds a fake plugin `.wasm` with `alloc`/`dealloc`/`memory`/`describe` always
    /// present, and `calculate_metrics`/`generate_passport` present only when their
    /// JSON is `Some`. Each export returns a fixed packed `(ptr<<32|len)` pointing at
    /// a canned JSON blob embedded via a WAT `data` segment — no real allocation
    /// logic is needed since these fixtures ignore their input entirely.
    fn build_plugin_wasm(
        describe_json: &str,
        calculate_json: Option<&str>,
        calculate_len_override: Option<u32>,
        generate_json: Option<&str>,
    ) -> Vec<u8> {
        let alloc_offset: u32 = 1024;
        let describe_offset: u32 = 4096;
        let calc_offset: u32 = 8192;
        let gen_offset: u32 = 12288;

        let mut data_segments = format!(
            "(data (i32.const {describe_offset}) \"{}\")\n",
            wat_escape(describe_json)
        );
        let describe_packed = pack(describe_offset, describe_json.len() as u32);

        let mut funcs = String::new();

        if let Some(cj) = calculate_json {
            data_segments += &format!("(data (i32.const {calc_offset}) \"{}\")\n", wat_escape(cj));
            let len = calculate_len_override.unwrap_or(cj.len() as u32);
            let packed = pack(calc_offset, len);
            funcs += &format!(
                "(func (export \"calculate_metrics\") (param $ptr i32) (param $len i32) (result i64)\n  i64.const {packed})\n"
            );
        }

        if let Some(gj) = generate_json {
            data_segments += &format!("(data (i32.const {gen_offset}) \"{}\")\n", wat_escape(gj));
            let packed = pack(gen_offset, gj.len() as u32);
            funcs += &format!(
                "(func (export \"generate_passport\") (param $ptr i32) (param $len i32) (result i64)\n  i64.const {packed})\n"
            );
        }

        let wat = format!(
            r#"(module
  (memory (export "memory") 2)
  {data_segments}
  (func (export "alloc") (param $len i32) (result i32)
    i32.const {alloc_offset})
  (func (export "dealloc") (param $ptr i32) (param $len i32))
  (func (export "describe") (result i64)
    i64.const {describe_packed})
  {funcs}
)"#
        );

        wat::parse_str(&wat).expect("generated WAT must parse")
    }

    fn write_plugin_file(dir: &TempDir, wasm: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join("plugin.wasm");
        std::fs::write(&path, wasm).unwrap();
        path
    }

    fn full_plugin_wasm() -> Vec<u8> {
        build_plugin_wasm(DESCRIBE_JSON, Some(CALC_OK_JSON), None, Some(GEN_OK_JSON))
    }

    /// Load a plugin without a trusted key — the development path. Opts into
    /// unsigned loading explicitly, mirroring what a real dev/CI deploy must do.
    fn load_unsigned(engine: &Engine, path: &Path, sector: &str) -> Result<LoadedPlugin> {
        // Safe: every caller sets the same value, so concurrent sets are benign.
        unsafe { std::env::set_var("DPP_ALLOW_UNSIGNED_PLUGINS", "true") };
        LoadedPlugin::from_file(engine, path, sector, None)
    }

    #[test]
    fn unsigned_allowed_only_when_explicitly_opted_in() {
        // The refusal decision is a pure function of the env value, so it can be
        // asserted deterministically without racing the process-global env.
        assert!(super::unsigned_allowed(Some("true")));
        assert!(super::unsigned_allowed(Some("TRUE")));
        assert!(!super::unsigned_allowed(Some("false")));
        assert!(!super::unsigned_allowed(Some("1")));
        assert!(!super::unsigned_allowed(Some("")));
        assert!(!super::unsigned_allowed(None));
    }

    #[test]
    fn from_file_refuses_when_signature_verification_fails() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        // Any bytes work — verification happens before the file is read as wasm,
        // and there's no `.sig` file at all.
        let path = write_plugin_file(&dir, b"not real wasm bytes");
        let trusted_key = SigningKey::from_bytes(&[9; 32]).verifying_key();

        let err = match LoadedPlugin::from_file(&engine, &path, "battery", Some(&trusted_key)) {
            Ok(_) => panic!("missing signature must refuse to load"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("signature file not found"));
    }

    #[test]
    fn from_file_without_trusted_key_falls_back_to_host_defaults_when_describe_missing() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        // A module with zero exports: instantiates fine, but `call_describe` fails
        // (missing `dealloc`/`describe`), so `from_file` must fall back rather than
        // propagate that error.
        let wasm = wat::parse_str("(module)").unwrap();
        let path = write_plugin_file(&dir, &wasm);

        let plugin = load_unsigned(&engine, &path, "battery")
            .expect("dev-mode load without a key must succeed even without describe()");
        assert!(plugin.capabilities.supported_schemas.is_empty());
        assert!(plugin.capabilities.capabilities.is_empty());
        assert_eq!(plugin.capabilities.max_fuel, None);
    }

    #[test]
    fn from_file_caches_declared_capabilities_from_describe() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        let wasm = build_plugin_wasm(DESCRIBE_JSON, Some(CALC_OK_JSON), None, None);
        let path = write_plugin_file(&dir, &wasm);

        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        assert_eq!(plugin.capabilities.abi_version.major, 1);
        assert_eq!(
            plugin.capabilities.capabilities,
            vec![PluginCapability::ComputeMetrics]
        );
        assert_eq!(plugin.capabilities.max_fuel, Some(500_000));
        assert_eq!(plugin.capabilities.max_memory_bytes, Some(1_048_576));
    }

    #[test]
    fn from_file_refuses_abi_incompatible_plugin() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        // describe() advertises ABI major 2; the host is major 1, so the load
        // gate must refuse it and surface the compatibility report.
        let wasm = build_plugin_wasm(DESCRIBE_JSON_ABI_MAJOR_2, Some(CALC_OK_JSON), None, None);
        let path = write_plugin_file(&dir, &wasm);

        let err = match load_unsigned(&engine, &path, "battery") {
            Ok(_) => panic!("ABI-incompatible plugin must be refused at load"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("ABI incompatible"), "got: {msg}");
        assert!(
            msg.contains("AbiIncompatible"),
            "report must name the status: {msg}"
        );
    }

    #[test]
    fn invoke_calculate_success_maps_plugin_result() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        let path = write_plugin_file(&dir, &full_plugin_wasm());
        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        let result = plugin
            .invoke_calculate(&serde_json::json!({"gtin": "irrelevant — fixture ignores input"}))
            .expect("calculate should succeed");

        assert_eq!(result.compliance_status, ComplianceStatus::Compliant);
        assert_eq!(result.co2e_score, Some(1.5));
    }

    #[test]
    fn invoke_generate_passport_success_returns_raw_payload() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        let path = write_plugin_file(&dir, &full_plugin_wasm());
        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        let payload = plugin
            .invoke_generate_passport(&serde_json::json!({}))
            .expect("generate_passport should succeed");

        assert_eq!(payload["productName"], "Test Widget");
    }

    #[test]
    fn invoke_calculate_surfaces_plugin_reported_error() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        let wasm = build_plugin_wasm(DESCRIBE_JSON, Some(CALC_ERR_JSON), None, None);
        let path = write_plugin_file(&dir, &wasm);
        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        let err = plugin
            .invoke_calculate(&serde_json::json!({}))
            .expect_err("plugin-reported error must surface as Err");
        assert!(err.to_string().contains("plugin reported an error"));
    }

    #[test]
    fn invoke_calculate_rejects_invalid_json_output() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        let wasm = build_plugin_wasm(DESCRIBE_JSON, Some("not json at all"), None, None);
        let path = write_plugin_file(&dir, &wasm);
        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        let err = plugin
            .invoke_calculate(&serde_json::json!({}))
            .expect_err("non-JSON output must be rejected");
        assert!(err.to_string().contains("invalid JSON"));
    }

    #[test]
    fn invoke_calculate_rejects_output_exceeding_size_cap() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        // Claims an output length far beyond MAX_ABI_OUTPUT_BYTES; the size check
        // must reject this before ever attempting to read that much memory.
        let oversized_len = (MAX_ABI_OUTPUT_BYTES + 1) as u32;
        let wasm = build_plugin_wasm(DESCRIBE_JSON, Some(CALC_OK_JSON), Some(oversized_len), None);
        let path = write_plugin_file(&dir, &wasm);
        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        let err = plugin
            .invoke_calculate(&serde_json::json!({}))
            .expect_err("oversized output must be rejected");
        assert!(err.to_string().contains("output too large"));
    }

    #[test]
    fn invoke_calculate_errors_cleanly_when_export_missing() {
        let engine = build_engine().unwrap();
        let dir = TempDir::new().unwrap();
        // describe() succeeds (so from_file loads fine) but calculate_metrics was
        // never exported — a partial/malformed plugin must fail predictably, not panic.
        let wasm = build_plugin_wasm(DESCRIBE_JSON, None, None, Some(GEN_OK_JSON));
        let path = write_plugin_file(&dir, &wasm);
        let plugin = load_unsigned(&engine, &path, "battery").unwrap();

        let err = plugin
            .invoke_calculate(&serde_json::json!({}))
            .expect_err("missing export must error, not panic");
        assert!(
            err.to_string()
                .contains("missing 'calculate_metrics' export")
        );
    }
}
