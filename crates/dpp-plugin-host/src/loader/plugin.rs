//! `LoadedPlugin`: a compiled, signature-verified sector plugin ready to be
//! instantiated per-request, plus the raw ABI call plumbing it needs.

use std::path::Path;

use anyhow::{Context, Result};
use dpp_common::event_codes;
use ed25519_dalek::VerifyingKey;
use wasmtime::{Engine, Instance, Linker, Module, Store};

use dpp_domain::ports::compliance::ComplianceResult;
use dpp_plugin_traits::{AbiResult, PluginCapabilities, PluginResult};

use super::signing::verify_plugin_signature;
use crate::host::plugin_result_to_compliance;
use crate::runtime::{DEFAULT_FUEL, DEFAULT_MEMORY_CAP_BYTES, HostState, build_store};

/// Maximum bytes accepted from any plugin ABI output (4 MiB).
const MAX_ABI_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

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
            tracing::warn!(
                path = %path.display(),
                "loading Wasm plugin WITHOUT signature verification — not safe for production"
            );
        }

        tracing::info!(path = %path.display(), sector = sector_key, "compiling Wasm plugin");
        let module = Module::from_file(engine, path)
            .map_err(|e| anyhow::anyhow!("failed to compile {}: {e}", path.display()))?;

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
        .map_err(w)?;
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
        .map_err(w)?;
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
