//! Sector plugin loader — compile, verify signature, and cache a `LoadedPlugin`.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as B64Engine;
use dpp_common::event_codes;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use wasmtime::{Engine, Instance, Linker, Module, Store};

use dpp_domain::ports::compliance::ComplianceResult;
use dpp_plugin_traits::{AbiResult, PluginCapabilities, PluginResult};

use crate::plugin_result_to_compliance;
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

/// Discover all `.wasm` files in `plugins_dir` and return (sector_key, path) pairs.
///
/// The sector key is the file stem, e.g. `sector-textile.wasm` → `"textile"`.
pub fn discover_plugins(plugins_dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut found = Vec::new();
    if !plugins_dir.exists() {
        tracing::warn!(dir = %plugins_dir.display(), "plugins directory not found — no plugins loaded");
        return Ok(found);
    }
    for entry in std::fs::read_dir(plugins_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .trim_start_matches("sector-")
                .to_owned();
            found.push((stem, path));
        }
    }
    Ok(found)
}

/// Verify the Ed25519 signature of a `.wasm` plugin file.
///
/// Expects a detached signature file at `{wasm_path}.sig` containing the raw
/// 64-byte Ed25519 signature (or base64-encoded signature) over `SHA-256(wasm_bytes)`.
///
/// # Signature protocol
///
/// 1. Publisher computes `digest = SHA-256(wasm_bytes)`.
/// 2. Publisher signs `digest` with their Ed25519 signing key.
/// 3. Publisher writes the 64-byte signature (or base64 thereof) to `{wasm}.sig`.
/// 4. The host verifies `sig` against `digest` using the publisher's public key.
fn verify_plugin_signature(wasm_path: &Path, trusted_key: &VerifyingKey) -> Result<()> {
    let sig_path = wasm_path.with_extension("wasm.sig");
    anyhow::ensure!(
        sig_path.exists(),
        "signature file not found: {} — unsigned plugins cannot be loaded in verified mode",
        sig_path.display()
    );

    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("failed to read wasm file: {}", wasm_path.display()))?;

    let digest = Sha256::digest(&wasm_bytes);

    let sig_bytes_raw = std::fs::read(&sig_path)
        .with_context(|| format!("failed to read signature file: {}", sig_path.display()))?;

    // Accept either raw 64-byte signature or base64-encoded (86 chars + optional newline).
    let sig_bytes = if sig_bytes_raw.len() == 64 {
        sig_bytes_raw
    } else {
        let trimmed = String::from_utf8_lossy(&sig_bytes_raw);
        let trimmed = trimmed.trim();
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .with_context(|| "signature file is neither raw 64 bytes nor valid base64")?
    };

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid Ed25519 signature format: {e}"))?;

    use ed25519_dalek::Verifier;
    trusted_key.verify(&digest, &signature).map_err(|_| {
        anyhow::anyhow!(
            "plugin signature verification failed for {} — the plugin may have been tampered with",
            wasm_path.display()
        )
    })?;

    tracing::info!(
        path = %wasm_path.display(),
        "Wasm plugin signature verified"
    );
    Ok(())
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
