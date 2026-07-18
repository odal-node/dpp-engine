//! `WasmPluginHost` — the `ComplianceRegistry` impl, per-sector dispatch, and
//! passthrough fallback when no plugin is loaded for a sector.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use dpp_common::plugin_admin::{InstalledPlugin, PluginAdmin, PluginInstallError};
use dpp_domain::{
    SectorCatalog,
    domain::sector::{Sector, SectorData},
    ports::{
        compliance::{
            ComplianceError, ComplianceErrorKind, ComplianceFinding, ComplianceRegistry,
            ComplianceResult, ComplianceStatus, gate_determination,
        },
        plugin_host_port::PluginHost,
    },
};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use wasmtime::Engine;

use crate::loader::LoadedPlugin;

/// Everything the host needs to *install* a plugin at runtime (compile, verify,
/// persist). Absent on a passthrough host built with [`WasmPluginHost::new`];
/// present when the node boots via [`WasmPluginHost::with_runtime`].
struct InstallConfig {
    /// Shared wasmtime engine used to compile incoming artifacts.
    engine: Engine,
    /// Pinned publisher key; `None` only in explicit unsigned dev mode.
    trusted_key: Option<VerifyingKey>,
    /// Directory the discovered plugins live in — installs persist here so a
    /// restart re-loads the same set.
    plugins_dir: PathBuf,
}

/// Thread-safe registry of loaded Wasm sector plugins.
///
/// The node boots this at startup, scanning `/plugins/*.wasm`.
/// Requests are dispatched here; fallback to `PassthroughRegistry` when
/// no plugin is loaded for the requested sector.
pub struct WasmPluginHost {
    plugins: Arc<RwLock<HashMap<String, Arc<LoadedPlugin>>>>,
    /// Runtime install capability; `None` on a passthrough/test host.
    install: Option<InstallConfig>,
}

impl WasmPluginHost {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            install: None,
        }
    }

    /// Construct a host that can install plugins at runtime, wired with the
    /// engine, pinned publisher key, and the on-disk plugins directory the node
    /// booted from. Installs verify against `trusted_key` and persist into
    /// `plugins_dir`.
    pub fn with_runtime(
        engine: Engine,
        trusted_key: Option<VerifyingKey>,
        plugins_dir: PathBuf,
    ) -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            install: Some(InstallConfig {
                engine,
                trusted_key,
                plugins_dir,
            }),
        }
    }

    /// Register a plugin that was loaded by `loader::load_plugin`.
    pub fn register(&self, sector_key: String, plugin: LoadedPlugin) {
        self.plugins
            .write()
            .unwrap()
            .insert(sector_key, Arc::new(plugin));
    }

    /// Fetch the plugin bound to `sector_key`, cloning its `Arc` out from under a
    /// momentary read lock so the (potentially long) Wasm invocation runs without
    /// holding the registry lock. This is what lets a [`reload_plugin`] swap and
    /// in-flight invocations proceed concurrently.
    ///
    /// [`reload_plugin`]: Self::reload_plugin
    pub fn get_plugin(&self, sector_key: &str) -> Option<Arc<LoadedPlugin>> {
        self.plugins.read().unwrap().get(sector_key).cloned()
    }

    /// Atomically swap in a freshly loaded plugin, keyed on its own sector.
    ///
    /// The swap only affects invocations that *begin* after it returns; an
    /// invocation already running holds its own `Arc` to the previous instance
    /// and completes normally (last-good continuity). Returns the sector key that
    /// was (re)bound.
    ///
    /// Callers build the replacement via [`LoadedPlugin::from_file`] first —
    /// which verifies the signature, gates the ABI, and instantiate-smokes the
    /// module by calling `describe()`. A rejected artifact errors there and never
    /// reaches this method, so the previously bound plugin keeps serving.
    pub fn reload_plugin(&self, plugin: LoadedPlugin) -> String {
        let sector_key = plugin.sector_key.clone();
        self.plugins
            .write()
            .unwrap()
            .insert(sector_key.clone(), Arc::new(plugin));
        sector_key
    }

    /// Verify a signed artifact, persist it, and hot-swap it into service —
    /// fail-closed, last-good on any rejection.
    ///
    /// Order matters for the last-good guarantee: the artifact is staged and
    /// verified in a scratch subdirectory (signature → ABI gate → instantiate
    /// via `describe()`), and only a *verified* artifact is renamed into the live
    /// plugins directory (overwriting the previous file) and swapped in. A
    /// rejected artifact never touches the live file or the registry, so the
    /// previously installed plugin keeps serving.
    pub fn install_plugin(
        &self,
        sector: &str,
        artifact: Vec<u8>,
        sig: Vec<u8>,
        precompiled: bool,
    ) -> Result<InstalledPlugin, PluginInstallError> {
        let cfg = self
            .install
            .as_ref()
            .ok_or(PluginInstallError::NotSupported)?;

        // Guard the sector key before it becomes a filename: it is interpolated
        // verbatim into `sector-{sector}.wasm`, so an admin-supplied value like
        // `../evil` would escape the plugins directory (a path-traversal write).
        // Sector catalog keys are lowercase kebab-case; reject anything else.
        if sector.is_empty()
            || !sector
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PluginInstallError::Rejected(format!(
                "invalid sector key '{sector}' — expected lowercase letters, digits, and '-'"
            )));
        }

        let persist = |e: std::io::Error| PluginInstallError::Persist(e.to_string());

        std::fs::create_dir_all(&cfg.plugins_dir).map_err(persist)?;

        // A precompiled artifact is persisted as `.cwasm` so `discover_plugins`
        // and `from_file` treat it as AOT (deserialize) rather than compile.
        let ext = if precompiled { "cwasm" } else { "wasm" };
        let file_stem = format!("sector-{sector}");

        // Stage inside the plugins dir so the final promotion is a same-filesystem
        // rename. `verify_plugin_signature` derives the `.sig` path by appending
        // `.sig` to the artifact filename, so the staged artifact keeps its `ext`.
        let staging = cfg.plugins_dir.join(staging_dir_name());
        std::fs::create_dir_all(&staging).map_err(persist)?;
        let staged_artifact = staging.join(format!("{file_stem}.{ext}"));
        let staged_sig = staging.join(format!("{file_stem}.{ext}.sig"));
        std::fs::write(&staged_artifact, &artifact).map_err(persist)?;
        std::fs::write(&staged_sig, &sig).map_err(persist)?;

        // Verify (signature → ABI gate → instantiate-smoke). On rejection the live
        // file and registry are untouched.
        let loaded = LoadedPlugin::from_file(
            &cfg.engine,
            &staged_artifact,
            sector,
            cfg.trusted_key.as_ref(),
        )
        .map_err(|e| {
            let _ = std::fs::remove_dir_all(&staging);
            PluginInstallError::Rejected(e.to_string())
        })?;

        // Promote the verified artifact into the live directory, then swap.
        let final_artifact = cfg.plugins_dir.join(format!("{file_stem}.{ext}"));
        let final_sig = cfg.plugins_dir.join(format!("{file_stem}.{ext}.sig"));
        let promote = |from: &Path, to: &Path| {
            std::fs::rename(from, to).map_err(|e| PluginInstallError::Persist(e.to_string()))
        };
        if let Err(e) = promote(&staged_artifact, &final_artifact)
            .and_then(|()| promote(&staged_sig, &final_sig))
        {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
        let _ = std::fs::remove_dir_all(&staging);

        // Retire any stale opposite-format artifact for this sector so a restart
        // discovers exactly one file per sector (never a `.wasm` and a `.cwasm`).
        let stale_ext = if precompiled { "wasm" } else { "cwasm" };
        let _ = std::fs::remove_file(cfg.plugins_dir.join(format!("{file_stem}.{stale_ext}")));
        let _ = std::fs::remove_file(cfg.plugins_dir.join(format!("{file_stem}.{stale_ext}.sig")));

        let abi = loaded.capabilities.abi_version;
        let report = InstalledPlugin {
            sector: sector.to_owned(),
            abi_version: format!("{}.{}", abi.major, abi.minor),
        };
        self.reload_plugin(loaded);
        tracing::info!(
            sector = %report.sector,
            abi = %report.abi_version,
            precompiled,
            "Wasm plugin installed and hot-swapped"
        );
        Ok(report)
    }

    /// Returns true if at least one Wasm plugin is registered.
    pub fn has_any_plugin(&self) -> bool {
        !self.plugins.read().unwrap().is_empty()
    }

    /// Call the plugin's `generate_passport` export and return the passport payload.
    ///
    /// The input is enriched with `__isInForce` before dispatch so the plugin can
    /// adjust its output for provisional vs. in-force regulatory status.
    /// The returned value is structurally validated to be a non-null JSON object.
    pub fn generate_passport_payload(
        &self,
        sector: &Sector,
        data: &SectorData,
    ) -> Result<Value, ComplianceError> {
        let key = sector.catalog_key();
        let plugin = self.get_plugin(key).ok_or_else(|| ComplianceError {
            kind: ComplianceErrorKind::UnknownSector,
            message: format!("no Wasm plugin loaded for sector '{key}'"),
        })?;

        let input = enrich_input(
            serde_json::to_value(data).map_err(|e| ComplianceError {
                kind: ComplianceErrorKind::InvalidInput,
                message: e.to_string(),
            })?,
            key,
        );

        let mut payload = plugin
            .invoke_generate_passport(&input)
            .map_err(|e| ComplianceError {
                kind: ComplianceErrorKind::Internal,
                message: format!("generate_passport failed: {e}"),
            })?;

        // Structural re-validation: the plugin must return a non-null JSON object.
        if !payload.is_object() {
            let type_desc = match &payload {
                Value::Null => "null",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => unreachable!(),
            };
            return Err(ComplianceError {
                kind: ComplianceErrorKind::InvalidInput,
                message: format!("generate_passport must return a JSON object, got {type_desc}"),
            });
        }

        // Host-side backstop mirroring compute()'s determination gate: a
        // provisional (not-in-force) sector can never surface a binding
        // compliance claim, even if the plugin ignores the advisory __isInForce
        // flag and injects one into its generated output.
        if !catalog().is_in_force(key)
            && let Some(obj) = payload.as_object_mut()
        {
            obj.remove("complianceStatus");
            obj.remove("complianceResult");
        }

        Ok(payload)
    }
}

impl Default for WasmPluginHost {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginAdmin for WasmPluginHost {
    fn install(
        &self,
        sector: &str,
        artifact: Vec<u8>,
        sig: Vec<u8>,
        precompiled: bool,
    ) -> Result<InstalledPlugin, PluginInstallError> {
        self.install_plugin(sector, artifact, sig, precompiled)
    }
}

/// A process-unique name for an install staging directory. Avoids a `uuid`
/// runtime dependency (it is a dev-dependency only) while staying collision-free
/// across concurrent installs via a monotonic counter plus a timestamp.
fn staging_dir_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(".staging-{nanos}-{n}")
}

impl PluginHost for WasmPluginHost {
    fn has_plugin(&self, sector: &Sector) -> bool {
        self.plugins
            .read()
            .unwrap()
            .contains_key(sector.catalog_key())
    }

    #[tracing::instrument(skip(self, data), fields(sector = %sector.catalog_key()))]
    fn compute(
        &self,
        sector: &Sector,
        data: &SectorData,
    ) -> Result<ComplianceResult, ComplianceError> {
        let key = sector.catalog_key();
        let plugin = self.get_plugin(key).ok_or_else(|| ComplianceError {
            kind: ComplianceErrorKind::UnknownSector,
            message: format!("no Wasm plugin loaded for sector '{key}'"),
        })?;

        let input = enrich_input(
            serde_json::to_value(data).map_err(|e| ComplianceError {
                kind: ComplianceErrorKind::InvalidInput,
                message: e.to_string(),
            })?,
            key,
        );

        let mut result = match plugin.invoke_calculate(&input) {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                // Classify sandbox events from HOST-controlled error prefixes,
                // never from plugin-controlled text. A fuel trap is remapped to a
                // "fuel exhausted" prefix and the memory cap bail to "memory cap
                // exceeded"; a plugin's own error surfaces as "plugin reported an
                // error: …", so it cannot spoof either metric/alert.
                if msg.starts_with("fuel exhausted") {
                    metrics::counter!(
                        "plugin_fuel_exhausted_total",
                        "sector" => key.to_owned()
                    )
                    .increment(1);
                    tracing::warn!(
                        code = dpp_common::event_codes::PLUGIN_FUEL_EXHAUSTED,
                        sector = %key,
                        "Wasm plugin exhausted fuel budget"
                    );
                }
                if msg.starts_with("memory cap exceeded") {
                    metrics::counter!(
                        "plugin_mem_capped_total",
                        "sector" => key.to_owned()
                    )
                    .increment(1);
                    tracing::warn!(
                        code = dpp_common::event_codes::PLUGIN_MEM_CAPPED,
                        sector = %key,
                        "Wasm plugin hit memory cap"
                    );
                }
                metrics::counter!(
                    "plugin_invocations_total",
                    "sector" => key.to_owned(),
                    "outcome" => "error"
                )
                .increment(1);
                return Err(ComplianceError {
                    kind: ComplianceErrorKind::Internal,
                    message: msg,
                });
            }
        };

        // Enforce regulatory status centrally: a provisional sector can never
        // surface a binding determination, regardless of what the plugin returns.
        result.compliance_status =
            gate_determination(catalog().is_in_force(key), result.compliance_status);

        metrics::counter!(
            "plugin_invocations_total",
            "sector" => key.to_owned(),
            "outcome" => "ok"
        )
        .increment(1);

        Ok(result)
    }
}

/// `ComplianceRegistry` impl allows wiring `WasmPluginHost` directly into `PassportService`.
///
/// When a plugin is loaded for the sector, it is invoked. Otherwise the behaviour mirrors
/// `PassthroughRegistry`: manufacturer-supplied values are stored verbatim.
impl ComplianceRegistry for WasmPluginHost {
    fn compute(
        &self,
        sector: Sector,
        data: &SectorData,
    ) -> Result<ComplianceResult, ComplianceError> {
        if self.has_plugin(&sector) {
            PluginHost::compute(self, &sector, data)
        } else {
            Ok(ComplianceResult::passthrough())
        }
    }
}

/// Inject host-side metadata into the plugin input before dispatch.
///
/// `__isInForce` tells the plugin whether the sector regulation is currently
/// active (in-force) so it can apply strict thresholds vs. provisional behaviour.
/// The key uses camelCase to match the rest of the JSON field convention.
pub(crate) fn enrich_input(input: Value, sector_key: &str) -> Value {
    match input {
        Value::Object(mut m) => {
            m.insert(
                "__isInForce".into(),
                catalog().is_in_force(sector_key).into(),
            );
            Value::Object(m)
        }
        other => other,
    }
}

/// Process-wide sector catalog (manifests parsed once) for status gating.
fn catalog() -> &'static SectorCatalog {
    static CATALOG: std::sync::OnceLock<SectorCatalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(SectorCatalog::new)
}

/// Convert a `PluginResult` into a `ComplianceResult` for the core compliance port.
pub fn plugin_result_to_compliance(pr: &dpp_plugin_traits::PluginResult) -> ComplianceResult {
    use dpp_plugin_traits::PluginComplianceStatus as PS;
    let status = match pr.compliance_status {
        PS::Compliant => ComplianceStatus::Compliant,
        PS::NonCompliant => ComplianceStatus::NonCompliant,
        PS::PassthroughNoValidation => ComplianceStatus::PassthroughNoValidation,
        PS::NotAssessed => ComplianceStatus::NotAssessed,
        PS::NotImplemented => ComplianceStatus::NotImplemented,
    };
    let map = |findings: &[dpp_plugin_traits::PluginFinding]| -> Vec<ComplianceFinding> {
        findings
            .iter()
            .map(|f| ComplianceFinding {
                code: f.code.clone(),
                field: f.field.clone(),
                message: f.message.clone(),
            })
            .collect()
    };
    ComplianceResult {
        co2e_score: pr.co2e_score(),
        repairability_index: pr.repairability_index(),
        recycled_content_pct: pr.recycled_content_pct(),
        compliance_status: status,
        // Structured findings from the plugin (ABI 1.1+). `assessed_at` is
        // stamped by the engine's `apply_compliance` when the determination is
        // attached to the passport. Receipts arrive once dpp-calc runs in-plugin.
        violations: map(&pr.violations),
        warnings: map(&pr.warnings),
        ..ComplianceResult::default()
    }
}
