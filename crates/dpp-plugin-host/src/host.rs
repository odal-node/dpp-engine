//! `WasmPluginHost` — the `ComplianceRegistry` impl, per-sector dispatch, and
//! passthrough fallback when no plugin is loaded for a sector.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
use serde_json::Value;

use crate::loader::LoadedPlugin;

/// Thread-safe registry of loaded Wasm sector plugins.
///
/// The node boots this at startup, scanning `/plugins/*.wasm`.
/// Requests are dispatched here; fallback to `PassthroughRegistry` when
/// no plugin is loaded for the requested sector.
pub struct WasmPluginHost {
    plugins: Arc<RwLock<HashMap<String, LoadedPlugin>>>,
}

impl WasmPluginHost {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a plugin that was loaded by `loader::load_plugin`.
    pub fn register(&self, sector_key: String, plugin: LoadedPlugin) {
        self.plugins.write().unwrap().insert(sector_key, plugin);
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
        let plugins = self.plugins.read().unwrap();
        let plugin = plugins.get(key).ok_or_else(|| ComplianceError {
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

        let payload = plugin
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

        Ok(payload)
    }
}

impl Default for WasmPluginHost {
    fn default() -> Self {
        Self::new()
    }
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
        let plugins = self.plugins.read().unwrap();
        let plugin = plugins.get(key).ok_or_else(|| ComplianceError {
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
                // Fuel exhaustion is a distinct sandbox event — track it separately
                // so the alert rule "any increment = sandbox limit actually firing"
                // is unambiguous.
                if msg.to_lowercase().contains("fuel") || msg.to_lowercase().contains("out of fuel")
                {
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
                // Memory cap is signalled by ResourceLimiter::memory_growing returning Err
                // with a message containing "memory cap" (see runtime.rs).
                if msg.contains("memory cap") {
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
