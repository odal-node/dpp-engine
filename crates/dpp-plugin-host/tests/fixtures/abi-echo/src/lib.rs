//! Minimal `export_plugin!` fixture for the host's `wasm-fixture-tests` suite.
//!
//! The plugin echoes its input back as the passport payload and surfaces the
//! `co2e` field as the CO2e metric. Its only job is to make the SDK-generated
//! Wasm ABI (`describe`/`calculate_metrics`/`generate_passport` + `alloc`/
//! `dealloc` + `write_output`/`read_input` packing) observable end-to-end when
//! driven by the real wasmtime host — something the hand-rolled WAT fixtures
//! cannot do.

use dpp_plugin_sdk::export_plugin;
use dpp_plugin_sdk::traits::{
    AbiVersion, DppSectorPlugin, METRIC_CO2E_SCORE, PluginCapabilities, PluginCapability,
    PluginComplianceStatus, PluginError, PluginInput, PluginMeta, PluginResult, SchemaVersionRange,
};
use serde_json::Value;

#[derive(Default)]
struct EchoPlugin;

impl DppSectorPlugin for EchoPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            sector: "abi-echo".into(),
            name: "ABI Echo Fixture".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            license: "BSL-1.1".into(),
            description: None,
            author: None,
            homepage: None,
        }
    }

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            abi_version: AbiVersion::current(),
            supported_schemas: vec![SchemaVersionRange {
                min_version: "1.0.0".into(),
                max_version: "1.0.0".into(),
            }],
            capabilities: vec![
                PluginCapability::Validate,
                PluginCapability::ComputeMetrics,
                PluginCapability::GeneratePassport,
            ],
            min_host_version: None,
            max_fuel: None,
            max_memory_bytes: None,
        }
    }

    fn validate_input(&self, input: &PluginInput) -> Result<(), PluginError> {
        if input.get("co2e").and_then(Value::as_f64).is_some() {
            Ok(())
        } else {
            Err(PluginError::InvalidInput(
                "fixture requires a numeric `co2e` field".into(),
            ))
        }
    }

    fn calculate_metrics(&self, input: &PluginInput) -> Result<PluginResult, PluginError> {
        self.validate_input(input)?;
        let co2e = input.get("co2e").and_then(Value::as_f64);
        Ok(PluginResult::new(PluginComplianceStatus::NotAssessed)
            .maybe_metric(METRIC_CO2E_SCORE, co2e))
    }

    fn generate_passport(&self, input: &PluginInput) -> Result<Value, PluginError> {
        self.validate_input(input)?;
        Ok(input.clone())
    }
}

export_plugin!(EchoPlugin);
