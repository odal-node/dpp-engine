//! Minimal `export_plugin!` fixture for the host's `wasm-fixture-tests` suite.
//!
//! The plugin echoes its input back as the passport payload and surfaces the
//! `co2e` field as the CO2e metric. Its only job is to make the SDK-generated
//! Wasm ABI (`describe`/`calculate_metrics`/`generate_passport` + `alloc`/
//! `dealloc` + `write_output`/`read_input` packing) observable end-to-end when
//! driven by the real wasmtime host — something the hand-rolled WAT fixtures
//! cannot do.
//!
//! `meta` and `capabilities` are left to the trait's defaults, built from
//! `plugin_identity` and `schema_version_range`, so `describe` reports what a
//! real plugin written against this SDK reports.

use dpp_plugin_sdk::export_plugin;
use dpp_plugin_sdk::traits::{
    DppProductGroupPlugin, METRIC_CO2E_SCORE, PluginComplianceStatus, PluginError, PluginIdentity,
    PluginInput, PluginResult, SchemaVersionRange,
};
use serde_json::Value;

#[derive(Default)]
struct EchoPlugin;

impl DppProductGroupPlugin for EchoPlugin {
    fn plugin_identity(&self) -> PluginIdentity {
        PluginIdentity {
            product_group: "abi-echo",
            name: "ABI Echo Fixture",
            version: env!("CARGO_PKG_VERSION"),
            description: "Echoes its input; exercises the export_plugin! ABI",
        }
    }

    fn schema_version_range(&self) -> SchemaVersionRange {
        SchemaVersionRange {
            min_version: "1.0.0".into(),
            max_version: "1.0.0".into(),
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

    fn generate_passport(&self, input: PluginInput) -> Result<Value, PluginError> {
        self.validate_input(&input)?;
        Ok(input)
    }
}

export_plugin!(EchoPlugin);
