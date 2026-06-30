# dpp-plugin-host

`wasmtime`-based sandbox host for [Odal Node](https://odal-node.io) sector plugins.

At node startup, `dpp-plugin-host` scans `/plugins/*.wasm`, compiles each module
with `wasmtime`, and registers it under its sector key. Inbound passport requests
are dispatched here; the host invokes the plugin's `calculate` export, maps the
result to a `ComplianceResult`, and enforces the `SectorCatalog` regulatory status
gate before returning.

---

## When to use this crate

- You are wiring new Wasm sector plugins into the node startup sequence.
- You are writing a benchmark or integration test for plugin invocation overhead.
- You need to extend host functions exposed to plugins.

## When NOT to use this crate

- You are **writing** a plugin → use `dpp-plugin-sdk` (open-source, Apache-2.0).
- You need to define the plugin ABI → `dpp-plugin-traits`.

---

## Architecture

```
node boot → loader::load_plugin(path) → WasmPluginHost::register(sector_key, plugin)
                                                         │
passport request → PassportService → WasmPluginHost::compute(sector, data)
                                             │
                              plugin.invoke_calculate(input_json)
                                             │
                              gate_determination(is_in_force, status)
                                             │
                                      ComplianceResult
```

### Regulatory status gate

`WasmPluginHost::compute` calls `gate_determination(catalog.is_in_force(sector_key), status)` after every plugin invocation. A plugin registered for a provisional sector (e.g. a delegated act not yet in force) can never surface `Compliant` or `NonCompliant` — the gate downgrades the status to `NotAssessed`. This is enforced centrally regardless of what the plugin returns.

### Passthrough behaviour

When no plugin is registered for the requested sector, `WasmPluginHost::compute`
returns `ComplianceStatus::PassthroughNoValidation`. The passport is stored with
the manufacturer-supplied values unchanged — no compliance score is computed.

---

## Module structure

```
src/
├── loader.rs       load_plugin(path) — compiles .wasm, wires host functions, returns LoadedPlugin
├── runtime.rs      wasmtime Engine + Linker construction (shared across all plugins)
├── sandbox.rs      Per-invocation Store + memory limits
├── host_funcs.rs   Host-side imports exposed to plugins (logging, abort)
└── lib.rs          WasmPluginHost + ComplianceRegistry + PluginHost impls
```

---

## Feature flag: `integration-tests`

Enables test helpers and the `wasm_invoke` criterion benchmark. Never enabled in
production.

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-plugin-traits` | Defines the Wasm ABI (`PluginInput`, `PluginResult`, `calculate` export) |
| `dpp-plugin-sdk` | Used by plugin **authors** to build against the ABI |
| `dpp-domain` | `SectorCatalog`, `ComplianceRegistry`, `PluginHost` port traits |
| `dpp-node` | Constructs `WasmPluginHost`, scans `/plugins/`, registers loaded plugins |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
