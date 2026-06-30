//! Wasm plugin sandbox: capability whitelist and policy version constant.

/// Capability whitelist documentation for the Odal Node plugin sandbox.
///
/// The sandbox is enforced at the wasmtime store level:
///
/// ALLOWED:
/// - CPU instructions up to `DEFAULT_FUEL` per invocation
/// - Linear memory up to `DEFAULT_MEMORY_CAP_BYTES` (64 MiB)
/// - `odal::log` — emit tracing events
/// - `odal::now_ms` — read monotonic clock
///
/// SANDBOXED WASI (preview1):
/// A no-capability `WasiP1Ctx` is wired into the linker so that real
/// `wasm32-wasip1` plugins can instantiate (their std emits ambient imports).
/// It grants:
/// - `wasi::random` — OS entropy is available, but only reaches std internals
///   (e.g. HashMap seeding); compliance output must remain input-derived
/// - `wasi::clocks` / `wasi::environ` — available (clocks host-real, env empty)
///
/// DENIED:
/// - `wasi::filesystem` — no preopened directories, so no file reads or writes
/// - `wasi::sockets` — no socket capability, so no TCP/UDP
/// - Thread spawning (single-threaded Wasm execution model)
///
/// FUEL ENFORCEMENT:
/// A plugin that loops indefinitely will exhaust its fuel budget and be
/// trapped with `wasmtime::Trap::OutOfFuel`. The host returns
/// `ComplianceErrorKind::Internal` to the caller.
///
/// This module is documentation-only. Enforcement is in `runtime::build_store`.
pub const SANDBOX_POLICY_VERSION: &str = "1.0.0";
