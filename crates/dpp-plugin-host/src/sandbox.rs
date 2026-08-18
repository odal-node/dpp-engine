//! Wasm plugin sandbox: capability whitelist and policy version constant.

/// Capability whitelist documentation for the Odal Node plugin sandbox.
///
/// The sandbox is enforced at the wasmtime store level:
///
/// ALLOWED:
/// - CPU instructions up to `DEFAULT_FUEL` per invocation
/// - Linear memory up to `DEFAULT_MEMORY_CAP_BYTES` (64 MiB)
/// - Table growth up to `MAX_TABLE_ELEMENTS`
/// - `odal::log` — emit tracing events, up to
///   `host_funcs::MAX_LOG_BYTES` per call. The cap is on the *host* allocation,
///   not just the message: the length is a guest-chosen `u32` and the buffer is
///   host memory, which the `ResourceLimiter` does not cover.
/// - `odal::now_ms` — the instant pinned at store creation
///
/// SANDBOXED WASI (preview1):
/// A no-capability `WasiP1Ctx` is wired into the linker so that real
/// `wasm32-wasip1` plugins can instantiate (their std emits ambient imports).
/// It grants:
/// - `wasi::clocks` — **pinned**, to the same instant as `odal::now_ms`. Both
///   doors, one value. `SystemTime::now()` in a plugin compiles to this import,
///   so leaving it host-real made the determinism `odal::now_ms` exists for a
///   convention rather than a property. See `runtime::PinnedClock`.
/// - `wasi::random` — OS entropy is available. Deliberately **not** pinned:
///   `random_get` is what std seeds `HashMap` from, and a fixed seed would make
///   iteration order predictable to a plugin without making any determination
///   more reproducible. A determination that varies with entropy is a plugin
///   bug the host cannot paper over; compliance output must remain input-derived.
/// - `wasi::environ` — available and empty
///
/// DENIED:
/// - `wasi::filesystem` — no preopened directories, so no file reads or writes
/// - `wasi::sockets` — no socket capability, so no TCP/UDP
/// - Thread spawning (single-threaded Wasm execution model)
/// - Loading an **unsigned precompiled** (`.cwasm`) artifact. It is native code,
///   so none of the limits above apply to it; `ALLOW_UNSIGNED_PLUGINS` waives
///   signature verification for a portable `.wasm` and never for this.
///
/// FUEL ENFORCEMENT:
/// A plugin that loops indefinitely will exhaust its fuel budget and be
/// trapped with `wasmtime::Trap::OutOfFuel`. The host returns
/// `ComplianceErrorKind::Internal` to the caller.
///
/// This module is documentation-only. Enforcement is in `runtime::build_store`,
/// `host_funcs::build_linker` and `loader::plugin::LoadedPlugin::from_file`.
///
/// `1.1.0`: the `odal::log` host allocation is capped, the ambient WASI clock is
/// pinned alongside `odal::now_ms`, and an unsigned `.cwasm` is refused.
pub const SANDBOX_POLICY_VERSION: &str = "1.1.0";
