//! Wasmtime engine configuration and sandboxed `Store` builder.

use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::{HostMonotonicClock, HostWallClock, WasiCtxBuilder};

use wasmtime::{Config, Engine, ResourceLimiter, Store};

/// Default fuel limit per plugin invocation (~10M Wasm instructions).
pub const DEFAULT_FUEL: u64 = 10_000_000;

/// Default memory cap per plugin instance (64 MiB).
pub const DEFAULT_MEMORY_CAP_BYTES: usize = 64 * 1024 * 1024;

/// Build a sandboxed wasmtime `Engine` for loading product group plugins.
///
/// - Cranelift ahead-of-time compilation for predictable latency.
/// - Fuel metering enabled — guests are killed after `DEFAULT_FUEL` instructions.
/// - Synchronous instantiation/invocation — the `ComplianceRegistry` port is a
///   sync trait and the loader calls guest exports with `.call()` (not
///   `.call_async()`); enabling `async_support` here makes wasmtime panic at
///   instantiation ("must use async instantiation when async support is enabled").
/// - Component model enabled for WIT-based plugins.
pub fn build_engine() -> wasmtime::Result<Engine> {
    let mut cfg = Config::new();
    cfg.cranelift_opt_level(wasmtime::OptLevel::Speed);
    cfg.consume_fuel(true);
    cfg.wasm_component_model(true);
    Engine::new(&cfg)
}

/// Wasm host state stored per-`Store`.
pub struct HostState {
    pub wasi: WasiP1Ctx,
    /// Memory cap enforced by the `ResourceLimiter` for this store.
    pub memory_cap_bytes: usize,
    /// Timestamp pinned at store-creation time (milliseconds since UNIX epoch).
    /// Served by `odal::now_ms` so every invocation sees a constant value,
    /// keeping compliance determinations deterministic and audit receipts
    /// reproducible on re-run with the same input.
    pub now_ms_pinned: u64,
    /// Set to true the first time `memory_growing` denies a request due to the
    /// cap. Checked by the caller after invocation to emit PLUGIN_MEM_CAPPED.
    pub memory_capped: bool,
}

impl ResourceLimiter for HostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        if desired > self.memory_cap_bytes {
            // Ok(false) makes memory.grow return -1 per the Wasm spec, which is
            // the correct denial signal. The caller reads memory_capped after
            // invocation and surfaces an error containing "memory cap" so that
            // lib.rs can emit the metric without relying on a trap.
            self.memory_capped = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        // Meter table growth like linear memory. Otherwise a single `table.grow`
        // with a huge element count forces a large host-side allocation that
        // fuel counts as only one instruction — a resource-limit bypass distinct
        // from the (capped) linear-memory path. Ok(false) makes `table.grow`
        // return -1 (the Wasm denial signal). ProductGroup plugins use tiny indirect
        // tables, so this ceiling is generous.
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }
}

/// Maximum number of elements a plugin's tables may grow to. A funcref/externref
/// element is a few host bytes, so this caps table growth well under a MiB.
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// A WASI clock frozen at store-creation time.
///
/// # Why the ambient clock is pinned too
///
/// `odal::now_ms` has always returned a value pinned per store, with the stated
/// reason that it makes determinations deterministic and audit receipts
/// reproducible. That was true of `odal::now_ms` and false of the store, because
/// [`build_linker`](crate::host_funcs::build_linker) also wires the preview1
/// context — which exposed a **host-real** clock through
/// `wasi_snapshot_preview1::clock_time_get`.
///
/// That is not a theoretical second door. It is the one a Rust plugin uses by
/// default: `std::time::SystemTime::now()` and `Instant::now()` compile straight
/// to it, and no plugin author would think to avoid them in favour of a custom
/// host import. So the property the receipts rest on was a plugin-authoring
/// convention with nothing enforcing it.
///
/// Pinning both clocks to the same instant makes the claim true: within one
/// invocation every clock a plugin can reach returns one value, whichever import
/// it goes through. Across invocations the value moves, because a new store is
/// built per call — which is what "reproducible on re-run with the same input"
/// requires (the input includes the timestamp the determination was made at, and
/// that timestamp is recorded).
#[derive(Clone, Copy)]
struct PinnedClock {
    nanos: u64,
}

impl HostWallClock for PinnedClock {
    fn resolution(&self) -> std::time::Duration {
        // One second: the honest resolution of a clock that does not advance.
        std::time::Duration::from_secs(1)
    }
    fn now(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.nanos)
    }
}

impl HostMonotonicClock for PinnedClock {
    fn resolution(&self) -> u64 {
        1_000_000_000
    }
    fn now(&self) -> u64 {
        self.nanos
    }
}

/// Create a sandboxed `Store` with WASI disabled for filesystem and network.
///
/// `fuel` and `memory_cap` override the defaults; the host always clamps them
/// at [`DEFAULT_FUEL`] and [`DEFAULT_MEMORY_CAP_BYTES`] so a plugin cannot
/// claim more resources than the host is willing to grant.
///
/// Guests may only:
/// - Access monotonic time (needed for deterministic caching)
/// - Call host logging functions (see `host_funcs`)
///
/// Guests may NOT:
/// - Open files or directories
/// - Create network sockets
/// - Spawn threads
pub fn build_store(
    engine: &Engine,
    fuel: Option<u64>,
    memory_cap: Option<usize>,
) -> wasmtime::Result<Store<HostState>> {
    // One instant, read once, serving every clock this store exposes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let now_ms_pinned = now.as_millis() as u64;
    let pinned = PinnedClock {
        nanos: now.as_nanos() as u64,
    };

    // Preview1 context for wasm32-wasip1 plugins. No preopened directories and
    // no socket capability are granted, so filesystem and network access stay
    // denied; this only satisfies the ambient WASI imports the wasip1 std emits
    // (random/clock/environ/proc_exit) so a real plugin can instantiate.
    //
    // Both clocks are pinned to `now` — see `PinnedClock` for why the ambient
    // one mattered. Entropy is deliberately left as the host's: `random_get` is
    // what `std` seeds `HashMap` from, and a fixed seed there would make
    // iteration order predictable to a plugin without making a determination any
    // more reproducible (a determination that depends on map order is a plugin
    // bug the host cannot paper over). The remaining non-determinism is
    // therefore a plugin's own choice to consume entropy, not an ambient
    // capability it reaches by writing ordinary Rust.
    let wasi = WasiCtxBuilder::new()
        .wall_clock(pinned)
        .monotonic_clock(pinned)
        .build_p1();
    let state = HostState {
        wasi,
        memory_cap_bytes: memory_cap
            .unwrap_or(DEFAULT_MEMORY_CAP_BYTES)
            .min(DEFAULT_MEMORY_CAP_BYTES),
        now_ms_pinned,
        memory_capped: false,
    };
    let mut store = Store::new(engine, state);
    store.set_fuel(fuel.unwrap_or(DEFAULT_FUEL).min(DEFAULT_FUEL))?;
    store.limiter(|state| state as &mut dyn ResourceLimiter);
    Ok(store)
}
