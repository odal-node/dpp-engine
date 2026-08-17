//! Host function registration — `odal::log` and `odal::now_ms` exposed to plugins.

use wasmtime::{Engine, Linker};

use crate::runtime::HostState;

/// Largest single log message accepted from a plugin.
///
/// A determination's log line is a diagnostic, not a data channel — 8 KiB is
/// generous for one and small enough that the cap can never be the reason the
/// host runs out of memory.
pub const MAX_LOG_BYTES: usize = 8 * 1024;

/// Register host functions that plugins are allowed to call.
///
/// Guests have access to:
/// - `odal::log` — emit a tracing event from inside the plugin
/// - `odal::now_ms` — monotonic milliseconds since epoch (for caching)
///
/// A sandboxed WASI preview1 context is also wired in (the per-store
/// `WasiP1Ctx`), which satisfies the ambient imports a `wasm32-wasip1` module
/// emits (`random_get`, `fd_write`, `proc_exit`, `environ_get`) — without it,
/// no real `export_plugin!` plugin can instantiate. The context grants no
/// preopened directories and no sockets (see `runtime::build_store`), so
/// filesystem and network access remain denied; thread spawning is unavailable
/// in the single-threaded execution model.
pub fn build_linker(engine: &Engine) -> wasmtime::Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);

    // Satisfy the ambient wasi_snapshot_preview1 imports the wasip1 std emits.
    // The per-store WasiP1Ctx grants no fs/sockets, so this does not widen the
    // sandbox — it only lets a real plugin link and instantiate.
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |s: &mut HostState| &mut s.wasi)?;

    // Guest can log a UTF-8 message from linear memory.
    //
    // `len` is chosen by the guest, so it is clamped *before* anything is
    // allocated. It used to be `vec![0u8; len as usize]` straight from the
    // argument: a `u32` the guest picks, so `odal::log(0, 0xFFFF_FFFF)` asked the
    // host for 4 GiB. `memory.read` would then fail and drop the buffer, but the
    // allocation had already happened — and it happened in the *host* heap, which
    // `HostState`'s `ResourceLimiter` never sees (that caps the guest's linear
    // memory, not ours). One `call` instruction of fuel, four gigabytes.
    //
    // The three ABI paths in `loader::plugin` already clamp this exact pattern
    // against `MAX_ABI_OUTPUT_BYTES` before allocating, and `table_growing` in
    // `runtime` meters the same class of bypass for tables. This was the one
    // guest-declared length in the crate that reached an allocator unchecked.
    linker.func_wrap(
        "odal",
        "log",
        |mut caller: wasmtime::Caller<'_, HostState>, ptr: u32, len: u32| {
            let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                return;
            };
            // Truncate rather than refuse: a message over the cap is a plugin
            // bug, and a truncated log line is strictly more useful than one
            // dropped after allocating for it.
            let len = (len as usize).min(MAX_LOG_BYTES);
            // Refuse a range that cannot succeed before allocating for it, so a
            // guest cannot spend host memory on reads it knows will fail.
            if (ptr as usize).saturating_add(len) > memory.data_size(&caller) {
                return;
            }
            let mut buf = vec![0u8; len];
            if memory.read(&caller, ptr as usize, &mut buf).is_ok() {
                let msg = String::from_utf8_lossy(&buf);
                tracing::debug!(plugin_log = %msg);
            }
        },
    )?;

    // Return the timestamp pinned at store-creation time so that all calls
    // within one invocation see the same value — making determinations
    // deterministic and audit receipts reproducible.
    linker.func_wrap(
        "odal",
        "now_ms",
        |caller: wasmtime::Caller<'_, HostState>| -> u64 { caller.data().now_ms_pinned },
    )?;

    Ok(linker)
}
