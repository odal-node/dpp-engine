//! Host function registration — `odal::log` and `odal::now_ms` exposed to plugins.

use wasmtime::{Engine, Linker};

use crate::runtime::HostState;

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

    // Guest can log a UTF-8 message from linear memory
    linker.func_wrap(
        "odal",
        "log",
        |mut caller: wasmtime::Caller<'_, HostState>, ptr: u32, len: u32| {
            let mem = caller.get_export("memory").and_then(|e| e.into_memory());
            if let Some(memory) = mem {
                let mut buf = vec![0u8; len as usize];
                if memory.read(&caller, ptr as usize, &mut buf).is_ok() {
                    let msg = String::from_utf8_lossy(&buf);
                    tracing::debug!(plugin_log = %msg);
                }
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
