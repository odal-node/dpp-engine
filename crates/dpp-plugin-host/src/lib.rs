//! Wasmtime-based Wasm plugin host — loads sector plugins and dispatches compliance work.
//!
//! `WasmPluginHost` implements both `PluginHost` (for dispatch-by-sector) and
//! `ComplianceRegistry` (the port wired into `PassportService`). When no plugin
//! is loaded for a sector it falls back to `PassthroughRegistry` behaviour.
//!
//! # Sandbox guarantees
//!
//! Every plugin invocation runs inside a fresh `wasmtime::Store` (see
//! [`runtime`]) bounded by a 10M fuel budget and a 64 MiB memory cap — both
//! actively enforced (`runtime::build_store`'s `ResourceLimiter`, see the W-9
//! regression test in `tests.rs`), with deny-all WASI (no filesystem,
//! network, clock, or environment access). Loading is gated by [`loader`]'s
//! signing policy — see `loader::signing`'s doc comment for exactly when
//! that refusal is enforced vs. merely warned.

pub mod host;
pub mod host_funcs;
pub mod loader;
pub mod runtime;
pub mod sandbox;

pub use host::{WasmPluginHost, plugin_result_to_compliance};

#[cfg(test)]
mod tests;
