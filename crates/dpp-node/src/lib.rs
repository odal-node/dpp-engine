//! Public surface for `dpp-node`.
//!
//! The `config`, `router`, and `infra` modules are re-exported here so that
//! integration tests (in `tests/`) can build the assembled node router with
//! injected test states without going through the binary entry point.
//!
//! The `plugins` module is binary-only (boot-time side-effect) and is
//! intentionally not exported from the library.
pub mod config;
pub mod infra;
pub mod router;
