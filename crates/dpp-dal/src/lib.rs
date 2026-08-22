//! Data access layer for dpp-engine.
//!
//! Single backend: [`pg`] — PostgreSQL via sqlx. The [`pg`] module exposes
//! one concrete struct per domain aggregate and re-exports them at crate root.
pub mod pg;

/// Shared throwaway-Postgres harness for integration suites across the
/// workspace. Dev-only: gated behind `test-harness`, which nothing outside a
/// `[dev-dependencies]` entry may enable.
#[cfg(feature = "test-harness")]
pub mod test_harness;
