//! Data access layer for dpp-engine.
//!
//! Single backend: [`pg`] — PostgreSQL via sqlx. The [`pg`] module exposes
//! one concrete struct per domain aggregate and re-exports them at crate root.
pub mod pg;
