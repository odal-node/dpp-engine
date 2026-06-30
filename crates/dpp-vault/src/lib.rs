//! Library interface for `dpp-vault`.
//!
//! Exposes internal modules so integration tests and dependent crates can
//! construct `AppState`, the router, and test helpers without duplicating code.

pub mod config;
pub mod domain;
pub mod handlers;
pub mod infra;
pub mod middleware;
pub mod public_view;
pub mod router;
pub mod state;
