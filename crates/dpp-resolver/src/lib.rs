//! `dpp-resolver` — shared resolution logic.
//!
//! This crate builds as both:
//! - A native Axum binary (`src/main.rs`) for self-hosted and staging deployments
//! - A `cdylib` WASM binary for Cloudflare Workers edge deployment (future task)
//!
//! The core resolution logic lives here in `lib.rs` and is shared between both targets.

pub mod config;
pub mod domain;
pub mod handlers;
pub mod infra;
pub mod router;
pub mod state;

#[cfg(test)]
mod jws_verification_tests;
