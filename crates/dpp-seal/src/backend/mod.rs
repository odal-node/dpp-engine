//! Which backend seals, and the seam every backend implements.
//!
//! - [`SealBackend`] — the one thing a backend has to be able to do
//! - [`QtspSealAdapter`] — the `SealPort` impl, holding one backend and nothing else
//! - [`provider`] — which backend this node runs, and nothing about any of them
//! - [`ghost`] — the placeholder, as a backend like any other
//!
//! The real backends own their own modules at the crate root
//! ([`crate::eideasy`], [`crate::local`]), so adding or dropping one touches that
//! module and the selector in [`provider`], and nothing here.

pub mod adapter;
pub mod ghost;
pub mod provider;
mod seal_backend;

pub use adapter::QtspSealAdapter;
pub use provider::{SEAL_PROVIDER, SealProvider};
pub use seal_backend::SealBackend;
