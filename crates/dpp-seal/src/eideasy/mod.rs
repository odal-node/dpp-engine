//! eID Easy "Cloud Direct e-Sealing" integration — the sealing backend.
//!
//! eID Easy aggregates qualified QTSPs and returns **CAdES** (not JAdES).
//! HMAC-authenticated server-to-server digest sealing. The wire contract is
//! eID Easy's published Cloud Direct e-Sealing API.
//!
//!
//! Cloud Direct e-Sealing produces **CAdES** over the payload digest (not
//! JAdES). Auth is HMAC over the exact request bytes. CAdES from a qualified
//! QTSP carries the same eIDAS Art. 35 legal presumption as any other AdES
//! envelope; the DPP registry requires a *qualified* seal, not a specific
//! envelope format.
//!
//! Sandbox needs no legal entity — it seals with the provider's test
//! certificates. The entity gates *production* only.
//!
//! - [`types`] — request/response wire types.
//! - [`client`] — the HMAC-signed POST, the sign-the-exact-bytes invariant, and
//!   this backend's `SealBackend` implementation.
//! - [`error`] — the failures that only mean something against this contract.

pub mod client;
pub mod config;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::EideasyClient;
pub use config::{EideasyConfig, EideasyEnvironment};
pub use error::{AuthHint, EideasyError};
pub use types::{EsealFile, EsealRequest, EsealResponse, EsealSignatureOut, MIME_JSON, MIME_PDF};
