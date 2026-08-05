//! eID Easy "Cloud Direct e-Sealing" integration — the sealing backend.
//!
//! eID Easy aggregates qualified QTSPs and returns **CAdES** (not JAdES).
//! HMAC-authenticated server-to-server digest sealing. The wire contract is
//! eID Easy's published Cloud Direct e-Sealing API.
//!
//! - [`types`] — request/response wire types.
//! - [`client`] — the HMAC-signed POST, and the sign-the-exact-bytes invariant.

pub mod client;
pub mod types;

pub use client::EideasyClient;
pub use types::{EsealFile, EsealRequest, EsealResponse, EsealSignatureOut, MIME_JSON, MIME_PDF};
