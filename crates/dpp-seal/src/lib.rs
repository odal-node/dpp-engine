//! eIDAS qualified seal adapter for Odal Node.
//!
//! # The sealing model
//!
//! A qualified electronic seal is produced by a Qualified Trust Service
//! Provider (QTSP) over the Cloud Signature Consortium (CSC) API — this node
//! never holds the seal's private key and never assembles an AdES signature
//! in-process (no Rust AdES library exists; the QTSP's `credentials/sign`
//! response is the seal). Until a QTSP contract is configured
//! (`QTSP_URL`/`QTSP_CLIENT_ID`/`QTSP_CLIENT_SECRET`/`QTSP_CREDENTIAL_ID`),
//! [`adapter::QtspSealAdapter`] delegates to `GhostSeal` — a placeholder with
//! no legal validity, which is why a production node's trust report refuses
//! to boot while the seal port resolves to a ghost.
//!
//! # Structure
//!
//! - [`adapter`] — `QtspSealAdapter`, the `SealPort` impl (ghost-delegation
//!   until configured)
//! - [`csc`] — CSC API wire types, and the reserved seats for the real HTTP
//!   client (`csc::client`) and capability probing (`csc::probe`)

pub mod adapter;
pub mod csc;

pub use adapter::QtspSealAdapter;

#[cfg(test)]
mod tests;
