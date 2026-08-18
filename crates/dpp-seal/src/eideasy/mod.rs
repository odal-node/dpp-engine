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
//! ## Two properties of this API that constrain any second backend
//!
//! Both are properties of *this provider*, not of sealing, and neither is
//! visible from the `SealBackend` contract — which is the reason to write them
//! down here rather than discover them from a second adapter.
//!
//! **It returns a container, never a raw signature.** A digest goes in and a
//! detached CMS comes back. There is no operation that signs caller-supplied
//! bytes and returns the signature value alone. So this backend cannot support
//! a format assembled locally — anything of that shape needs a provider
//! offering a raw-signature primitive, which is what the Cloud Signature
//! Consortium API calls `signatures/signHash`. That is a procurement
//! constraint, not something an adapter can work around. It is also the line
//! between this backend and [`crate::local`], which assembles in-process and is
//! therefore not qualified.
//!
//! **It has no capability discovery.** There is no endpoint that reports which
//! formats or conformance levels are available. The provider's own API
//! documentation states that the signature form and profile to send are the
//! values enabled for a given client — so they are configured out of band, and
//! [`SealCapabilities`] for this backend is *declared* rather than discovered.
//! A CSC-speaking provider would answer the same question with
//! `credentials/info`, and an adapter for one should — the port models
//! capability precisely so the two can differ.
//!
//! [`SealCapabilities`]: dpp_domain::domain::seal::SealCapabilities
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
