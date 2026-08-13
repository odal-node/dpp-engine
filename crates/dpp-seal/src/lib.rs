//! eIDAS qualified seal adapter for Odal Node.
//!
//! # The sealing model
//!
//! A qualified electronic seal is produced by a Qualified Trust Service
//! Provider (QTSP) — this node never holds the seal's private key and never
//! assembles an AdES signature in-process (no Rust AdES library exists; the
//! provider's response *is* the seal). Until a provider is configured,
//! [`adapter::QtspSealAdapter`] delegates to `GhostSeal` — a placeholder with
//! no legal validity, which is why a production node's trust report refuses
//! to boot while the seal port resolves to a ghost.
//!
//! # Provider
//!
//! **eID Easy Cloud Direct e-Sealing**, which aggregates qualified QTSPs and
//! produces **CAdES** over the payload digest. Auth is HMAC over the exact
//! request bytes. CAdES from a qualified QTSP carries the same eIDAS
//! Art. 35 legal presumption as any other AdES envelope; the DPP registry
//! requires a *qualified* seal, not a specific envelope format.
//!
//! Sandbox needs no legal entity — it seals with eID Easy test certificates.
//! The entity gates *production* only.
//!
//! # What is sealed
//!
//! The digest handed to `SealPort::seal` is over the passport's `jwsSignature`
//! compact string. That makes the qualified seal a countersignature — a QTSP
//! attesting that this operator signature existed at this time — and it is
//! reconstructible by anyone holding the passport, with no canonicalization step
//! and no dependence on fields that stay mutable after publish. The composition
//! lives with the payload, in `dpp-vault`; this crate only ever sees a hex digest.
//!
//! # Structure
//!
//! - [`adapter`] — `QtspSealAdapter`, the `SealPort` impl
//! - [`config`] — which backend this node runs, and nothing about any of them
//! - [`eideasy`] — the hosted QTSP backend: config, wire types, HTTP client
//! - [`local`] — in-process signing for development
//! - [`error`] — `SealError`, classified once at the HTTP boundary
//!
//! Each backend owns its own module: its configuration, its variables, its
//! failure messages and its wire types. Nothing outside a backend's module
//! names it, so one can be added or dropped without touching the others.

pub mod adapter;
pub mod config;
pub mod eideasy;
pub mod error;
pub mod local;

pub use adapter::QtspSealAdapter;
pub use config::{SEAL_PROVIDER, SealProvider};
pub use error::SealError;

#[cfg(test)]
mod tests;
