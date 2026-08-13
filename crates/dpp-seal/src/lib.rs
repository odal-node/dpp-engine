//! eIDAS qualified seal adapter for Odal Node.
//!
//! # The sealing model
//!
//! A qualified electronic seal is produced by a Qualified Trust Service
//! Provider (QTSP) — for that seal this node never holds the private key and
//! never assembles the signature in-process; the provider's response *is* the
//! seal. The local backend does assemble a CMS structure in-process, which is
//! precisely why it is not qualified. Until a provider is configured,
//! [`adapter::QtspSealAdapter`] delegates to `GhostSeal` — a placeholder with
//! no legal validity, which is why a production node's trust report refuses
//! to boot while the seal port resolves to a ghost.
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
//! - [`backend`] — `SealBackend`, the seam every backend implements
//! - [`adapter`] — `QtspSealAdapter`, the `SealPort` impl over one of them
//! - [`config`] — which backend this node runs, and nothing about any of them
//! - [`eideasy`] — a hosted QTSP backend: its config, wire types, client and errors
//! - [`local`] — in-process signing for development
//! - [`ghost`] — the placeholder, as a backend like any other
//! - [`error`] — `SealError`, what is true of sealing regardless of backend
//!
//! Each backend owns its own module: its configuration, its variables, its
//! failure messages and its wire types, and it constructs itself. Nothing
//! outside a backend's module names it — the adapter holds a `dyn SealBackend`
//! and the selector maps one environment value to one module — so a backend can
//! be added or dropped without touching the others.

pub mod adapter;
pub mod backend;
pub mod config;
pub mod eideasy;
pub mod error;
pub mod ghost;
pub mod local;

pub use adapter::QtspSealAdapter;
pub use backend::SealBackend;
pub use config::{SEAL_PROVIDER, SealProvider};
pub use error::SealError;
