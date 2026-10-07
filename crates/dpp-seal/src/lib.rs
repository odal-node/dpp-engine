//! eIDAS qualified seal adapter for Odal Node.
//!
//! # The sealing model
//!
//! A qualified electronic seal is produced by a Qualified Trust Service
//! Provider (QTSP) — for that seal this node never holds the private key and
//! never assembles the signature in-process; the provider's response *is* the
//! seal. The local backend does assemble a CMS structure in-process, which is
//! precisely why it is not qualified. Until a provider is configured,
//! [`backend::QtspSealAdapter`] delegates to `GhostSeal` — a placeholder with
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
//! - [`backend`] — `SealBackend`, the seam every backend implements;
//!   `QtspSealAdapter`, the `SealPort` impl over one of them; which backend this
//!   node runs; and the placeholder, as a backend like any other
//! - [`eideasy`] — a hosted QTSP backend: its config, wire types, client and errors
//! - [`local`] — in-process signing for development
//! - [`cades`] — reading what a detached CAdES reports about itself, shared by
//!   the backends and never claiming a check it did not perform
//! - [`inspect`] — `CadesInspector`, the one place a stored seal is opened and
//!   judged, holding the Trusted Lists every verdict is read against
//! - [`qualification`] — what the Trusted Lists say about a seal's issuer and
//!   about whoever stamped its time
//! - [`trustlist`] — fetching and verifying the EU's Trusted Lists
//! - [`timestamp`] — extending a stored seal's archive timestamp, from any
//!   [`TimestampSource`]; RFC 3161 over HTTP is the provider-independent one
//! - [`error`] — `SealError`, what is true of sealing regardless of backend
//!
//! Each backend owns its own module: its configuration, its variables, its
//! failure messages and its wire types, and it constructs itself. Nothing
//! outside a backend's module names it — the adapter holds a `dyn SealBackend`
//! and the selector maps one environment value to one module — so a backend can
//! be added or dropped without touching the others.

pub(crate) mod ats;
pub mod backend;
pub mod cades;
pub mod eideasy;
pub mod error;
pub mod inspect;
pub mod local;
pub mod qualification;
pub mod timestamp;
pub mod trustlist;

pub use backend::{QtspSealAdapter, SEAL_PROVIDER, SealBackend, SealProvider};
pub use error::SealError;
pub use inspect::{CadesInspector, RenewedEnvelope};
pub use timestamp::TimestampSource;
