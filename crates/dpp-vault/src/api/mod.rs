//! The shapes this service publishes, as distinct from the shapes it stores.
//!
//! A response type here is the API's own contract. It is built from the core
//! aggregate rather than being it, so a change inside `dpp-domain` reaches the
//! wire only by way of an edit somebody wrote in this module.
//!
//! # How far that insulation goes, and why it stops
//!
//! Only the top-level response is copied. Everything nested inside it —
//! `ManufacturerInfo`, `MaterialEntry`, `ComplianceResult`, `InstrumentRef` and
//! the rest — is a core type published straight to the wire. That is
//! deliberate, and the two levels are guarded differently:
//!
//! - **The aggregate gets a compile-time seam.** Rename a field in core and the
//!   mapping below stops building, so somebody has to decide whether the public
//!   API changes too. That decision point *is* what the copy buys; it is not
//!   duplication to be tidied away.
//! - **Everything under it gets a test-time seam.** A core rename compiles fine
//!   and changes the wire, and `crates/dpp-node/tests/openapi_contract.rs` is
//!   what catches it. Weaker, but hand-copying every nested type would be a lot
//!   of transcription for a seam the gate already provides.
//!
//! So: **copy the aggregate, pass through what is below it, and let the
//! contract gate cover the rest.** Wrap a nested type only when it is not
//! already core's shape — because it folds several calls into one answer, or
//! carries a field core deliberately keeps off its own type. Wrapping one that
//! is *identical* to core's buys a second compile-time seam; that is a real
//! thing to want, but say so in a comment, or the next reader reads it as
//! duplication and deletes it.
//!
//! Two things this does not decide, on purpose. Which crate a response type
//! lives in is a per-service call — the integrator keeps its response types in
//! the handler that serves them, which is fine for types with one caller. And
//! whether a shape gets its own schema is not a judgement at all: every
//! published object shape must be a named schema, and
//! `every_published_object_shape_has_a_name` fails the build if it is not.

pub mod passport_response;

pub use passport_response::PassportResponse;
