//! `dpp-types` — platform-wide shared types: operator config, API keys, audit trail, and auth.
//!
//! These are the data-only types shared across the dpp-engine crates. They carry
//! no infrastructure logic — all persistence and network behaviour lives in the
//! crates that implement the `*Repository` / `AuthProvider` traits declared here.
//!
//! # What lives here (three species — read this before adding a new module)
//!
//! 1. **Engine-operational types** — `operator`, `api_key`, `auth`, `trust`,
//!    `registry_identity`: these describe how this node is deployed and run.
//!    They belong here permanently; they are not part of the DPP standard.
//! 2. **Persistence ports** — `registry_sync::RegistrySyncOutbox`,
//!    `transfer::TransferStore`: these persist operational records (an outbox,
//!    a chain-per-passport store). They live engine-side deliberately: the
//!    standard defines the *records*, not how a given deployment queues or
//!    stores them. See the doc comment on each port for the specific reasoning.
//! 3. **Standard-adjacent provenance** — `audit`: `AuditEntry` and its hash
//!    chain were promoted to `dpp-core`'s `dpp-evidence` crate (2026-07-08),
//!    since they're verified by third parties and are part of the
//!    proof-bound standard rather than engine plumbing. This module
//!    re-exports the type and keeps only the persistence port
//!    (`AuditRepository`) — storage is still an engine deployment choice.
//!
//! New types should fit one of these three; if a fit isn't obvious, that's a
//! sign the taxonomy needs revisiting rather than a place to force it.

pub mod api_key;
pub mod audit;
pub mod auth;
pub mod operator;
pub mod registry_identity;
pub mod registry_sync;
pub mod transfer;
pub mod trust;

pub use api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository, CreateApiKeyRequest, NewApiKey};
pub use audit::{
    AuditChainBreak, AuditEntry, AuditRepository, GENESIS_PREV_HASH, verify_audit_chain,
};
pub use auth::{AuthContext, AuthError, AuthProvider};
pub use operator::{
    OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID, UpdateOperatorConfig,
};
pub use registry_identity::{
    CreateFacilityRequest, CreateOperatorIdentifierRequest, Facility, OperatorIdentifier,
    RegistryIdentityRepository,
};
pub use registry_sync::{
    RegistrySyncCounts, RegistrySyncOutbox, RegistrySyncRow, RegistrySyncStatus,
};
pub use transfer::TransferStore;
pub use trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort};
