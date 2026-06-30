//! `dpp-types` — platform-wide shared types: operator config, API keys, audit trail, and auth.
//!
//! These are the data-only types shared across the dpp-engine crates. They carry
//! no infrastructure logic — all persistence and network behaviour lives in the
//! crates that implement the `*Repository` / `AuthProvider` traits declared here.

pub mod api_key;
pub mod audit;
pub mod auth;
pub mod operator;
pub mod registry_identity;

pub use api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository, CreateApiKeyRequest, NewApiKey};
pub use audit::{AuditEntry, AuditRepository};
pub use auth::{AuthContext, AuthError, AuthProvider};
pub use operator::{
    OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID, UpdateOperatorConfig,
};
pub use registry_identity::{
    CreateFacilityRequest, CreateOperatorIdentifierRequest, Facility, OperatorIdentifier,
    RegistryIdentityRepository,
};
