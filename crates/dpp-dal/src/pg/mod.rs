//! PostgreSQL backend for the Odal Node data layer.
//!
//! Design: document-style storage — the full serde `Passport` JSON lives in a
//! `doc JSONB` column; query/constraint-bearing fields are real columns kept
//! in sync by this module. Single-tenant: one operator per node, so there is
//! no in-process operator-isolation boundary (no RLS); tenant isolation is an
//! infrastructure concern.
//!
//! Behavioural coverage lives in `tests/pg_integration.rs`, which runs against
//! a real `postgres:17` container in CI.

pub mod pool;
pub mod repo_api_key;
pub mod repo_audit;
pub mod repo_evidence;
pub mod repo_operator_config;
pub mod repo_passport;
pub mod repo_registry_identity;
pub mod repo_registry_sync;
pub mod repo_transfer;

pub use pool::PgDal;

pub use repo_api_key::PgApiKeyRepo;
pub use repo_audit::PgAuditRepo;
pub use repo_evidence::PgEvidenceDossierRepo;
pub use repo_operator_config::PgOperatorConfigRepo;
pub use repo_passport::PgPassportRepo;
pub use repo_registry_identity::PgRegistryIdentityRepo;
pub use repo_registry_sync::PgRegistrySyncRepo;
pub use repo_transfer::PgTransferRepo;
/// Re-export so downstream crates (dpp-node's PgJobStore) can use the same
/// sqlx version without declaring their own dependency.
pub use sqlx;

use dpp_domain::DppError;

/// Map any sqlx error into the domain error space, surfacing the two
/// database-enforced invariants as their typed variants.
pub(crate) fn db_err(e: sqlx::Error) -> DppError {
    if let sqlx::Error::Database(ref db) = e {
        let msg = db.message();
        if msg.contains("ODAL_RETENTION") {
            return DppError::RetentionLocked;
        }
        if msg.contains("ODAL_AUDIT") {
            return DppError::Internal("audit entries are append-only".into());
        }
        if msg.contains("ODAL_EVIDENCE") {
            return DppError::Internal("evidence dossiers are append-only".into());
        }
    }
    DppError::Internal(format!("database: {e}"))
}
