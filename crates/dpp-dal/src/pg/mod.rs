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
pub mod repo_snapshot;
pub mod repo_transfer;
pub mod repo_webhook;

pub use pool::PgDal;

pub use repo_api_key::PgApiKeyRepo;
pub use repo_audit::PgAuditRepo;
pub use repo_evidence::PgEvidenceDossierRepo;
pub use repo_operator_config::PgOperatorConfigRepo;
pub use repo_passport::PgPassportRepo;
pub use repo_registry_identity::PgRegistryIdentityRepo;
pub use repo_registry_sync::PgRegistrySyncRepo;
pub use repo_snapshot::PgSnapshotOutboxRepo;
pub use repo_transfer::PgTransferRepo;
pub use repo_webhook::PgWebhookRepo;
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

/// Turn an `UPDATE`/`DELETE` that matched no row into `NotFound` rather than a
/// silent success — a status transition against an absent or already-processed
/// row is a real error, not a no-op. Shared by every outbox repo's mark-*
/// methods so this can't drift into "surfaced in some, silently ignored in
/// others" the way it previously had (registry_sync checked it, snapshot and
/// webhook did not).
pub(crate) fn require_updated(
    res: &sqlx::postgres::PgQueryResult,
    row_kind: &str,
    id: impl std::fmt::Display,
) -> Result<(), DppError> {
    if res.rows_affected() == 0 {
        return Err(DppError::NotFound(format!("{row_kind} {id}")));
    }
    Ok(())
}
