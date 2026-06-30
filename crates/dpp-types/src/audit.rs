//! Audit trail types and repository port.
//!
//! Audit entries record every state-changing operation on a passport.
//! The database enforces append-only at the trigger level — entries are never
//! updated or deleted.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::DppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

/// A single immutable audit record for a passport state change.
///
/// Entries are append-only; the DB trigger raises `ODAL_AUDIT` on any
/// UPDATE or DELETE attempt, making the trail tamper-evident at the DB layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// Unique identifier for this audit record.
    pub id: Uuid,
    /// The passport this entry is for (stringified UUID for forward-compat).
    pub passport_id: String,
    /// `user_id` of the actor who triggered this change, from `AuthContext`.
    pub actor: String,
    /// Machine-readable action code, e.g. `"create"`, `"publish"`, `"archive"`.
    pub action: String,
    /// Passport status before the transition, if applicable.
    pub previous_status: Option<String>,
    /// Passport status after the transition, if applicable.
    pub new_status: Option<String>,
    /// Optional structured metadata (e.g. field diffs, EU registry sync result).
    pub metadata: Option<serde_json::Value>,
    /// Wall-clock timestamp of the operation (UUIDv7 source; sub-millisecond ordered).
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    /// Construct an audit entry from an action and its auth context.
    ///
    /// `id` is a new UUIDv7 so entries are time-ordered within a passport.
    /// Single-tenant: `actor` carries `user_id` only — there is no operator
    /// scope to include (DECISION-0002).
    pub fn new(
        passport_id: &str,
        action: &str,
        auth: &AuthContext,
        previous_status: Option<&str>,
        new_status: Option<&str>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            passport_id: passport_id.to_owned(),
            // Single-tenant: `actor` carries who acted; there is no operator scope.
            actor: auth.user_id.clone(),
            action: action.to_owned(),
            previous_status: previous_status.map(|s| s.to_owned()),
            new_status: new_status.map(|s| s.to_owned()),
            metadata: None,
            timestamp: Utc::now(),
        }
    }

    /// Attach structured metadata to this entry (builder-style).
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Port trait for audit trail persistence.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Append a new audit entry. The DB trigger prevents any update or delete.
    async fn append(&self, entry: AuditEntry) -> Result<(), DppError>;
    /// Retrieve the full audit trail for a passport, ordered by timestamp ascending.
    async fn list_by_passport(&self, passport_id: &str) -> Result<Vec<AuditEntry>, DppError>;
}
