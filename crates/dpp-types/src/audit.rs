//! Audit trail persistence port.
//!
//! The wire type and hash-chain algorithm were promoted to `dpp-core`'s
//! `dpp-evidence` crate (2026-07-08) — the shape is third-party-verifiable,
//! which makes it part of the proof-bound standard rather than engine
//! plumbing (this module's doc used to flag exactly this as a
//! "core-candidate"). This module now owns only what's legitimately
//! engine-side: persistence.
//!
//! Entries are append-only; the DB trigger raises `ODAL_AUDIT` on any UPDATE
//! or DELETE attempt, making the trail tamper-evident at the DB layer.

use async_trait::async_trait;
use dpp_domain::DppError;

pub use dpp_evidence::audit::{AuditChainBreak, AuditEntry, GENESIS_PREV_HASH, verify_audit_chain};

/// Port trait for audit trail persistence.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Append a new audit entry. The DB trigger prevents any update or delete.
    async fn append(&self, entry: AuditEntry) -> Result<(), DppError>;
    /// Retrieve the full audit trail for a passport, ordered by timestamp ascending.
    async fn list_by_passport(&self, passport_id: &str) -> Result<Vec<AuditEntry>, DppError>;
}
