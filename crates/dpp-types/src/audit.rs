//! Audit trail types and repository port.
//!
//! Audit entries record every state-changing operation on a passport.
//! The database enforces append-only at the trigger level — entries are never
//! updated or deleted.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::DppError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::AuthContext;

/// The `prev_hash` of the first (genesis) entry in a passport's chain.
pub const GENESIS_PREV_HASH: &str = "";

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
    /// Hash-chain link to the previous entry in this passport's chain.
    /// `""`/`None` for the genesis entry. Set by the repo on append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    /// SHA-256 (hex) over the JCS-canonicalised content of this entry folded
    /// with `prev_hash` — the chain link the next entry points back to. Set by
    /// the repo on append; `None` on an in-memory entry not yet persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
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
            prev_hash: None,
            entry_hash: None,
        }
    }

    /// Attach structured metadata to this entry (builder-style).
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// The chain hash for this entry given its predecessor's hash: SHA-256 (hex)
    /// over the JCS-canonicalised content **and** `prev_hash`. Excludes the
    /// `prev_hash`/`entry_hash` columns themselves (prev is folded in as
    /// `prevHash`). Deterministic — the same content + prev always hashes equal.
    #[must_use]
    pub fn chain_hash(&self, prev_hash: &str) -> String {
        let canonical = serde_json::json!({
            "id": self.id,
            "passportId": self.passport_id,
            "actor": self.actor,
            "action": self.action,
            "previousStatus": self.previous_status,
            "newStatus": self.new_status,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "prevHash": prev_hash,
        });
        let bytes = serde_jcs::to_vec(&canonical)
            .expect("JCS canonicalisation of audit content is infallible");
        hex::encode(Sha256::digest(&bytes))
    }
}

/// The first broken link found while verifying a passport's audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainBreak {
    /// 0-based position of the offending entry in the ordered chain.
    pub index: usize,
    /// The passport whose chain broke.
    pub passport_id: String,
    /// Human-readable reason (prev-link mismatch vs. content tamper).
    pub reason: String,
}

/// Verify a passport's audit entries form an intact hash chain.
///
/// `entries` must be in chain order (ascending timestamp). Returns the first
/// break: either a `prev_hash` that doesn't point at the prior entry, or an
/// `entry_hash` that doesn't match the entry's recomputed content hash (a
/// tampered row). `Ok(())` means every link verifies.
///
/// This detects any tamper that does not re-hash the *entire forward chain*;
/// pinning the head with a signed checkpoint is what
/// makes a full re-hash detectable by a third party without DB access.
///
/// # Errors
/// [`AuditChainBreak`] at the first inconsistent entry.
pub fn verify_audit_chain(entries: &[AuditEntry]) -> Result<(), AuditChainBreak> {
    let mut expected_prev = GENESIS_PREV_HASH.to_owned();
    for (index, entry) in entries.iter().enumerate() {
        let stored_prev = entry.prev_hash.as_deref().unwrap_or(GENESIS_PREV_HASH);
        if stored_prev != expected_prev {
            return Err(AuditChainBreak {
                index,
                passport_id: entry.passport_id.clone(),
                reason: format!(
                    "prev_hash link broken: stored {stored_prev:?}, expected {expected_prev:?}"
                ),
            });
        }
        let recomputed = entry.chain_hash(&expected_prev);
        let stored_hash = entry.entry_hash.as_deref().unwrap_or("");
        if stored_hash != recomputed {
            return Err(AuditChainBreak {
                index,
                passport_id: entry.passport_id.clone(),
                reason: "entry_hash mismatch — content tampered".to_owned(),
            });
        }
        expected_prev = recomputed;
    }
    Ok(())
}

/// Port trait for audit trail persistence.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Append a new audit entry. The DB trigger prevents any update or delete.
    async fn append(&self, entry: AuditEntry) -> Result<(), DppError>;
    /// Retrieve the full audit trail for a passport, ordered by timestamp ascending.
    async fn list_by_passport(&self, passport_id: &str) -> Result<Vec<AuditEntry>, DppError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(action: &str) -> AuditEntry {
        AuditEntry {
            id: Uuid::now_v7(),
            passport_id: "p1".into(),
            actor: "actor".into(),
            action: action.into(),
            previous_status: None,
            new_status: None,
            metadata: None,
            timestamp: Utc::now(),
            prev_hash: None,
            entry_hash: None,
        }
    }

    /// Link a slice into a chain exactly as the repo's append path does.
    fn chain(entries: &mut [AuditEntry]) {
        let mut prev = GENESIS_PREV_HASH.to_owned();
        for e in entries.iter_mut() {
            let h = e.chain_hash(&prev);
            e.prev_hash = Some(prev.clone());
            e.entry_hash = Some(h.clone());
            prev = h;
        }
    }

    #[test]
    fn chain_hash_is_deterministic_and_prev_sensitive() {
        let e = entry("created");
        assert_eq!(e.chain_hash(""), e.chain_hash(""));
        assert_ne!(e.chain_hash(""), e.chain_hash("deadbeef"));
    }

    #[test]
    fn intact_chain_verifies() {
        let mut es = [entry("created"), entry("published"), entry("suspended")];
        chain(&mut es);
        assert!(verify_audit_chain(&es).is_ok());
    }

    #[test]
    fn tampered_content_breaks_at_exact_index() {
        let mut es = [entry("created"), entry("published"), entry("archived")];
        chain(&mut es);
        es[1].new_status = Some("suspended".into()); // flip content, keep stored hash
        let brk = verify_audit_chain(&es).expect_err("tamper must be detected");
        assert_eq!(brk.index, 1);
        assert!(brk.reason.contains("tampered"));
    }

    #[test]
    fn broken_prev_link_detected() {
        let mut es = [entry("created"), entry("published")];
        chain(&mut es);
        es[1].prev_hash = Some("0000".into());
        assert_eq!(verify_audit_chain(&es).expect_err("break").index, 1);
    }
}
