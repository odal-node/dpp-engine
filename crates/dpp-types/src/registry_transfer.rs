//! Transactional outbox for EU Central Registry transfer-of-responsibility
//! notifications.
//!
//! A transfer moves the responsible economic operator for a passport. The
//! registry has to be told, and the notification must never be lost: a killed
//! node, an unreachable registry, or a rejected notification must all leave a
//! durable, inspectable record rather than a swallowed log line — the same
//! standard registration is held to.
//!
//! The `registry_transfer` table (`ops/pg/0029`) is that outbox. This module
//! declares the port; the Postgres implementation lives in
//! `dpp-dal::pg::repo_registry_transfer`.
//!
//! # Why this is not part of [`crate::RegistrySyncOutbox`]
//!
//! That outbox is keyed by `passport_id` — one registration per passport, which
//! is correct for registration and wrong for transfers. A passport is sold,
//! imported, remanufactured and repurposed over its life, and each of those is
//! a separate handover the registry needs to hear about. Sharing the row would
//! mean each transfer silently overwrote the last one's notification.
//!
//! So this is keyed by `transfer_id`, and it is a separate port rather than
//! extra methods on the other one: the two have different keys, different
//! lifecycles, and different terminal states.
//!
//! # The atomicity guarantee
//!
//! [`RegistryTransferOutbox::commit_accept`] persists the updated *transfer
//! chain* and *enqueues the notification row* in a **single** transaction, the
//! same invariant [`crate::RegistrySyncOutbox::commit_publish`] establishes for
//! registration: a transfer is never recorded as accepted without a
//! corresponding `pending` row, so a crash between the two writes cannot drop a
//! notification the registry is owed.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use dpp_domain::{
    DppError,
    domain::{passport::PassportId, transfer::TransferChain},
};

/// Queue state of one transfer notification.
///
/// Mirrors the `status` CHECK constraint on `odal.registry_transfer`. `Pending`
/// rows are the ones the drain acts on; the other two are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryTransferStatus {
    /// A notification attempt is due (drainable).
    Pending,
    /// Accepted by the EU registry (terminal success).
    Notified,
    /// Rejected by the EU registry (terminal; needs human attention).
    Rejected,
}

impl RegistryTransferStatus {
    /// The exact string persisted in the `status` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Notified => "notified",
            Self::Rejected => "rejected",
        }
    }

    /// Parse a `status` column value. Unknown values map to `Pending` so an
    /// unexpected row is drained/inspected rather than silently ignored.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "notified" => Self::Notified,
            "rejected" => Self::Rejected,
            _ => Self::Pending,
        }
    }
}

/// One outbox row — the durable record of a transfer notification's state.
#[derive(Debug, Clone)]
pub struct RegistryTransferRow {
    /// The transfer this row notifies. Also the row's primary key.
    pub transfer_id: Uuid,
    /// The passport whose responsibility moved.
    pub passport_id: PassportId,
    /// Current queue state.
    pub status: RegistryTransferStatus,
    /// Serialised `TransferRecord` captured when the transfer was accepted —
    /// both operators, the reason, and both signatures.
    pub payload: serde_json::Value,
    /// Registry-assigned record id, once notified.
    pub registry_id: Option<String>,
    /// Last error/status message, if any.
    pub message: Option<String>,
    /// Number of drain attempts so far.
    pub attempts: i32,
    /// When this row is next eligible for a drain attempt.
    pub next_attempt_at: DateTime<Utc>,
}

/// Aggregate counts for boot reconciliation and metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryTransferCounts {
    /// Rows awaiting a drain attempt.
    pub pending: i64,
    /// Rows terminally notified.
    pub notified: i64,
    /// Rows terminally rejected (need attention).
    pub rejected: i64,
    /// Pending rows whose `attempts` have reached the stall threshold — these
    /// are the ones a human must investigate (never silently dropped).
    pub stalled: i64,
}

/// Transactional outbox for EU registry transfer notifications.
#[async_trait]
pub trait RegistryTransferOutbox: Send + Sync {
    /// Atomically persist the updated transfer chain **and** enqueue the
    /// notification for the just-accepted transfer, in one transaction.
    ///
    /// `payload` is the serialised `TransferRecord`. On `transfer_id` conflict
    /// the enqueue is a no-op: a transfer is accepted once, so a conflict means
    /// a retry of the same handover, not a new one. The chain write still
    /// applies.
    async fn commit_accept(
        &self,
        chain: &TransferChain,
        transfer_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<(), DppError>;

    /// Rows due for a drain attempt (`pending`, `next_attempt_at <= now`),
    /// oldest first, capped at `limit`.
    async fn due(&self, limit: i64) -> Result<Vec<RegistryTransferRow>, DppError>;

    /// Terminal success: mark `notified` and store the registry id.
    async fn mark_notified(&self, transfer_id: Uuid, registry_id: String) -> Result<(), DppError>;

    /// Terminal failure: mark `rejected` and store the reason. The row stays for
    /// audit — a human investigates, it is never deleted.
    async fn mark_rejected(&self, transfer_id: Uuid, message: String) -> Result<(), DppError>;

    /// Transient failure: increment `attempts`, push `next_attempt_at` out by an
    /// exponential backoff (with jitter), keep the row `pending`.
    async fn mark_attempt_failed(&self, transfer_id: Uuid, message: String)
    -> Result<(), DppError>;

    /// Every notification row recorded for a passport, newest first
    /// (reconciliation/inspection).
    async fn rows_for(&self, passport_id: PassportId)
    -> Result<Vec<RegistryTransferRow>, DppError>;

    /// Counts by status plus the stalled count (`pending` rows whose `attempts`
    /// have reached `stall_threshold`).
    async fn status_counts(&self, stall_threshold: i32)
    -> Result<RegistryTransferCounts, DppError>;
}
