//! Transactional outbox for EU Central Registry synchronisation.
//!
//! ESPR Art. 13 requires every published passport to be registered with the EU
//! Central Registry (live 19 Jul 2026). Registration must never be lost: a
//! killed node, an unreachable registry, or a rejected payload must all leave a
//! durable, inspectable record rather than a swallowed log line.
//!
//! The `registry_sync` table (`ops/pg/0006`) is that outbox — one row per
//! passport (`passport_id UNIQUE`). This module declares the port; the
//! Postgres implementation lives in `dpp-dal::pg::repo_registry_sync`.
//!
//! # The atomicity guarantee
//!
//! [`RegistrySyncOutbox::commit_publish`] persists the *published passport* and
//! *enqueues its registration row* in a **single** database transaction. This
//! is the invariant the whole chunk exists to establish: a passport is never
//! marked Published without a corresponding `pending` outbox row, so a crash
//! between the two writes cannot silently drop a legally-required registration.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use dpp_domain::{DppError, domain::passport::PassportId};

/// Persisted sync state of a passport's registry registration.
///
/// Mirrors the `status` CHECK constraint on `odal.registry_sync`. `Pending`
/// rows are the ones the drain worker acts on (`register`); the remaining
/// variants are terminal or record a status-change intent (see
/// [`RegistrySyncOutbox::enqueue_status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrySyncStatus {
    /// A registration/sync attempt is due (drainable).
    Pending,
    /// Registered by the EU registry (terminal success).
    Registered,
    /// Rejected by the EU registry (terminal; needs human attention).
    Rejected,
    /// Status-change intent: passport suspended.
    Suspended,
    /// Status-change intent: passport deactivated (archive/EOL).
    Deactivated,
}

impl RegistrySyncStatus {
    /// The exact string persisted in the `status` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Registered => "registered",
            Self::Rejected => "rejected",
            Self::Suspended => "suspended",
            Self::Deactivated => "deactivated",
        }
    }

    /// Parse a `status` column value. Unknown values map to `Pending` so an
    /// unexpected row is drained/inspected rather than silently ignored.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "registered" => Self::Registered,
            "rejected" => Self::Rejected,
            "suspended" => Self::Suspended,
            "deactivated" => Self::Deactivated,
            _ => Self::Pending,
        }
    }
}

/// One outbox row — the durable record of a passport's registry sync state.
///
/// `payload` holds the serialised `dpp_domain::ports::registry_sync::RegistrationRequest`
/// captured at publish time, so the drain worker can rebuild the exact request
/// without re-reading the passport.
#[derive(Debug, Clone)]
pub struct RegistrySyncRow {
    /// The passport this row registers.
    pub passport_id: PassportId,
    /// Current sync status.
    pub status: RegistrySyncStatus,
    /// Registry-assigned record id, once registered.
    pub registry_id: Option<String>,
    /// Serialised `RegistrationRequest` captured at publish time.
    pub payload: Option<serde_json::Value>,
    /// Last error/status message, if any.
    pub message: Option<String>,
    /// Number of drain attempts so far.
    pub attempts: i32,
    /// When this row is next eligible for a drain attempt.
    pub next_attempt_at: DateTime<Utc>,
}

/// Aggregate counts for boot reconciliation and metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrySyncCounts {
    /// Rows awaiting a drain attempt.
    pub pending: i64,
    /// Rows terminally registered.
    pub registered: i64,
    /// Rows terminally rejected (need attention).
    pub rejected: i64,
    /// Rows recording a suspended/deactivated status intent.
    pub status_intents: i64,
    /// Pending rows whose `attempts` have reached the stall threshold — these
    /// are the ones a human must investigate (never silently dropped).
    pub stalled: i64,
}

/// Transactional outbox for EU Central Registry registration.
///
/// Implemented by the Postgres DAL. Kept in `dpp-types` (not `dpp-core`) because
/// the outbox is a platform persistence concern — the core `RegistrySyncPort`
/// stays untouched.
#[async_trait]
pub trait RegistrySyncOutbox: Send + Sync {
    /// Atomically persist the just-published passport **and** enqueue its
    /// registration row in one transaction.
    ///
    /// `payload` is the serialised `RegistrationRequest`. On `passport_id`
    /// conflict the enqueue is a no-op (idempotent re-publish), but the passport
    /// write still applies. This is the invariant that makes registration
    /// loss-proof — see the module docs.
    async fn commit_publish(
        &self,
        passport: &dpp_domain::domain::passport::Passport,
        payload: serde_json::Value,
    ) -> Result<(), DppError>;

    /// Record a status-change intent (suspend/deactivate) on an existing row,
    /// upserting one if the passport predates the outbox. The EU registry has no
    /// published status-push API yet, so these are recorded durably for the
    /// Phase-B status-sync path rather than drained here.
    async fn enqueue_status(
        &self,
        passport_id: PassportId,
        status: RegistrySyncStatus,
    ) -> Result<(), DppError>;

    /// Rows due for a drain attempt (`pending`, `next_attempt_at <= now`),
    /// oldest first, capped at `limit`.
    async fn due(&self, limit: i64) -> Result<Vec<RegistrySyncRow>, DppError>;

    /// Terminal success: mark `registered` and store the registry id.
    async fn mark_registered(
        &self,
        passport_id: PassportId,
        registry_id: String,
    ) -> Result<(), DppError>;

    /// Terminal failure: mark `rejected` and store the reason. The row stays for
    /// audit — a human investigates, it is never deleted.
    async fn mark_rejected(&self, passport_id: PassportId, message: String)
    -> Result<(), DppError>;

    /// Transient failure: increment `attempts`, push `next_attempt_at` out by an
    /// exponential backoff (with jitter), keep the row `pending`.
    async fn mark_attempt_failed(
        &self,
        passport_id: PassportId,
        message: String,
    ) -> Result<(), DppError>;

    /// The current row for a passport, if any (reconciliation/inspection).
    async fn pending_for(
        &self,
        passport_id: PassportId,
    ) -> Result<Option<RegistrySyncRow>, DppError>;

    /// Counts by status plus the stalled count (`pending` rows whose `attempts`
    /// have reached `stall_threshold`). Feeds boot reconciliation logs and the
    /// `registry_outbox_*` gauges.
    async fn status_counts(&self, stall_threshold: i32) -> Result<RegistrySyncCounts, DppError>;
}
