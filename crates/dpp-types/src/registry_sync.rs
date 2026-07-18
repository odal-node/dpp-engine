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
//!
//! # Queue state and status intent are separate columns
//!
//! The transaction above protects against a *crash* between the two writes. It
//! does nothing about a *later* write overwriting the queue state, which is how
//! registrations were being lost: `status` held both "a registration is still
//! owed" and "this status should eventually be pushed to the registry", so
//! recording a suspend/EOL intent overwrote `pending` and [`RegistrySyncOutbox::due`]
//! stopped selecting the row. Nothing re-armed it — [`RegistrySyncOutbox::commit_publish`]
//! only re-queues rows sitting at `rejected`.
//!
//! So the two facts live in two columns (`ops/pg/0024`), and two types:
//! [`RegistrySyncStatus`] is queue state, moved only by the drain and the
//! publish transaction; [`RegistryStatusIntent`] is the outstanding intent,
//! recorded by [`RegistrySyncOutbox::enqueue_status`]. Because they are distinct
//! types, `enqueue_status` *cannot* write a queue state — the compiler rejects it.
//!
//! # Why this port lives here and not in core's `dpp-domain::ports`
//!
//! The DPP standard defines *that* a passport must be registered — it says
//! nothing about queuing, retry, or outbox mechanics for getting there. Those
//! are this deployment's operational concern, so the port stays engine-side
//! alongside `TransferStore`, not promoted to a core port.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use dpp_domain::{DppError, domain::passport::PassportId};

/// Queue state of a passport's registry registration.
///
/// Mirrors the `status` CHECK constraint on `odal.registry_sync`. `Pending`
/// rows are the ones the drain worker acts on (`register`); the other two are
/// terminal. Moved only by the drain (`mark_*`) and the publish transaction —
/// never by a status change on the passport, which is what
/// [`RegistryStatusIntent`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrySyncStatus {
    /// A registration attempt is due (drainable).
    Pending,
    /// Registered by the EU registry (terminal success).
    Registered,
    /// Rejected by the EU registry (terminal; needs human attention).
    Rejected,
}

impl RegistrySyncStatus {
    /// The exact string persisted in the `status` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Registered => "registered",
            Self::Rejected => "rejected",
        }
    }

    /// Parse a `status` column value. Unknown values map to `Pending` so an
    /// unexpected row is drained/inspected rather than silently ignored.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "registered" => Self::Registered,
            "rejected" => Self::Rejected,
            _ => Self::Pending,
        }
    }
}

/// An outstanding status change owed to the EU registry, held in the
/// `status_intent` column independently of the registration queue state.
///
/// Recorded by [`RegistrySyncOutbox::enqueue_status`] when a passport is
/// suspended, archived, or declared end-of-life. The registry has no published
/// status-push API yet, so nothing drains these — they are kept durably for
/// that path and cleared when a passport is re-published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryStatusIntent {
    /// Passport suspended (reversible — cleared on re-publish).
    Suspended,
    /// Passport deactivated (archive/EOL).
    Deactivated,
}

impl RegistryStatusIntent {
    /// The exact string persisted in the `status_intent` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Suspended => "suspended",
            Self::Deactivated => "deactivated",
        }
    }

    /// Parse a `status_intent` column value; `None` for NULL or unrecognised.
    #[must_use]
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "suspended" => Some(Self::Suspended),
            "deactivated" => Some(Self::Deactivated),
            _ => None,
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
    /// Current queue state of the registration.
    pub status: RegistrySyncStatus,
    /// Status change owed to the registry, independent of `status`.
    pub status_intent: Option<RegistryStatusIntent>,
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
    /// Rows carrying an outstanding status intent. Independent of the counts
    /// above — a row can be `pending` *and* carry an intent.
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
    ///
    /// Also clears any `status_intent`: re-publishing is the transition that
    /// makes a recorded `Suspended` obsolete, and a suspended passport *can* be
    /// re-published. Leaving it would let the future status-sync path push a
    /// suspension for a passport that is live again.
    async fn commit_publish(
        &self,
        passport: &dpp_domain::domain::passport::Passport,
        payload: serde_json::Value,
    ) -> Result<(), DppError>;

    /// Record a status-change intent (suspend/deactivate) on an existing row.
    /// The EU registry has no published status-push API yet, so these are
    /// recorded durably for the Phase-B status-sync path rather than drained here.
    ///
    /// Never touches the registration queue state: a passport suspended before
    /// its registration drained still owes that registration, and the row stays
    /// `pending` so [`RegistrySyncOutbox::due`] keeps returning it.
    ///
    /// A no-op when the passport has no row — deliberately *not* an error.
    /// [`RegistrySyncOutbox::commit_publish`] is the only thing that creates
    /// rows, so no row means the passport never published and owes no
    /// registration; `Draft -> Archived` is legal, so this is a normal path, not
    /// a missing-row bug. (A passport published before this outbox existed also
    /// has no row and no payload to register from. Surfacing those belongs in a
    /// reconciliation query over Published passports lacking a row — not in a
    /// fabricated outbox entry that can never be drained.)
    async fn enqueue_status(
        &self,
        passport_id: PassportId,
        intent: RegistryStatusIntent,
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
