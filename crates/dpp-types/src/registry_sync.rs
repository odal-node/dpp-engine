//! Transactional outbox for EU Central Registry synchronisation.
//!
//! ESPR Art. 13 requires every published passport to be registered with the EU
//! Central Registry (operational 20 Jul 2026). Registration must never be lost: a
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

use dpp_domain::{DppError, passport::PassportId};

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
    /// Accepted by the registry for asynchronous validation, verdict outstanding
    /// (drainable — the drain *polls* rather than resubmitting).
    ///
    /// Registration is not synchronous: the registry returns a record
    /// identifier and validates afterwards. Without this state the drain had to
    /// call that terminal success, which recorded every submission as complete
    /// and never learned if it was later refused.
    Submitted,
    /// Registered by the EU registry (terminal success).
    Registered,
    /// Rejected by the EU registry (terminal; needs human attention).
    Rejected,
    /// Withdrawn from service in the registry (terminal; not our defect).
    ///
    /// Kept apart from [`Self::Rejected`], which it used to be folded into: a
    /// rejection is a defective submission an operator can correct, a
    /// deactivation is not.
    Deactivated,
    /// The operator gave up on registering this passport, after the registry was
    /// shown to hold no submission for it (terminal; needs no one, and is
    /// visible).
    ///
    /// Kept apart from [`Self::Rejected`]: a rejection is the registry refusing a
    /// submission, and this is nobody refusing anything. The registry never
    /// received the passport, or never accepted it, and a person decided to stop
    /// asking. Nothing the drain writes can move a row out of it; only a
    /// re-publish queues the passport again.
    Abandoned,
}

impl RegistrySyncStatus {
    /// The exact string persisted in the `status` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Registered => "registered",
            Self::Rejected => "rejected",
            Self::Deactivated => "deactivated",
            Self::Abandoned => "abandoned",
        }
    }

    /// Parse a `status` column value. Unknown values map to `Pending` so an
    /// unexpected row is drained/inspected rather than silently ignored.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "submitted" => Self::Submitted,
            "registered" => Self::Registered,
            "rejected" => Self::Rejected,
            "deactivated" => Self::Deactivated,
            "abandoned" => Self::Abandoned,
            _ => Self::Pending,
        }
    }

    /// Whether the drain still has work to do on a row in this state.
    #[must_use]
    pub fn is_drainable(&self) -> bool {
        matches!(self, Self::Pending | Self::Submitted)
    }
}

/// An outstanding status change owed to the EU registry, held in the
/// `status_intent` column independently of the registration queue state.
///
/// Recorded by [`RegistrySyncOutbox::enqueue_status`] when a passport is
/// suspended, retired, or declared end-of-life. The registry has no published
/// status-push API yet, so nothing drains these — they are kept durably for
/// that path and cleared when a passport is re-published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryStatusIntent {
    /// Passport suspended (reversible — cleared on re-publish).
    Suspended,
    /// Passport deactivated (retire/EOL).
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
    /// Rows accepted by the registry and awaiting its verdict.
    pub submitted: i64,
    /// Rows the registry withdrew from service.
    pub deactivated: i64,
    /// Rows terminally registered.
    pub registered: i64,
    /// Rows terminally rejected (need attention).
    pub rejected: i64,
    /// Rows the operator gave up on after the registry was shown to hold nothing
    /// for them. Counted so a published passport that will not be registered is
    /// visible, and not read as one that is still owed.
    pub abandoned: i64,
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
        passport: &dpp_domain::passport::Passport,
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
    /// registration; `Draft -> Retired` is legal, so this is a normal path, not
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

    /// The registry accepted the submission for validation but has not ruled on
    /// it: record the identifier it returned and move the row to `submitted`, so
    /// the next drain polls for the verdict instead of registering again.
    ///
    /// An **empty** `registry_id` means the registry returned none, which is the
    /// case for a replayed submission: it is acknowledged, not re-described. The
    /// row keeps whatever id it already held and never records `''` as one.
    async fn mark_submitted(
        &self,
        passport_id: PassportId,
        registry_id: String,
    ) -> Result<(), DppError>;

    /// A `submitted` row that cannot be moved on by the drain, and the reason.
    ///
    /// Backed off and counted as an attempt exactly as [`Self::mark_submitted`]
    /// is, so it stops sorting to the head of the queue and reaches the stalled
    /// count that tells an operator it needs looking at. What differs is the
    /// `message`: it is **kept** and read back by the per-passport registry
    /// route, where `mark_submitted` clears it. A row waiting for a person, or
    /// for a state nobody has named, would otherwise show no reason, and the
    /// operator would have to find it in a log. The registry id the row holds is
    /// left as it is.
    async fn mark_submitted_noting(
        &self,
        passport_id: PassportId,
        message: String,
    ) -> Result<(), DppError>;

    /// A person has established the correlation identifier of a `submitted` row
    /// that holds none: record it, so the drain polls the submission by it.
    ///
    /// Returns whether the row took it. It takes it only while the row is
    /// `submitted` **and** holds no identifier, so it can never overwrite one the
    /// registry gave, never touch a row that has been ruled on, and loses a race
    /// with another writer rather than stacking on it. `false` means the row was
    /// not in that state when the write was made.
    ///
    /// The row's attempts start again and it is due at once. The poll that follows
    /// is a new one, run on a handle somebody checked, so the count that earned
    /// the stall belongs to what came before and must not keep the row reported
    /// as stalled while it is being polled. The message is cleared: whatever it
    /// said was about the missing handle.
    async fn record_handle(
        &self,
        passport_id: PassportId,
        correlation_id: &str,
    ) -> Result<bool, DppError>;

    /// A person has decided not to register this passport, and the registry has
    /// been shown to hold nothing for it: end the row as `abandoned`, keeping
    /// `message` as the account of why.
    ///
    /// Returns whether the row took it. It takes it only while the row is
    /// `pending`, has been **tried at least once**, and is **backed off**
    /// (`next_attempt_at` in the future). Each condition is a safety, not a
    /// convenience:
    ///
    /// - `pending` means the registry never acknowledged it. A `submitted` row is
    ///   one the registry holds, and ending that row would orphan a registration.
    /// - tried at least once means the drain has asked the registry about it and
    ///   been refused or failed, so the row is not simply new.
    /// - backed off means the drain is not about to pick it up, and is not in the
    ///   middle of doing so: a row being attempted is still due, and only a
    ///   finished attempt pushes it out. Without this an abandon could land
    ///   between the drain's read of the row and its `register` call, and the
    ///   registry would accept a passport this node had just recorded as given up.
    ///
    /// `false` means the row was not in that state when the write was made, and
    /// is the answer to a lost race as much as to a wrong state. Nothing the
    /// drain writes can move a row out of `abandoned` afterwards.
    async fn abandon(&self, passport_id: PassportId, message: String) -> Result<bool, DppError>;

    /// Terminal: the registry withdrew the record from service. Distinct from
    /// [`Self::mark_rejected`] — nothing about the submission was defective, so
    /// there is nothing to correct and resubmit.
    async fn mark_deactivated(
        &self,
        passport_id: PassportId,
        message: String,
    ) -> Result<(), DppError>;

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

    /// How many **Published** passports have no outbox row at all.
    ///
    /// A published passport owes a registration; one with no row owes it with
    /// nothing tracking it. That happens for passports published before this
    /// outbox existed, or lost to an older write path.
    ///
    /// This reports, it does not repair. A drain replays the *queued payload*,
    /// and for these there is none to rebuild — inventing a row would create an
    /// entry that can never drain, trading a visible gap for an invisible one.
    /// Re-publishing is the repair, and that is an operator's decision.
    async fn unregistered_published_count(&self) -> Result<i64, DppError>;
}
