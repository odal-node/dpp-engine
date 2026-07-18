//! Continuity snapshots — object-storage of pre-rendered public passport views.
//!
//! On publish (and on the status changes that leave the public tier) the node
//! pushes the **byte-identical** public passport view to object storage, so the
//! passport stays reachable under a stable path when the live node is
//! unreachable — EN 18221's "reachable for the product's life" posture as an
//! architecture, not an uptime promise.
//!
//! # Why this lives here (not in core's `dpp-domain::ports`)
//!
//! Whether a deployment mirrors its public views to object storage for
//! availability is purely operational — the DPP standard defines the public
//! view, not how a given node keeps it reachable. So this port stays engine-side
//! alongside `RegistrySyncOutbox` and `WebhookOutbox`, never promoted to a core
//! port. (`ArchivePort` is a separate, core-side concern: immutable Art. 13
//! retention, not a mutable availability mirror.)
//!
//! Two ports live here: [`SnapshotStore`] is the object-storage sink, and
//! [`SnapshotOutbox`] is the durable queue that decides *when* to drive it. See
//! [`SnapshotOutbox`] for why a queued row means "reconcile this passport"
//! rather than carrying an explicit put/remove action.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use dpp_domain::{DppError, domain::passport::PassportId};

/// Object-storage sink for pre-rendered public passport snapshots, keyed by
/// passport id.
///
/// The stored bytes are exactly what the public read serves (including the
/// public JWS), so a stale-but-signed snapshot is verifiably authentic. `put`
/// overwrites (the view is re-rendered on each publish); `remove` retires a
/// snapshot when the passport leaves the public tier (suspend/archive), so the
/// static tier never keeps serving `active` for a suspended passport.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Store (overwriting any prior) the byte-identical public-view JSON for
    /// `dpp_id`.
    ///
    /// # Errors
    /// Propagates the object-storage failure; callers treat it as non-fatal (the
    /// live node remains the source of truth).
    async fn put_public_json(&self, dpp_id: &str, bytes: &[u8]) -> Result<(), DppError>;

    /// Remove any stored snapshot for `dpp_id`. Idempotent — a missing object is
    /// success, not an error.
    ///
    /// # Errors
    /// Propagates the object-storage failure; callers treat it as non-fatal.
    async fn remove(&self, dpp_id: &str) -> Result<(), DppError>;
}

/// Persisted state of one reconcile row. Mirrors the `status` CHECK on
/// `odal.snapshot_outbox`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotReconcileStatus {
    /// A reconcile attempt is due or backed off (drainable).
    Pending,
    /// The static tier matches the passport's current state — terminal success
    /// (until the next state change re-arms the row).
    Reconciled,
    /// Retries exhausted — terminal failure, needs attention. The static tier
    /// may be serving stale content, so this is the gauge that matters.
    Exhausted,
}

impl SnapshotReconcileStatus {
    /// The exact string persisted in the `status` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Reconciled => "reconciled",
            Self::Exhausted => "exhausted",
        }
    }

    /// Parse a `status` column value. Unknown values map to `Pending` so an
    /// unexpected row is drained/inspected rather than silently ignored.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "reconciled" => Self::Reconciled,
            "exhausted" => Self::Exhausted,
            _ => Self::Pending,
        }
    }
}

/// One drainable reconcile row. Deliberately carries **no** action and no
/// rendered body — only the passport to reconcile and its retry bookkeeping.
/// The drain resolves the passport and derives put-or-remove from its *current*
/// status, which is what makes replays and duplicates harmless.
#[derive(Debug, Clone)]
pub struct SnapshotReconcileRow {
    /// Outbox row id.
    pub id: uuid::Uuid,
    /// The passport whose static-tier state should be made to match the DB.
    pub passport_id: PassportId,
    /// Attempts made so far (pre-increment).
    pub attempts: i32,
}

/// Aggregate counts for boot reconciliation and gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotOutboxCounts {
    /// Rows awaiting a reconcile attempt.
    pub pending: i64,
    /// Rows whose static-tier state matches the DB.
    pub reconciled: i64,
    /// Rows that gave up — the static tier may be stale.
    pub exhausted: i64,
}

/// The reconcile outbox — enqueue (from the lifecycle, after commit) and drain
/// (from the node's background loop). Implemented by the Postgres DAL.
///
/// # Why a row means "reconcile", not "put" or "remove"
///
/// An explicit action column makes the queue order-dependent: a `put` enqueued
/// at publish and a `remove` enqueued at suspend can be retried or drained out
/// of order, letting the stale `put` land last and re-publish a suspended
/// passport to the public tier under a still-valid signature. Deriving the
/// action from the passport's current status at drain time removes that failure
/// mode entirely — the drain always converges on the truth in the database, so
/// duplicate rows, replays after a crash, and reordering are all no-ops.
///
/// # Delivery guarantee
///
/// Enqueue is **after-commit**, matching `WebhookOutbox` rather than
/// `RegistrySyncOutbox`'s in-transaction coupling: the status-change paths
/// (`suspend`/`archive`/`declare_eol`) have no transaction to join — they
/// already enqueue their EU-registry status intent best-effort — so making the
/// snapshot strictly stronger on the identical code path would be incoherent.
/// Once a row exists it is loss-proof: failures back off and stay `pending`, so
/// a killed node reconciles on restart. The residual commit→enqueue window is
/// closed by a periodic reconciliation sweep, not by a transaction — a sweep
/// also repairs the divergences a transaction cannot (an `exhausted` row, a
/// bucket restored from backup, an object removed by hand).
#[async_trait]
pub trait SnapshotOutbox: Send + Sync {
    /// Record that `passport_id`'s public state changed and the static tier must
    /// be re-derived. Idempotent: re-arms an existing row (back to `pending`,
    /// due now, attempts reset) rather than stacking a second one, since one
    /// pending reconcile already subsumes any number of changes.
    async fn enqueue(&self, passport_id: PassportId) -> Result<(), DppError>;

    /// Rows due for a reconcile attempt (`pending`, `next_attempt_at <= now`),
    /// oldest first, capped at `limit`.
    async fn due(&self, limit: i64) -> Result<Vec<SnapshotReconcileRow>, DppError>;

    /// Terminal success: the static tier now matches the passport's state.
    async fn mark_reconciled(&self, id: uuid::Uuid) -> Result<(), DppError>;

    /// Transient failure: increment `attempts`, push `next_attempt_at` out by an
    /// exponential backoff, keep the row `pending`.
    async fn mark_attempt_failed(&self, id: uuid::Uuid, message: String) -> Result<(), DppError>;

    /// Terminal failure: mark `exhausted` and store the reason. The row stays for
    /// audit and is re-armed by the next state change — it is never deleted.
    async fn mark_exhausted(&self, id: uuid::Uuid, message: String) -> Result<(), DppError>;

    /// Counts by status, for boot reconciliation logs and gauges.
    async fn status_counts(&self) -> Result<SnapshotOutboxCounts, DppError>;
}
