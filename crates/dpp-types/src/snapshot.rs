//! Continuity snapshots — object-storage of pre-rendered public passport views.
//!
//! On publish (and on the status changes that leave the public tier) the node
//! pushes the passport's signed public view to object storage, so the passport
//! stays reachable under a stable path when the live node is unreachable —
//! EN 18221's "reachable for the product's life" posture as an architecture,
//! not an uptime promise.
//!
//! # The claim is bounded
//!
//! A snapshot carries `asOf` and `validUntil` and its own proof over both, and
//! the node re-signs published snapshots on a cadence far shorter than that
//! window. That makes withdrawal *stop refreshing*, which is the only form of
//! withdrawal that works while the node is down — the state this tier exists to
//! serve, and therefore the state in which a withdrawal must still take effect.
//! It also reaches a copy that has already left: a cache, a mirror, or a file
//! someone kept expires on its own, with no cooperation from anybody.
//!
//! Without the bound the tier serves a claim it cannot stand behind. A copy of
//! an unbounded signed view is indistinguishable from a live response, forever,
//! to any verifier — so a suspended passport keeps answering `active` under a
//! signature that still checks out. Staleness signalled only by an HTTP header
//! does not survive being cached or copied and is not covered by any signature.
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

/// The object key a passport's machine-readable snapshot is written at,
/// relative to the bucket root and to whatever base URL serves it.
///
/// # Why this is not private to the store
///
/// Two places have to agree on it and they live in different crates: the store
/// writes the object, and `publish` declares a back-up URL to the EU registry
/// that has to point at the object the store wrote. They did not agree — the
/// store wrote `{id}/public.json` while the declaration said `{id}.json`, so an
/// operator who configured the feature published a link one path segment away
/// from the file, and `.env.example` documented the wrong one of the two.
///
/// Nothing could catch that. The registry payload's own validation checks the
/// scheme and stops, because `https://host/dpp/{id}.json` is a perfectly
/// well-formed URL that happens to address nothing; reachability is the
/// registry's check, so the first party to notice would have been the registry,
/// on a live registration.
///
/// One definition, used by both, is what stops them drifting apart again.
#[must_use]
pub fn snapshot_json_key(dpp_id: &str) -> String {
    format!("{dpp_id}/public.json")
}

/// The rendered HTML sibling of [`snapshot_json_key`].
///
/// Written for a human who reaches the static tier directly. Deliberately *not*
/// what the registry back-up URL points at: that link is consumed by machines,
/// and the JSON view is the one carrying the signatures a verifier needs.
#[must_use]
pub fn snapshot_html_key(dpp_id: &str) -> String {
    format!("{dpp_id}/public.html")
}

use dpp_domain::{DppError, passport::PassportId};

/// When a snapshot was taken and how long it vouches for itself, carried
/// alongside the bytes so the object store can state both outside the signature
/// as well as inside it.
///
/// The signed `validUntil` in the payload is the binding claim — it survives a
/// copy, a cache and a mirror, which is the whole point. These are the
/// unsigned, transport-level echo of it: a `Cache-Control` and a couple of
/// user-metadata headers that a direct reader (one who never passes through the
/// reverse proxy and so never sees the proxy's own headers) still gets. They do
/// not replace the signed bound and must never be relied on as if they did —
/// they close the gap for the ordinary well-behaved consumer, not the
/// determined one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// The instant this snapshot was rendered — the same value signed into the
    /// payload as `asOf`.
    pub as_of: chrono::DateTime<chrono::Utc>,
    /// When the snapshot stops vouching for itself — the same value signed into
    /// the payload as `validUntil`.
    pub valid_until: chrono::DateTime<chrono::Utc>,
    /// How long a cache may hold this object. Set from the *refresh* cadence,
    /// not from `valid_until`: a newer snapshot exists once a refresh cycle has
    /// passed, so telling an intermediary it may hold this one for the whole
    /// validity window would let it serve a copy the node has already replaced.
    pub max_age: std::time::Duration,
}

/// Object-storage sink for pre-rendered public passport snapshots, keyed by
/// passport id.
///
/// The stored bytes are the passport's signed public view — the same fields,
/// carrying the same publish-time `publicJwsSignature`, that the live public
/// read serves — plus the bounded-claim fields (`asOf`, `validUntil`) and the
/// snapshot's own proof over the whole document. So a stale copy is verifiably
/// authentic *and* verifiably dated, which the passport's publish-time proof
/// alone cannot make it: that proof is frozen and says nothing about when the
/// copy was taken. `put` overwrites (the view is re-rendered on each reconcile
/// and on each refresh); `remove` retires a snapshot when the passport leaves
/// the public tier (suspend/archive), so the static tier never keeps serving
/// `active` for a suspended passport.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Store (overwriting any prior) the public-view JSON for `dpp_id`.
    ///
    /// # Errors
    /// Propagates the object-storage failure; callers treat it as non-fatal (the
    /// live node remains the source of truth).
    async fn put_public_json(
        &self,
        dpp_id: &str,
        bytes: &[u8],
        meta: SnapshotMeta,
    ) -> Result<(), DppError>;

    /// Store (overwriting any prior) the pre-rendered public **page** for
    /// `dpp_id`.
    ///
    /// Stored beside the JSON rather than instead of it: the JSON is the signed
    /// artifact a verifier checks, the page is what a person scanning a QR code
    /// actually needs to read. Serving only JSON would keep the passport
    /// technically reachable while being useless to the consumer it exists for.
    ///
    /// # Errors
    /// Propagates the object-storage failure; callers treat it as non-fatal (the
    /// live node remains the source of truth).
    async fn put_public_html(
        &self,
        dpp_id: &str,
        bytes: &[u8],
        meta: SnapshotMeta,
    ) -> Result<(), DppError>;

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

    /// Repair sweep: queue reconciles for passports whose static-tier state may
    /// have drifted from the database, capped at `limit`. Returns how many rows
    /// were queued or re-armed.
    ///
    /// This is what makes the tier's guarantee end-to-end rather than merely
    /// "loss-proof once enqueued". [`Self::enqueue`] is called after commit, so
    /// a crash in the window between the two loses the reconcile; a transaction
    /// would close only that window, while a sweep also repairs what a
    /// transaction never could — a row that exhausted its retries, and drift
    /// left by any past code path that failed to enqueue at all.
    ///
    /// Targeted, not exhaustive: it queries for actual divergence signals
    /// (never reconciled, exhausted, or reconciled before the passport last
    /// changed) rather than re-uploading every passport on a timer, so a
    /// converged deployment sweeps to zero work. Only passports that have been
    /// published are considered — one never published can have nothing in the
    /// public tier to repair.
    ///
    /// Not detected: an object deleted or restored *behind* the node, since
    /// nothing in the database records that. Closing it means listing object
    /// storage and diffing, which is a separate, heavier mechanism.
    async fn enqueue_divergent(&self, limit: i64) -> Result<u64, DppError>;

    /// Refresh pass: queue reconciles for passports whose snapshot was last
    /// written more than `older_than` ago, capped at `limit`. Returns how many
    /// rows were queued.
    ///
    /// This is what keeps a live passport's snapshot from expiring. Each
    /// reconcile re-renders and re-signs with a later `validUntil`, so a
    /// published passport stays vouched for while a withdrawn one simply stops
    /// being renewed and lapses on its own.
    ///
    /// **Deliberately not folded into [`Self::enqueue_divergent`].** The two
    /// answer different questions and one of them is a health signal: a
    /// divergent row means the event-driven path dropped something, and a
    /// steady trickle of them is a defect worth investigating. Refresh rows are
    /// the *expected* steady state and would drown that signal completely —
    /// after which nobody could tell a broken enqueue path from a working one.
    /// They share the re-arm path, so the drain still needs no special case and
    /// a refreshed row is indistinguishable from a lifecycle-queued one once
    /// queued; only the reason for queueing it is kept apart.
    ///
    /// Ordered by staleness, oldest snapshot first, so that when the corpus is
    /// larger than one batch the passports nearest expiry are the ones renewed.
    /// Ordering by anything else lets a snapshot lapse while a fresher one is
    /// rewritten ahead of it.
    async fn enqueue_stale(
        &self,
        older_than: chrono::Duration,
        limit: i64,
    ) -> Result<u64, DppError>;

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
