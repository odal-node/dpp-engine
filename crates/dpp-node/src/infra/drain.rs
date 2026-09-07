//! Shared cadence for the node's outbox drain loops (registry sync, webhook
//! delivery, continuity snapshots).

/// How often every outbox drain loop wakes.
///
/// Lives in the library rather than the binary's `boot::tasks` because for the
/// continuity tier this is not a tuning knob: a passport that leaves the public
/// tier stops being served from the static tier within one cycle, so this bounds
/// the worst-case window in which a stale `published` snapshot can still be
/// served.
///
/// That makes it the suspend lag an operator is owed a number for, which is why
/// a test pins it rather than letting it drift with whoever last tuned a loop.
/// Wherever the window is stated — an agreement, an operator-facing page, an
/// answer to a due-diligence question — the statement has to move with this
/// constant, or it stops being true the moment the constant changes.
pub const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// How often the continuity tier's repair sweep runs.
///
/// Deliberately far rarer than [`DRAIN_INTERVAL`]: the sweep is a backstop for
/// divergence the event-driven path missed, not the path itself. It is also the
/// only bound on how long a *lost* reconcile (one whose enqueue never landed)
/// can leave the static tier stale — the drain interval bounds reconciles that
/// were successfully queued, this one bounds the ones that were not.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// How long a continuity snapshot vouches for itself: the `validUntil` written
/// into the signed payload is `asOf + SNAPSHOT_VALIDITY`.
///
/// **This is a policy number, not a tuning knob**, and it is the same number
/// read from two directions:
///
/// - It is the longest a **withdrawn** passport can keep answering from a copy
///   the node can no longer reach — a cache, a mirror, a file someone kept.
///   Every mechanism that needs the node to be up has already failed by then;
///   this is what remains.
/// - It is the longest **outage** the tier can ride out before a passport that
///   is perfectly valid stops being served. That is the availability posture
///   the tier exists to provide, and shortening the window spends it.
///
/// Seven days settles those against each other: a week is short enough that a
/// withdrawal is not indefinite, and long enough to cover an outage that spans
/// a weekend and the working days on either side of it — the realistic shape of
/// an operator's worst case, since the recovery needs a person. Changing it
/// moves an accuracy duty and an availability duty in opposite directions at
/// once, so it is a decision to be taken deliberately rather than tuned.
///
/// Must stay comfortably longer than [`SNAPSHOT_REFRESH_INTERVAL`] — see there.
pub const SNAPSHOT_VALIDITY: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// How stale a snapshot may get before the refresh pass re-signs it.
///
/// The ratio to [`SNAPSHOT_VALIDITY`] is the margin that keeps a *live*
/// passport from expiring, and it is the number that matters here: at 24 hours
/// against seven days, six consecutive refresh cycles can fail — a lost weekend
/// of database trouble, a signing outage, an object store rejecting writes —
/// before any published passport's snapshot lapses. Set the two close together
/// and an ordinary incident silently ends continuity for the whole corpus,
/// which is the failure this tier exists to prevent, arriving by the door meant
/// to prevent it.
///
/// It is also the ceiling on refresh cost: one render, one signature and one
/// object-store write per published passport per day.
pub const SNAPSHOT_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 3600);

/// How often the refresh pass looks for snapshots due to be re-signed.
///
/// Distinct from [`SNAPSHOT_REFRESH_INTERVAL`], which is *when a snapshot is
/// stale*; this is how often we go looking. Scanning more often than a
/// snapshot's staleness threshold is what spreads a day's renewals across the
/// day instead of stacking them into one burst — and, with a per-scan cap, is
/// what sets how large a corpus the tier can keep renewed at all.
pub const SNAPSHOT_REFRESH_SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(900);
