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
