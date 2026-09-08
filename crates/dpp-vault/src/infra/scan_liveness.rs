//! Whether scan telemetry is actually reaching this node.
//!
//! # The question this answers
//!
//! `GET /api/v1/stats` reported `totalScans: 0` in two completely different
//! situations: nobody scanned anything, and nothing is counting. An operator
//! could not tell a real zero from an unmeasured one, and the second is the
//! shipped default — `SCAN_INGEST_URL` is commented out of `.env.example` and
//! absent from the compose file.
//!
//! The node cannot resolve that from configuration, and this is the part worth
//! being precise about: `SCAN_INGEST_URL` belongs to the **resolver**, a
//! separate deployable with its own environment. Reading config here would only
//! ever produce a guess about another process.
//!
//! So the node reports what it can observe — whether a resolver has flushed to
//! it — and the resolver now sends an empty batch each interval so that
//! observation exists even with nothing to count.
//!
//! # Ever-flushed is not the question
//!
//! "A resolver reached me once" and "a resolver is reaching me now" are
//! different claims, and only the second is useful in front of a suspicious
//! zero: a resolver that died an hour ago satisfies the first for the whole
//! remaining life of the process.
//!
//! Answering the second needs the sender's cadence, and that is the piece the
//! node structurally cannot have — `SCAN_FLUSH_INTERVAL_SECS` is the resolver's
//! environment. Rather than assume the default here, which would be the same
//! guess-about-another-process this module was written to avoid, the resolver
//! **declares** its interval in every batch and this compares against that.
//! See `ScanBatch::flush_interval_secs`.
//!
//! # Why a process-wide marker rather than a field on `AppState`
//!
//! The node is strictly single-tenant: one process, one operator, no in-process
//! scoping (see `CLAUDE.md`). "When did a resolver last flush to *this
//! process*" is therefore genuinely process-scoped — it is not per-request, not
//! per-operator, and not per-connection. Threading it through `AppState` would
//! have meant editing twenty-six construction sites to carry a diagnostic that
//! belongs to none of them.
//!
//! # Why in memory
//!
//! This is liveness, not history. It resets on restart, so a node that has just
//! booted reports `ingesting: false` until the next flush arrives — at most one
//! flush interval. That is the honest answer for a liveness signal: a node that
//! has not yet heard from a resolver does not know that one is there.

use std::sync::RwLock;

use chrono::{DateTime, Duration, Utc};

/// How many flush intervals may pass before telemetry is called stale.
///
/// It must be at least two. A heartbeat is deliberately **at-most-once** — the
/// resolver never re-sends a failed one, because holding an empty batch would
/// starve its counter — so a single missed heartbeat is designed behaviour, not
/// an anomaly, and a threshold of one interval would flap on exactly the case
/// the design accepts. Three tolerates two consecutive misses and still reports
/// a genuinely dead resolver within 15 minutes at the default 300s cadence.
const STALE_AFTER_INTERVALS: i64 = 3;

/// What the last flush told us: when it arrived, and how often the sender said
/// it would call again.
#[derive(Clone, Copy)]
struct LastIngest {
    at: DateTime<Utc>,
    /// The sender's declared cadence. `None` from a resolver predating the
    /// field, which leaves staleness uncomputable rather than guessed.
    interval_secs: Option<u64>,
}

/// The last flush a resolver made to this process, if any.
static LAST_INGEST: RwLock<Option<LastIngest>> = RwLock::new(None);

/// Record that a resolver just flushed, and what cadence it declared.
///
/// Called by the internal ingest route, including for an empty batch — the
/// heartbeat is the point.
pub fn record_ingest(interval_secs: Option<u64>) {
    if let Ok(mut slot) = LAST_INGEST.write() {
        *slot = Some(LastIngest {
            at: Utc::now(),
            interval_secs,
        });
    }
}

/// When a resolver last flushed, if one ever has since this process started.
#[must_use]
pub fn last_ingest() -> Option<DateTime<Utc>> {
    LAST_INGEST.read().ok().and_then(|slot| slot.map(|l| l.at))
}

/// Whether telemetry is arriving **now**, not merely whether it once did.
///
/// This is the question an operator is actually asking when they read a zero,
/// and answering it needs two facts: when the last flush arrived, and how often
/// the sender promised to call. The node has the first and cannot know the
/// second — `SCAN_FLUSH_INTERVAL_SECS` is the resolver's environment — so the
/// resolver declares it in the batch and this compares against the sender's own
/// promise rather than a constant invented here.
///
/// Degrades honestly in the one case it cannot answer. A resolver predating the
/// declaration sends no interval, and this then reports whether a flush was ever
/// seen — the older, weaker signal — rather than applying a made-up threshold to
/// a cadence it does not know. `last_ingest` is on the wire either way, so a
/// caller who knows their own deployment can always judge for themselves.
#[must_use]
pub fn is_ingesting() -> bool {
    LAST_INGEST
        .read()
        .ok()
        .and_then(|slot| *slot)
        .is_some_and(|last| is_fresh(last, Utc::now()))
}

/// The decision itself, with `now` supplied.
///
/// Split out so the rule can be tested against constructed timestamps. Driving
/// it through the process-wide marker and the wall clock would make the stale
/// case untestable without sleeping for minutes, and the freshness rule is the
/// whole substance of this module.
fn is_fresh(last: LastIngest, now: DateTime<Utc>) -> bool {
    let Some(interval) = last.interval_secs else {
        // Cadence undeclared: staleness is not knowable, so report the older,
        // weaker fact rather than inventing a window.
        return true;
    };
    let Ok(interval) = i64::try_from(interval) else {
        // A cadence that does not fit in an i64 is not a cadence. Treat the
        // sender as undeclared rather than as permanently stale.
        return true;
    };
    now - last.at < Duration::seconds(interval.saturating_mul(STALE_AFTER_INTERVALS))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing is claimed before a flush arrives — the whole point is that
    /// silence is reported as silence rather than as a measured zero.
    #[test]
    fn a_flush_is_what_makes_the_answer_true() {
        // Order-independent: this asserts the transition, not the initial value,
        // because the marker is process-wide and another test may have set it.
        record_ingest(Some(300));
        assert!(
            last_ingest().is_some(),
            "a flush must be observable once recorded"
        );
        assert!(
            is_ingesting(),
            "a flush that just arrived is not stale under any cadence"
        );
    }

    fn ingest(secs_ago: i64, interval_secs: Option<u64>) -> (LastIngest, DateTime<Utc>) {
        let now = Utc::now();
        (
            LastIngest {
                at: now - Duration::seconds(secs_ago),
                interval_secs,
            },
            now,
        )
    }

    /// The flag must mean "arriving", not "once arrived".
    ///
    /// A resolver that died an hour ago satisfies "has ever flushed" for the
    /// whole remaining life of the node process, which is precisely the reading
    /// an operator staring at a zero must not be given.
    #[test]
    fn a_resolver_that_stopped_reporting_is_not_ingesting() {
        let (last, now) = ingest(3_600, Some(300));
        assert!(
            !is_fresh(last, now),
            "an hour of silence on a 5-minute cadence is not 'ingesting'"
        );
    }

    /// A dropped heartbeat must not flip the flag.
    ///
    /// The resolver never re-sends a failed heartbeat — holding an empty batch
    /// would starve its counter — so a single miss is designed behaviour. A
    /// threshold that did not tolerate it would flap on the normal case.
    #[test]
    fn one_missed_heartbeat_is_tolerated() {
        let (last, now) = ingest(310, Some(300));
        assert!(
            is_fresh(last, now),
            "one missed heartbeat is expected, not a fault"
        );

        let (last, now) = ingest(620, Some(300));
        assert!(
            is_fresh(last, now),
            "two consecutive misses still tolerated"
        );

        let (last, now) = ingest(1_000, Some(300));
        assert!(
            !is_fresh(last, now),
            "three intervals of silence is a stopped resolver"
        );
    }

    /// The threshold scales with the sender's declared cadence rather than a
    /// constant, which is the whole reason the interval travels in the batch.
    #[test]
    fn the_window_follows_the_declared_cadence() {
        // 10 minutes of silence: stale for a fast sender, fine for a slow one.
        let (fast, now) = ingest(600, Some(60));
        assert!(!is_fresh(fast, now), "10 min silent on a 1-minute cadence");

        let (slow, now) = ingest(600, Some(3_600));
        assert!(is_fresh(slow, now), "10 min silent on a 1-hour cadence");
    }

    /// An undeclared cadence degrades to the older, weaker signal rather than
    /// to a guessed threshold — a resolver predating the field must not be
    /// reported as dead for not answering a question it was never asked.
    #[test]
    fn an_undeclared_cadence_reports_ever_flushed_rather_than_guessing() {
        let (last, now) = ingest(86_400, None);
        assert!(
            is_fresh(last, now),
            "without a declared cadence there is no window to be outside of"
        );
    }
}
