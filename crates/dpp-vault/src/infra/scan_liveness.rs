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

use chrono::{DateTime, Utc};

/// Last time a resolver flushed scan telemetry to this process.
static LAST_INGEST: RwLock<Option<DateTime<Utc>>> = RwLock::new(None);

/// Record that a resolver just flushed. Called by the internal ingest route,
/// including for an empty batch — the heartbeat is the point.
pub fn record_ingest() {
    if let Ok(mut slot) = LAST_INGEST.write() {
        *slot = Some(Utc::now());
    }
}

/// When a resolver last flushed, if one ever has since this process started.
#[must_use]
pub fn last_ingest() -> Option<DateTime<Utc>> {
    LAST_INGEST.read().ok().and_then(|slot| *slot)
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
        record_ingest();
        assert!(
            last_ingest().is_some(),
            "a flush must be observable once recorded"
        );
    }
}
