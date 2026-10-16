//! One drain pass over the registry-sync outbox.
//!
//! Fetches due rows and moves each one along the registry's two steps through
//! the `RegistrySyncPort`: a pending row is submitted and, once the registry has
//! accepted it, polled by the correlation identifier it was given until the
//! registry rules on it. The ruling is recorded as the terminal
//! (`registered`/`rejected`) outcome, and a transient failure as a backoff, on the
//! row. Extracted from the node's background loop so the drain semantics are
//! unit-testable with a mock port — the loop in `main` just calls this on a
//! timer and refreshes the gauges.
//!
//! # What the row's `registry_id` holds
//!
//! One column holds the registry's handle on the row, and which handle depends
//! on the step. While the row is `submitted` it is the **correlation
//! identifier** the registry gave the submission, which is what is polled.
//! Once the row is `registered` it is the **registration identifier** the
//! registry generated (IR (EU) 2026/1778 Art. 8(8)), which every later call
//! about the record names it by. The two are different identifiers of different
//! things, and the status says which one the column holds: a reader must check
//! the status before using it.

use std::sync::Arc;

use dpp_domain::ports::registry_sync::{
    RegistrationRequest, RegistrySyncPort, SubmissionAcknowledgement, SubmissionReport,
};
use dpp_types::{RegistrySyncOutbox, RegistrySyncStatus};

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Rows that reached terminal `registered`.
    pub registered: u32,
    /// Rows the registry accepted for validation, verdict still outstanding.
    pub submitted: u32,
    /// Rows the registry terminally `rejected`.
    pub rejected: u32,
    /// Rows that failed transiently and were backed off for retry.
    pub retried: u32,
    /// Rows dropped from draining because their payload was missing/corrupt.
    pub skipped: u32,
}

/// Drain up to `batch` due rows once.
///
/// Never panics and never propagates: a per-row failure is recorded on the row
/// (`mark_*`) and the pass continues, so one bad row cannot stall the queue. A
/// row is only ever removed from the due set by reaching a terminal state or a
/// future `next_attempt_at` — it is never silently dropped.
pub async fn drain_once(
    outbox: &Arc<dyn RegistrySyncOutbox>,
    registry_sync: &Arc<dyn RegistrySyncPort>,
    operator: Option<&Arc<dyn dpp_types::operator::OperatorConfigRepository>>,
    batch: i64,
) -> DrainStats {
    let mut stats = DrainStats::default();

    // Verified-operator status is not permanent: it ends when the eID means
    // used expire, and at the latest three years after verification. An expired
    // operator cannot register anything, so submitting would earn an opaque
    // remote refusal. Hold the whole pass instead — re-verification makes every
    // held row drainable again, and nothing is lost meanwhile.
    if let Some(repo) = operator
        && let Ok(Some(cfg)) = repo.get(dpp_types::STANDALONE_OPERATOR_ID).await
        && !cfg.registry_verification_is_current(chrono::Utc::now())
    {
        tracing::warn!(
            verified_at = ?cfg.registry_verified_at,
            expires_at = ?cfg.registry_verification_expires_at(),
            "registry outbox drain held — operator is not currently verified with the EU \
             registry; re-verify to resume registration"
        );
        metrics::counter!("registry_outbox_held_unverified_total").increment(1);
        return stats;
    }
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "registry outbox drain: query failed");
            return stats;
        }
    };
    for row in due {
        let pid = row.passport_id;

        // Already submitted: the registry has it and is validating. Poll for the
        // verdict by the correlation identifier it gave — resubmitting would
        // register the same product twice.
        if row.status == RegistrySyncStatus::Submitted {
            let Some(correlation_id) = row
                .registry_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
            else {
                // The registry held the submission already (a replayed
                // idempotency key) and did not say under which handle. There is
                // nothing to poll, and inventing a handle or falling back to this
                // node's own passport id would ask the registry about something
                // it never received. The row stays `submitted` until its
                // correlation identifier is recovered from the registry's own
                // record of the operator's requests.
                tracing::warn!(
                    passport_id = %pid,
                    "registry holds this submission under a correlation identifier this node \
                     does not have — it cannot be polled and needs reconciling"
                );
                stats.submitted += 1;
                continue;
            };
            let started = std::time::Instant::now();
            let outcome = registry_sync.check_submission(correlation_id).await;
            metrics::histogram!("registry_outbox_drain_seconds")
                .record(started.elapsed().as_secs_f64());
            apply_report(outbox, pid, outcome, &mut stats).await;
            continue;
        }

        let Some(payload) = row.payload else {
            // A pending row with no payload can never be registered — mark it
            // rejected so it stops draining and a human notices.
            let _ = outbox
                .mark_rejected(pid, "missing registration payload".into())
                .await;
            stats.skipped += 1;
            continue;
        };
        let req: RegistrationRequest = match serde_json::from_value(payload) {
            Ok(r) => r,
            Err(e) => {
                let _ = outbox
                    .mark_rejected(pid, format!("corrupt payload: {e}"))
                    .await;
                stats.skipped += 1;
                continue;
            }
        };
        let started = std::time::Instant::now();
        let outcome = registry_sync.register(req).await;
        metrics::histogram!("registry_outbox_drain_seconds")
            .record(started.elapsed().as_secs_f64());
        apply_acknowledgement(outbox, pid, outcome, &mut stats).await;
    }
    stats
}

/// Record what the registry said when the row was submitted.
///
/// An acknowledgement is never a registration: the registry accepted the
/// submission for checking and gave it a handle, and the ruling comes later.
async fn apply_acknowledgement(
    outbox: &Arc<dyn RegistrySyncOutbox>,
    pid: dpp_domain::passport::PassportId,
    outcome: Result<SubmissionAcknowledgement, dpp_domain::DppError>,
    stats: &mut DrainStats,
) {
    match outcome {
        Ok(SubmissionAcknowledgement::Accepted { correlation_id }) => {
            let _ = outbox.mark_submitted(pid, correlation_id).await;
            stats.submitted += 1;
        }
        // The registry already had the submission. An empty handle tells the
        // outbox to keep whatever the row held and never to record `''`.
        Ok(SubmissionAcknowledgement::AlreadyHeld) => {
            let _ = outbox.mark_submitted(pid, String::new()).await;
            stats.submitted += 1;
        }
        // An answer this node has no name for is not an acceptance: record it as
        // a failed attempt, so the retry carries the same idempotency key and the
        // registry says what it holds.
        Ok(other) => {
            let _ = outbox
                .mark_attempt_failed(pid, format!("unrecognised acknowledgement: {other:?}"))
                .await;
            stats.retried += 1;
        }
        Err(e) => {
            // Transient/unreachable — back off and retry. The row stays.
            let _ = outbox.mark_attempt_failed(pid, e.to_string()).await;
            stats.retried += 1;
        }
    }
}

/// Record what the registry reported about a submission it accepted earlier.
async fn apply_report(
    outbox: &Arc<dyn RegistrySyncOutbox>,
    pid: dpp_domain::passport::PassportId,
    outcome: Result<SubmissionReport, dpp_domain::DppError>,
    stats: &mut DrainStats,
) {
    match outcome {
        Ok(SubmissionReport::Registered { registration_id }) => {
            let _ = outbox.mark_registered(pid, registration_id).await;
            stats.registered += 1;
        }
        Ok(SubmissionReport::Refused { reason }) => {
            tracing::warn!(passport_id = %pid, reason = %reason, "registry rejected registration");
            metrics::counter!("registry_outbox_rejected_total").increment(1);
            let _ = outbox.mark_rejected(pid, reason).await;
            stats.rejected += 1;
        }
        // A state this node has no name for is not a verdict. Reading it as a
        // refusal would discard a submission that may have succeeded, and as a
        // registration would record one that may not exist, so the row stays
        // `submitted` and the next pass asks again.
        Ok(SubmissionReport::Unrecognised { state }) => {
            tracing::warn!(
                passport_id = %pid,
                state = %state,
                "registry reported a submission state this node has no name for — polling on"
            );
            stats.submitted += 1;
        }
        // Still being checked: the expected answer to a fresh submission, not an
        // edge case. Anything the report type grows later is read the same way,
        // as not yet ruled on.
        Ok(_) => stats.submitted += 1,
        Err(e) => {
            // Transient/unreachable — back off and retry. The row stays.
            let _ = outbox.mark_attempt_failed(pid, e.to_string()).await;
            stats.retried += 1;
        }
    }
}
