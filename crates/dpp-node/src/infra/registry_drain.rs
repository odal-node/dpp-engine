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
    RegistrationRequest, RegistrySyncPort, SubmissionAcknowledgement, SubmissionLookup,
    SubmissionReport,
};
use dpp_types::{RegistrySyncOutbox, RegistrySyncStatus};

/// What a row's message says to do once a person has found the submission's
/// correlation identifier by other means. The registry's own interface lists each
/// submission with one.
const RECONCILE_BY_HAND: &str = "Once the right correlation identifier is known, record it with \
     `odal registry handle <passport-id> <correlation-id>` \
     (POST /vault/api/v1/dpp/{dppId}/registry/handle).";

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
    /// Rows whose correlation identifier was lost and has been found again, by
    /// the unique product identifier the passport was submitted under.
    pub recovered: u32,
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
                // it never received. So the handle is looked for: the registry
                // lists each passport it was given by the unique product
                // identifier it was submitted under, and the frozen payload holds
                // ours.
                recover_handle(outbox, registry_sync, pid, row.payload, &mut stats).await;
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
        let outcome = registry_sync.register(req.clone()).await;
        metrics::histogram!("registry_outbox_drain_seconds")
            .record(started.elapsed().as_secs_f64());
        apply_acknowledgement(outbox, registry_sync, pid, &req, outcome, &mut stats).await;
    }
    stats
}

/// Record what the registry said when the row was submitted.
///
/// An acknowledgement is never a registration: the registry accepted the
/// submission for checking and gave it a handle, and the ruling comes later.
async fn apply_acknowledgement(
    outbox: &Arc<dyn RegistrySyncOutbox>,
    registry_sync: &Arc<dyn RegistrySyncPort>,
    pid: dpp_domain::passport::PassportId,
    request: &RegistrationRequest,
    outcome: Result<SubmissionAcknowledgement, dpp_domain::DppError>,
    stats: &mut DrainStats,
) {
    match outcome {
        Ok(SubmissionAcknowledgement::Accepted { correlation_id }) => {
            // The registry has the submission and this is the only place its
            // handle exists. If it cannot be written down the next pass sends the
            // submission again under the same key, which is answered as already
            // held, and the handle is found again by the identifier: so the
            // failure is loud, and it names the handle for a person who needs it.
            if let Err(e) = outbox.mark_submitted(pid, correlation_id.clone()).await {
                tracing::error!(
                    passport_id = %pid,
                    correlation_id = %correlation_id,
                    error = %e,
                    "the registry accepted the submission and this node could not record its \
                     correlation identifier — it will be recovered by the passport's unique \
                     product identifier"
                );
            }
            stats.submitted += 1;
        }
        // The registry already had the submission, and a replayed key does not say
        // under which handle. Moving the row to `submitted` is what stops the
        // drain posting it again; an empty handle tells the outbox to keep
        // whatever the row held and never to record `''`. Then the handle is
        // looked for straight away, rather than a pass later.
        Ok(SubmissionAcknowledgement::AlreadyHeld) => {
            let _ = outbox.mark_submitted(pid, String::new()).await;
            recover_with_request(outbox, registry_sync, pid, request, stats).await;
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
        // `submitted` and a later pass asks again — backed off like the
        // acknowledgement was, with the attempt counted, so a poll that never
        // gets a ruling neither runs hot nor escapes the stalled count.
        Ok(SubmissionReport::Unrecognised { state }) => {
            tracing::warn!(
                passport_id = %pid,
                state = %state,
                "registry reported a submission state this node has no name for — polling on"
            );
            let _ = outbox
                .mark_submitted_noting(
                    pid,
                    format!("the registry reported a submission state this node has no name for: {state}"),
                )
                .await;
            stats.submitted += 1;
        }
        // Still being checked: the expected answer to a fresh submission, not an
        // edge case. Anything the report type grows later is read the same way,
        // as not yet ruled on, and backed off the same way.
        Ok(_) => {
            let _ = outbox.mark_submitted(pid, String::new()).await;
            stats.submitted += 1;
        }
        Err(e) => {
            // Transient/unreachable — back off and retry. The row stays.
            let _ = outbox.mark_attempt_failed(pid, e.to_string()).await;
            stats.retried += 1;
        }
    }
}

/// Look for the handle of a `submitted` row that has none, from its frozen
/// payload.
///
/// A payload that is missing or unreadable cannot say what was submitted, so
/// there is nothing to look for: that is reported and backed off, never guessed
/// at.
async fn recover_handle(
    outbox: &Arc<dyn RegistrySyncOutbox>,
    registry_sync: &Arc<dyn RegistrySyncPort>,
    pid: dpp_domain::passport::PassportId,
    payload: Option<serde_json::Value>,
    stats: &mut DrainStats,
) {
    let request = payload.map(serde_json::from_value::<RegistrationRequest>);
    match request {
        Some(Ok(request)) => {
            recover_with_request(outbox, registry_sync, pid, &request, stats).await;
        }
        Some(Err(_)) | None => {
            tracing::warn!(
                passport_id = %pid,
                "registry holds this submission under a correlation identifier this node does \
                 not have, and the row's payload cannot say what was submitted — it needs \
                 reconciling by hand"
            );
            let _ = outbox
                .mark_submitted_noting(
                    pid,
                    format!(
                        "the registry holds this submission under a correlation identifier this \
                         node does not have, and the row's payload cannot say what was submitted, \
                         so it cannot be looked for. {RECONCILE_BY_HAND}"
                    ),
                )
                .await;
            stats.submitted += 1;
        }
    }
}

/// Look for a submission whose handle was lost, and settle the row by what is
/// found.
///
/// [`SubmissionLookup::Found`] gives the handle and the ruling together: the
/// handle is recorded first, so it survives whatever happens to the ruling's
/// write, and a ruling is then applied as a poll's would be. Everything else
/// leaves the row `submitted`, backed off and counted as an attempt, so it stops
/// sorting to the head of the queue and reaches the stalled count that tells an
/// operator it needs a person.
async fn recover_with_request(
    outbox: &Arc<dyn RegistrySyncOutbox>,
    registry_sync: &Arc<dyn RegistrySyncPort>,
    pid: dpp_domain::passport::PassportId,
    request: &RegistrationRequest,
    stats: &mut DrainStats,
) {
    let started = std::time::Instant::now();
    let lookup = registry_sync.find_submission(request).await;
    metrics::histogram!("registry_outbox_drain_seconds").record(started.elapsed().as_secs_f64());

    match lookup {
        Ok(SubmissionLookup::Found {
            correlation_id,
            report,
        }) => {
            tracing::info!(
                passport_id = %pid,
                correlation_id = %correlation_id,
                "recovered the correlation identifier of a submission the registry held"
            );
            metrics::counter!("registry_outbox_recovered_total").increment(1);
            stats.recovered += 1;
            let _ = outbox.mark_submitted(pid, correlation_id).await;
            if report.is_terminal() {
                apply_report(outbox, pid, Ok(report), stats).await;
            } else {
                stats.submitted += 1;
            }
        }
        // More than one submission reports this passport's identifier, and
        // choosing would give it another passport's registration.
        Ok(SubmissionLookup::Ambiguous { candidates }) => {
            tracing::warn!(
                passport_id = %pid,
                candidates = ?candidates,
                "more than one registry submission reports this passport's unique product \
                 identifier — the handle was not chosen and needs reconciling by hand"
            );
            let _ = outbox
                .mark_submitted_noting(
                    pid,
                    format!(
                        "more than one registry submission reports this passport's unique \
                         product identifier, so the correlation identifier was not chosen. \
                         Candidates: {}. {RECONCILE_BY_HAND}",
                        candidates.join(", ")
                    ),
                )
                .await;
            stats.submitted += 1;
        }
        Ok(SubmissionLookup::NotFound { exhaustive }) => {
            tracing::warn!(
                passport_id = %pid,
                exhaustive,
                "the registry holds this submission and its correlation identifier was not \
                 found among the tasks read — looking again later"
            );
            let read = if exhaustive {
                "every task the registry listed was read"
            } else {
                "only part of the registry's task list was read, or a task is still being \
                 checked, so absence proves nothing"
            };
            let _ = outbox
                .mark_submitted_noting(
                    pid,
                    format!(
                        "the registry holds this submission and its correlation identifier was \
                         not found among its tasks ({read}). Looking again later. \
                         {RECONCILE_BY_HAND}"
                    ),
                )
                .await;
            stats.submitted += 1;
        }
        // An adapter that cannot look a submission up, and anything the lookup
        // grows later: nothing was found, and nothing is guessed.
        Ok(_) => {
            tracing::warn!(
                passport_id = %pid,
                "this registry adapter cannot look a submission up without its handle — it \
                 needs reconciling by hand"
            );
            let _ = outbox
                .mark_submitted_noting(
                    pid,
                    format!(
                        "this registry adapter cannot look a submission up without its \
                         correlation identifier. {RECONCILE_BY_HAND}"
                    ),
                )
                .await;
            stats.submitted += 1;
        }
        Err(e) => {
            // Transient/unreachable — back off and retry. The row stays.
            let _ = outbox.mark_attempt_failed(pid, e.to_string()).await;
            stats.retried += 1;
        }
    }
}
