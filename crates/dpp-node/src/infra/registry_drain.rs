//! One drain pass over the registry-sync outbox.
//!
//! Fetches due rows, registers each against the `RegistrySyncPort`, and records
//! the terminal (`registered`/`rejected`) or transient (backoff) outcome on the
//! row. Extracted from the node's background loop so the drain semantics are
//! unit-testable with a mock port — the loop in `main` just calls this on a
//! timer and refreshes the gauges.

use std::sync::Arc;

use dpp_domain::ports::registry_sync::{RegistrationRequest, RegistryStatus, RegistrySyncPort};
use dpp_types::RegistrySyncOutbox;

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Rows that reached terminal `registered`.
    pub registered: u32,
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
    batch: i64,
) -> DrainStats {
    let mut stats = DrainStats::default();
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "registry outbox drain: query failed");
            return stats;
        }
    };
    for row in due {
        let pid = row.passport_id;
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
        match outcome {
            Ok(rec) if rec.status == RegistryStatus::Rejected => {
                tracing::warn!(passport_id = %pid, "registry rejected registration");
                metrics::counter!("registry_outbox_rejected_total").increment(1);
                let _ = outbox
                    .mark_rejected(pid, "registry rejected registration".into())
                    .await;
                stats.rejected += 1;
            }
            Ok(rec) => {
                let _ = outbox
                    .mark_registered(pid, rec.identifiers.registry_id)
                    .await;
                stats.registered += 1;
            }
            Err(e) => {
                // Transient/unreachable — back off and retry. The row stays.
                let _ = outbox.mark_attempt_failed(pid, e.to_string()).await;
                stats.retried += 1;
            }
        }
    }
    stats
}
