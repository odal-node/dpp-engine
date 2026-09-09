//! One drain pass over the continuity-snapshot reconcile outbox.
//!
//! Fetches due rows and makes the static tier match the database for each
//! passport: `Published` passports get their public view mirrored to object
//! storage under a freshly signed time bound, everything else gets its snapshot
//! retired. Extracted from the node's background loop so the convergence
//! semantics are unit-testable with in-memory doubles — the loop in `main` just
//! calls this on a timer.
//!
//! Structurally mirrors `webhook_drain`/`registry_drain`: never panics, never
//! propagates — a per-row failure is recorded (`mark_*`) and the pass continues,
//! so one bad row cannot stall the queue.
//!
//! The bound makes signing part of the store path, so a signing outage now stops
//! snapshots being written. That is the intended direction of failure: the
//! copies already out there run down their remaining validity and lapse, rather
//! than being extended by a node that cannot currently prove anything.
//!
//! # Why the row carries no action
//!
//! A reconcile row names a passport, not an operation. The action is derived
//! *here*, from the passport's status at drain time. That is what makes the
//! queue convergent: a retried or out-of-order row can never apply a stale
//! decision, so a `put` queued at publish cannot land after a `remove` queued at
//! suspend and resurrect a suspended passport in the public tier. The cost is
//! one extra read per row; the benefit is that duplicates, replays after a
//! crash, and reordering are all no-ops.

use std::sync::Arc;

use chrono::SubsecRound as _;
use dpp_domain::{ports::identity::IdentityPort, ports::passport_repo::PassportRepository};
use dpp_types::SnapshotOutbox;
use dpp_types::snapshot::{SnapshotMeta, SnapshotStore};

use super::drain::{SNAPSHOT_REFRESH_INTERVAL, SNAPSHOT_VALIDITY};

/// Max reconcile attempts before a row is terminally `exhausted`.
pub const MAX_ATTEMPTS: i32 = 8;

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Passports whose public view was mirrored to the static tier.
    pub stored: u32,
    /// Passports whose snapshot was retired (left the public tier, or is gone).
    pub removed: u32,
    /// Rows that failed transiently and were backed off for retry.
    pub retried: u32,
    /// Rows that reached terminal `exhausted` — the static tier may be stale.
    pub exhausted: u32,
}

/// Record a transient failure: back off and retry, unless the attempt cap is
/// reached in which case the row is terminally `exhausted`.
async fn back_off_or_exhaust(
    outbox: &Arc<dyn SnapshotOutbox>,
    id: uuid::Uuid,
    attempts: i32,
    reason: String,
    stats: &mut DrainStats,
) {
    if attempts + 1 >= MAX_ATTEMPTS {
        let _ = outbox
            .mark_exhausted(id, format!("max attempts reached: {reason}"))
            .await;
        metrics::counter!("snapshot_reconcile_total", "outcome" => "exhausted").increment(1);
        stats.exhausted += 1;
    } else {
        let _ = outbox.mark_attempt_failed(id, reason).await;
        metrics::counter!("snapshot_reconcile_total", "outcome" => "retried").increment(1);
        stats.retried += 1;
    }
}

/// Drain up to `batch` due reconcile rows once.
pub async fn drain_once(
    outbox: &Arc<dyn SnapshotOutbox>,
    repo: &Arc<dyn PassportRepository>,
    store: &Arc<dyn SnapshotStore>,
    identity: &Arc<dyn IdentityPort>,
    resolver_base_url: &str,
    batch: i64,
) -> DrainStats {
    let mut stats = DrainStats::default();
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "snapshot outbox drain: query failed");
            return stats;
        }
    };

    for row in due {
        let dpp_id = row.passport_id.to_string();

        // Read the passport's *current* state — this is where put-or-remove is
        // decided, and why a replayed row cannot apply a stale action.
        let passport = match repo.find_by_id_any_status(row.passport_id).await {
            Ok(p) => p,
            Err(e) => {
                back_off_or_exhaust(
                    outbox,
                    row.id,
                    row.attempts,
                    format!("passport lookup failed: {e}"),
                    &mut stats,
                )
                .await;
                continue;
            }
        };

        // Whether a passport belongs in the public tier is one question with one
        // answer: `dpp_vault::public_view::serves_publicly`, the same rule the
        // live public read applies.
        //
        // It used to be `== Published` here and a separate list of statuses
        // there, and the two had already diverged — a deactivated passport was
        // served live while the snapshot of it was removed, so the continuity
        // tier answered `404` for a record the node itself was serving. That
        // tier exists to stand in for the node when the node is down, which
        // makes a disagreement between them invisible until precisely the moment
        // it matters.
        //
        // Both branches are idempotent.
        let started = std::time::Instant::now();
        let outcome = match &passport {
            Some(p) if dpp_vault::public_view::serves_publicly(&p.status) => {
                store_published(store, identity, &dpp_id, p, resolver_base_url)
                    .await
                    .map(|()| Action::Stored)
            }
            _ => store.remove(&dpp_id).await.map(|()| Action::Removed),
        };
        metrics::histogram!("snapshot_reconcile_seconds").record(started.elapsed().as_secs_f64());

        match outcome {
            Ok(action) => {
                let _ = outbox.mark_reconciled(row.id).await;
                match action {
                    Action::Stored => {
                        metrics::counter!("snapshot_reconcile_total", "outcome" => "stored")
                            .increment(1);
                        stats.stored += 1;
                    }
                    Action::Removed => {
                        metrics::counter!("snapshot_reconcile_total", "outcome" => "removed")
                            .increment(1);
                        stats.removed += 1;
                    }
                }
            }
            Err(e) => {
                back_off_or_exhaust(outbox, row.id, row.attempts, e.to_string(), &mut stats).await;
            }
        }
    }
    stats
}

/// Mirror a published passport into the static tier in both representations.
///
/// The signed JSON is written **first** and the page second, deliberately: if
/// the pair is ever left half-written, the survivor should be the artifact a
/// verifier can check rather than a page a consumer would read and believe. The
/// retire path in the store reverses the order for the same reason.
///
/// Both go through the renderers the live surfaces use — `public_view` for the
/// JSON, `dpp_render` for the page — because a second implementation of either
/// is precisely how the static tier would drift from what the node serves.
///
/// One `as_of` is taken here and used for the JSON, the page and the object
/// metadata. Reading the clock once per representation would let a copy state
/// three slightly different ages for one snapshot — small, and exactly the kind
/// of discrepancy that reads as tampering to someone comparing them.
async fn store_published(
    store: &Arc<dyn SnapshotStore>,
    identity: &Arc<dyn IdentityPort>,
    dpp_id: &str,
    passport: &dpp_domain::passport::Passport,
    resolver_base_url: &str,
) -> Result<(), dpp_domain::DppError> {
    // Truncated to the second at the source. The payload states its timestamps
    // in RFC 3339 seconds, so keeping sub-second precision on the copy handed
    // to the object metadata would have the header and the signed claim
    // disagree about the same instant — a discrepancy that reads as tampering
    // to whoever compares them, for no gain.
    let as_of = chrono::Utc::now().trunc_subsecs(0);
    let valid_until = as_of
        + chrono::Duration::from_std(SNAPSHOT_VALIDITY)
            .expect("SNAPSHOT_VALIDITY is a small constant");
    let meta = SnapshotMeta {
        as_of,
        valid_until,
        max_age: SNAPSHOT_REFRESH_INTERVAL,
    };

    let json = dpp_vault::public_view::render_public_snapshot(
        identity.as_ref(),
        passport,
        as_of,
        valid_until,
    )
    .await?;
    store.put_public_json(dpp_id, &json, meta).await?;

    // Render the page from the same public view the JSON carries, never from
    // the full passport — the static tier must not become a confidential-data
    // leak just because it renders HTML.
    let view: serde_json::Value = serde_json::from_slice(&json)
        .map_err(|e| dpp_domain::DppError::Serialisation(e.to_string()))?;
    let html = dpp_render::render_page(
        dpp_id,
        &view,
        resolver_base_url,
        dpp_render::SnapshotNotice::Snapshot { as_of, valid_until },
    );
    store.put_public_html(dpp_id, html.as_bytes(), meta).await
}

/// Which way a reconcile resolved, so the tally can distinguish the two.
enum Action {
    Stored,
    Removed,
}
