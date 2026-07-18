//! Background task spawns: expired-import-job cleanup and the registry-sync
//! outbox drain (including its boot-time reconciliation log/gauges).

use std::sync::Arc;

use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::ports::registry_sync::RegistrySyncPort;
use dpp_integrator::infra::job_store::JobStore;
use dpp_types::registry_sync::RegistrySyncOutbox;
use dpp_types::snapshot::{SnapshotOutbox, SnapshotStore};
use dpp_types::webhook::WebhookOutbox;

/// Spawn the periodic cleanup of expired import jobs (every 6 hours).
pub fn spawn_job_cleanup(store: Arc<dyn JobStore>) {
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(6 * 3600);
        let max_age = chrono::Duration::days(30);
        loop {
            tokio::time::sleep(interval).await;
            tracing::debug!("running import job cleanup");
            store.cleanup(max_age).await;
        }
    });
}

use dpp_node::infra::drain::DRAIN_INTERVAL;

const DRAIN_BATCH: i64 = 50;
const STALL_THRESHOLD: i32 = 8;

/// Log/gauge the outbox's outstanding state, then spawn the periodic drain
/// loop (ESPR Art. 13). Publish enqueues each registration transactionally
/// with the passport write; this task drains due rows against the registry
/// port with backoff. A killed node loses nothing — rows persist and are
/// retried here on restart.
pub async fn spawn_registry_drain(
    outbox: Arc<dyn RegistrySyncOutbox>,
    registry_sync: Arc<dyn RegistrySyncPort>,
) {
    // Boot reconciliation: log outstanding registry-sync state so a restart
    // surfaces (never hides) queued/rejected/stalled registrations.
    match outbox.status_counts(STALL_THRESHOLD).await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                registered = c.registered,
                rejected = c.rejected,
                status_intents = c.status_intents,
                stalled = c.stalled,
                "registry outbox reconciliation at boot"
            );
            metrics::gauge!("registry_outbox_pending").set(c.pending as f64);
            metrics::gauge!("registry_outbox_stalled").set(c.stalled as f64);
            metrics::gauge!("registry_outbox_rejected").set(c.rejected as f64);
        }
        Err(e) => tracing::warn!(error = %e, "registry outbox boot reconciliation failed"),
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::registry_drain::drain_once(&outbox, &registry_sync, DRAIN_BATCH).await;
            if let Ok(c) = outbox.status_counts(STALL_THRESHOLD).await {
                metrics::gauge!("registry_outbox_pending").set(c.pending as f64);
                metrics::gauge!("registry_outbox_stalled").set(c.stalled as f64);
                metrics::gauge!("registry_outbox_rejected").set(c.rejected as f64);
                if c.stalled > 0 {
                    tracing::warn!(
                        stalled = c.stalled,
                        "registry outbox has stalled rows — manual investigation required"
                    );
                }
            }
        }
    });
}

/// Log/gauge the webhook delivery outbox's outstanding state, then spawn the
/// periodic drain loop. Each emitted event fans out to matching subscriptions
/// (after-commit, in the vault service); this task performs the signed HTTP POST
/// with backoff. A killed node loses nothing — `pending` rows redeliver on boot.
pub async fn spawn_webhook_drain(outbox: Arc<dyn WebhookOutbox>, allow_private_targets: bool) {
    match outbox.status_counts().await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                delivered = c.delivered,
                exhausted = c.exhausted,
                "webhook outbox reconciliation at boot"
            );
            metrics::gauge!("webhook_outbox_pending").set(c.pending as f64);
            metrics::gauge!("webhook_outbox_exhausted").set(c.exhausted as f64);
        }
        Err(e) => tracing::warn!(error = %e, "webhook outbox boot reconciliation failed"),
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::webhook_drain::drain_once(
                &outbox,
                &client,
                DRAIN_BATCH,
                allow_private_targets,
            )
            .await;
            if let Ok(c) = outbox.status_counts().await {
                metrics::gauge!("webhook_outbox_pending").set(c.pending as f64);
                metrics::gauge!("webhook_outbox_exhausted").set(c.exhausted as f64);
                if c.exhausted > 0 {
                    tracing::warn!(
                        exhausted = c.exhausted,
                        "webhook outbox has exhausted deliveries — check receiver health"
                    );
                }
            }
        }
    });
}

/// Log/gauge the continuity-snapshot outbox's outstanding state, then spawn the
/// periodic reconcile loop. Every change to a passport's public state enqueues a
/// row (after-commit, in the vault service); this task re-reads each passport and
/// makes object storage match — mirroring the public view for `Published`,
/// retiring it otherwise. A killed node loses nothing: `pending` rows reconcile
/// on boot.
///
/// [`DRAIN_INTERVAL`] bounds the suspend lag — see its docs before changing it.
pub async fn spawn_snapshot_drain(
    outbox: Arc<dyn SnapshotOutbox>,
    repo: Arc<dyn PassportRepository>,
    store: Arc<dyn SnapshotStore>,
) {
    match outbox.status_counts().await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                reconciled = c.reconciled,
                exhausted = c.exhausted,
                "continuity snapshot outbox reconciliation at boot"
            );
            metrics::gauge!("snapshot_outbox_pending").set(c.pending as f64);
            metrics::gauge!("snapshot_outbox_exhausted").set(c.exhausted as f64);
        }
        Err(e) => tracing::warn!(error = %e, "snapshot outbox boot reconciliation failed"),
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::snapshot_drain::drain_once(&outbox, &repo, &store, DRAIN_BATCH).await;
            if let Ok(c) = outbox.status_counts().await {
                metrics::gauge!("snapshot_outbox_pending").set(c.pending as f64);
                metrics::gauge!("snapshot_outbox_exhausted").set(c.exhausted as f64);
                if c.exhausted > 0 {
                    // Exhausted here means the static tier may still be serving a
                    // stale public view — a correctness signal, not just noise.
                    tracing::warn!(
                        exhausted = c.exhausted,
                        "snapshot outbox has exhausted reconciles — the static tier may be stale"
                    );
                }
            }
        }
    });
}
