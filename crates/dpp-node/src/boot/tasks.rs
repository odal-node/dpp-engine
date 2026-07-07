//! Background task spawns: expired-import-job cleanup and the registry-sync
//! outbox drain (including its boot-time reconciliation log/gauges).

use std::sync::Arc;

use dpp_domain::ports::registry_sync::RegistrySyncPort;
use dpp_integrator::infra::job_store::JobStore;
use dpp_types::registry_sync::RegistrySyncOutbox;

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

const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
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
