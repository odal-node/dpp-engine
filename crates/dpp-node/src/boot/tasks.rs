//! Background task spawns: expired-import-job cleanup and the registry-sync
//! outbox drain (including its boot-time reconciliation log/gauges).

use std::sync::Arc;

use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::ports::registry_sync::RegistrySyncPort;
use dpp_domain::ports::seal::SealPort;
use dpp_integrator::infra::job_store::JobStore;
use dpp_types::registry_sync::{RegistrySyncCounts, RegistrySyncOutbox};
use dpp_types::registry_transfer::{RegistryTransferCounts, RegistryTransferOutbox};
use dpp_types::scan::ScanTelemetryRepository;
use dpp_types::seal::{SealOutbox, SealOutboxCounts};
use dpp_types::snapshot::{SnapshotOutbox, SnapshotOutboxCounts, SnapshotStore};
use dpp_types::webhook::{WebhookCounts, WebhookOutbox};

/// The scan-telemetry retention horizon: aggregate counters older than this are
/// pruned daily. Rolling 24 months — long enough for year-over-year comparison,
/// bounded so aggregates do not accumulate forever (the time-axis half of the
/// privacy posture, alongside the schema's refusal to model the scanner).
const SCAN_RETENTION_DAYS: i64 = 730;

/// Spawn the periodic scan-telemetry retention prune (every 24 hours).
pub fn spawn_scan_prune(repo: Arc<dyn ScanTelemetryRepository>) {
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(24 * 3600);
        loop {
            tokio::time::sleep(interval).await;
            match repo.prune(SCAN_RETENTION_DAYS).await {
                Ok(c) if c.scans > 0 || c.qr_renders > 0 => tracing::info!(
                    scans = c.scans,
                    qr_renders = c.qr_renders,
                    "scan telemetry retention prune"
                ),
                Ok(_) => tracing::debug!("scan telemetry prune: nothing past horizon"),
                Err(e) => tracing::warn!(error = %e, "scan telemetry prune failed"),
            }
        }
    });
}

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

use dpp_node::infra::drain::{DRAIN_INTERVAL, SWEEP_INTERVAL};

const DRAIN_BATCH: i64 = 50;
/// Per-sweep cap. Larger than `DRAIN_BATCH` because a sweep only enqueues rows
/// (one statement, no object-storage work); the drain still paces the actual
/// reconciles at its own batch size.
const SWEEP_BATCH: i64 = 500;
const STALL_THRESHOLD: i32 = 8;

/// Reflect the registry-sync outbox's counts onto its gauges. Shared by the
/// boot-time reconciliation log and every post-drain re-check so the two
/// can never silently report different gauge names for the same counts.
fn set_registry_gauges(c: &RegistrySyncCounts) {
    metrics::gauge!("registry_outbox_pending").set(c.pending as f64);
    metrics::gauge!("registry_outbox_stalled").set(c.stalled as f64);
    metrics::gauge!("registry_outbox_rejected").set(c.rejected as f64);
}

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
            set_registry_gauges(&c);
        }
        Err(e) => tracing::warn!(error = %e, "registry outbox boot reconciliation failed"),
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::registry_drain::drain_once(&outbox, &registry_sync, DRAIN_BATCH).await;
            if let Ok(c) = outbox.status_counts(STALL_THRESHOLD).await {
                set_registry_gauges(&c);
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

/// Reflect the transfer outbox's counts onto its gauges. Separate names from
/// the registration gauges: a stalled transfer notification and a stalled
/// registration are different problems with different fixes.
fn set_transfer_gauges(c: &RegistryTransferCounts) {
    metrics::gauge!("registry_transfer_outbox_pending").set(c.pending as f64);
    metrics::gauge!("registry_transfer_outbox_stalled").set(c.stalled as f64);
    metrics::gauge!("registry_transfer_outbox_rejected").set(c.rejected as f64);
}

/// Log/gauge the transfer outbox's outstanding state, then spawn its periodic
/// drain loop. Accepting a transfer enqueues the notification transactionally
/// with the chain write; this task drains due rows against the registry port
/// with backoff, so a killed node never loses a handover the registry is owed.
pub async fn spawn_transfer_drain(
    outbox: Arc<dyn RegistryTransferOutbox>,
    registry_sync: Arc<dyn RegistrySyncPort>,
) {
    match outbox.status_counts(STALL_THRESHOLD).await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                notified = c.notified,
                rejected = c.rejected,
                stalled = c.stalled,
                "registry transfer outbox reconciliation at boot"
            );
            set_transfer_gauges(&c);
        }
        Err(e) => {
            tracing::warn!(error = %e, "registry transfer outbox boot reconciliation failed")
        }
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::transfer_drain::drain_once(&outbox, &registry_sync, DRAIN_BATCH).await;
            if let Ok(c) = outbox.status_counts(STALL_THRESHOLD).await {
                set_transfer_gauges(&c);
                if c.stalled > 0 {
                    tracing::warn!(
                        stalled = c.stalled,
                        "registry transfer outbox has stalled rows — manual investigation required"
                    );
                }
            }
        }
    });
}

/// Reflect the webhook outbox's counts onto its gauges. Shared by the
/// boot-time reconciliation log and every post-drain re-check so the two
/// can never silently report different gauge names for the same counts.
fn set_webhook_gauges(c: &WebhookCounts) {
    metrics::gauge!("webhook_outbox_pending").set(c.pending as f64);
    metrics::gauge!("webhook_outbox_exhausted").set(c.exhausted as f64);
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
            set_webhook_gauges(&c);
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
                set_webhook_gauges(&c);
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

/// Reflect the continuity-snapshot outbox's counts onto its gauges. Shared by
/// the boot-time reconciliation log and every post-drain re-check so the two
/// can never silently report different gauge names for the same counts.
fn set_snapshot_gauges(c: &SnapshotOutboxCounts) {
    metrics::gauge!("snapshot_outbox_pending").set(c.pending as f64);
    metrics::gauge!("snapshot_outbox_exhausted").set(c.exhausted as f64);
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
    resolver_base_url: String,
) {
    match outbox.status_counts().await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                reconciled = c.reconciled,
                exhausted = c.exhausted,
                "continuity snapshot outbox reconciliation at boot"
            );
            set_snapshot_gauges(&c);
        }
        Err(e) => tracing::warn!(error = %e, "snapshot outbox boot reconciliation failed"),
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::snapshot_drain::drain_once(
                &outbox,
                &repo,
                &store,
                &resolver_base_url,
                DRAIN_BATCH,
            )
            .await;
            if let Ok(c) = outbox.status_counts().await {
                set_snapshot_gauges(&c);
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

fn set_seal_gauges(c: &SealOutboxCounts) {
    metrics::gauge!("seal_outbox_pending").set(c.pending as f64);
    metrics::gauge!("seal_outbox_exhausted").set(c.exhausted as f64);
}

/// Log/gauge the qualified-seal outbox's outstanding state, then spawn the
/// periodic sealing loop. Publish enqueues a digest (after-commit, in the vault
/// service); this task asks the QTSP to seal it and writes the envelope onto the
/// passport. A killed node loses nothing: `pending` rows seal on boot.
///
/// Only spawned when a real QTSP is configured — see the `sealing_live` guard in
/// `main`, which is also what stops the vault enqueueing rows nothing would
/// drain.
pub async fn spawn_seal_drain(
    outbox: Arc<dyn SealOutbox>,
    seal: Arc<dyn SealPort>,
    client_id: String,
) {
    match outbox.status_counts().await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                sealed = c.sealed,
                exhausted = c.exhausted,
                "qualified-seal outbox reconciliation at boot"
            );
            set_seal_gauges(&c);
        }
        Err(e) => tracing::warn!(error = %e, "seal outbox boot reconciliation failed"),
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DRAIN_INTERVAL).await;
            dpp_node::infra::seal_drain::drain_once(&outbox, &seal, &client_id, DRAIN_BATCH).await;
            if let Ok(c) = outbox.status_counts().await {
                set_seal_gauges(&c);
                if c.exhausted > 0 {
                    // A published passport that gave up on sealing carries no
                    // qualified seal at all — a compliance signal, not noise.
                    tracing::warn!(
                        exhausted = c.exhausted,
                        "seal outbox has exhausted rows — those passports are published unsealed"
                    );
                }
            }
        }
    });
}

/// How long an exhausted seal row is left alone before the sweep re-arms it.
///
/// A row reaches `exhausted` only after eight attempts with exponential backoff,
/// so it almost always means the provider is down rather than the digest being
/// unsealable. Six hours lets an outage clear before we spend another eight
/// attempts on it, and bounds a genuinely unsealable passport to four retry
/// cycles a day rather than one every sweep.
const SEAL_EXHAUSTED_COOLDOWN_SECS: i64 = 6 * 3600;

/// Spawn the qualified-seal repair sweep.
///
/// The drain only ever sees rows that were successfully queued. This covers the
/// ones that were not: a crash between commit and enqueue leaves a published
/// passport with no row at all, and an `exhausted` row is one that gave up
/// during a provider outage. Both leave a passport published and unsealed, and
/// neither is self-healing — a re-publish would work, but it changes the very
/// signature the seal is supposed to attest to, so it is not a recovery an
/// operator should have to perform.
///
/// Cannot double-bill: it only queues passports carrying no seal at all.
pub fn spawn_seal_sweep(outbox: Arc<dyn SealOutbox>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            match outbox
                .enqueue_unsealed(SWEEP_BATCH, SEAL_EXHAUSTED_COOLDOWN_SECS)
                .await
            {
                Ok(0) => tracing::debug!("seal sweep: every published passport is sealed"),
                Ok(n) => tracing::warn!(
                    queued = n,
                    "seal sweep queued published passports that carry no qualified seal"
                ),
                Err(e) => tracing::warn!(error = %e, "seal sweep failed"),
            }
        }
    });
}

/// Spawn the continuity tier's repair sweep.
///
/// The drain only ever sees reconciles that were successfully queued. This loop
/// covers the ones that were not — a crash in the window between commit and
/// enqueue, a row that exhausted its retries, or drift left by an earlier code
/// path — by querying for passports whose static-tier state disagrees with the
/// database and queueing them through the same path. It is what makes the tier's
/// guarantee end-to-end rather than "loss-proof once enqueued".
///
/// Runs on [`SWEEP_INTERVAL`], far rarer than the drain: this is a backstop, not
/// the primary path. Because it queries for divergence signals rather than
/// sweeping everything, a converged deployment queues nothing.
pub fn spawn_snapshot_sweep(outbox: Arc<dyn SnapshotOutbox>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            match outbox.enqueue_divergent(SWEEP_BATCH).await {
                Ok(0) => tracing::debug!("continuity snapshot sweep: nothing divergent"),
                Ok(n) => {
                    // Non-zero is worth an info line: in a healthy deployment the
                    // event-driven path should have caught these, so a steady
                    // trickle here means something upstream is dropping enqueues.
                    metrics::counter!("snapshot_sweep_requeued_total").increment(n);
                    tracing::info!(
                        requeued = n,
                        "continuity snapshot sweep queued divergent passports"
                    );
                }
                Err(e) => tracing::warn!(error = %e, "continuity snapshot sweep failed"),
            }
        }
    });
}
