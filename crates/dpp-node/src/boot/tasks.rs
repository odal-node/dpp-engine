//! Background task spawns: expired-import-job cleanup and the registry-sync
//! outbox drain (including its boot-time reconciliation log/gauges).

use std::sync::Arc;

use dpp_domain::ports::identity::IdentityPort;
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

/// Spawn the periodic purge of expired idempotency keys (hourly).
///
/// Hourly against a 24-hour retention: frequent enough that the table tracks a
/// day of traffic rather than growing between restarts, rare enough that the
/// `DELETE` is never in the way. The grant that lets this run is the reason
/// `odal.idempotency_key` is named in `ops/pg/README.md`'s DELETE set.
///
/// A failure is logged and the loop continues — an unswept table is a growing
/// one, not a broken one, and every row in it is still honoured.
pub fn spawn_idempotency_purge(store: Arc<dyn dpp_common::idempotency::IdempotencyStore>) {
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(3600);
        loop {
            tokio::time::sleep(interval).await;
            match store.purge_expired().await {
                Ok(0) => tracing::debug!("idempotency purge: nothing expired"),
                Ok(n) => {
                    metrics::counter!("idempotency_keys_purged_total").increment(n);
                    tracing::debug!(purged = n, "idempotency purge removed expired keys");
                }
                Err(e) => tracing::warn!(error = %e, "idempotency purge failed"),
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

use dpp_node::infra::drain::{
    DRAIN_INTERVAL, SNAPSHOT_REFRESH_INTERVAL, SNAPSHOT_REFRESH_SCAN_INTERVAL, SWEEP_INTERVAL,
};

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
    // Awaiting the registry's verdict: not an error, but not done either, and a
    // number that should not keep growing.
    metrics::gauge!("registry_outbox_submitted").set(c.submitted as f64);
    metrics::gauge!("registry_outbox_stalled").set(c.stalled as f64);
    metrics::gauge!("registry_outbox_rejected").set(c.rejected as f64);
    metrics::gauge!("registry_outbox_deactivated").set(c.deactivated as f64);
}

/// Log/gauge the outbox's outstanding state, then spawn the periodic drain
/// loop (ESPR Art. 13). Publish enqueues each registration transactionally
/// with the passport write; this task drains due rows against the registry
/// port with backoff. A killed node loses nothing — rows persist and are
/// retried here on restart.
pub async fn spawn_registry_drain(
    outbox: Arc<dyn RegistrySyncOutbox>,
    registry_sync: Arc<dyn RegistrySyncPort>,
    operator: Option<Arc<dyn dpp_types::operator::OperatorConfigRepository>>,
) {
    // Boot reconciliation: log outstanding registry-sync state so a restart
    // surfaces (never hides) queued/rejected/stalled registrations.
    match outbox.status_counts(STALL_THRESHOLD).await {
        Ok(c) => {
            tracing::info!(
                pending = c.pending,
                submitted = c.submitted,
                registered = c.registered,
                rejected = c.rejected,
                deactivated = c.deactivated,
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
            dpp_node::infra::registry_drain::drain_once(
                &outbox,
                &registry_sync,
                operator.as_ref(),
                DRAIN_BATCH,
            )
            .await;
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
    registrations: Arc<dyn RegistrySyncOutbox>,
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
            dpp_node::infra::transfer_drain::drain_once(
                &outbox,
                &registrations,
                &registry_sync,
                DRAIN_BATCH,
            )
            .await;
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
    identity: Arc<dyn IdentityPort>,
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
                &identity,
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
    key_ref: dpp_domain::seal::SealCredentialRef,
    mode: dpp_domain::seal::SealMode,
    conformance_level: dpp_domain::seal::SealConformanceLevel,
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
            dpp_node::infra::seal_drain::drain_once(
                &outbox,
                &seal,
                &key_ref,
                mode.clone(),
                conformance_level,
                DRAIN_BATCH,
            )
            .await;
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

/// How many stored seals one audit pass opens.
///
/// Smaller than the sweep's batch, because this does cryptographic work per row
/// rather than one query: a pass opens each CAdES, checks a signature and reads
/// a digest out of it. Walking the whole estate in one go would be a spike of
/// CPU on a background task that is in no hurry — the walk continues from its
/// cursor on the next tick, so a large estate is covered over several passes
/// rather than in one.
/// Overridable with `SEAL_AUDIT_BATCH` — see [`seal_audit_cadence`].
const SEAL_AUDIT_BATCH: i64 = 200;

/// How often an audit pass runs.
///
/// Its own cadence rather than [`SWEEP_INTERVAL`], which is hourly because the
/// sweep is a backstop for a rare divergence. This is a **scan that wants to
/// finish**: nothing it reports is usable until the walk has been all the way
/// round, and at the sweep's cadence a modest estate would take most of a day —
/// which is also how long a restart would leave the report blank.
///
/// Together with [`SEAL_AUDIT_BATCH`] this is the knob: a pass covers
/// `SEAL_AUDIT_BATCH` seals every interval, so the freshness of the report is
/// the estate divided by that rate. A pass is one query plus a few hundred
/// signature checks, which is why it can afford to be this frequent.
/// Overridable with `SEAL_AUDIT_INTERVAL_SECS` — see [`seal_audit_cadence`].
const SEAL_AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The ceiling the cadence should be read against.
///
/// **A day to notice a corrupt seal**, which is the outer bound worth accepting
/// for a condition an operator can do nothing about until they are told. A walk
/// slower than this leaves a passport that is published and, in substance,
/// unsealed sitting unreported for longer than anyone would choose.
///
/// The number is borrowed rather than invented: CIR (EU) 2025/1945 — the act
/// that pins how a qualified seal is validated, through Art. 32(3) and Art. 40
/// of Reg. (EU) No 910/2014 — caps revocation information for the signing
/// certificate at 24 hours old.
///
/// **That cap does not currently bind this walk, and the difference matters.**
/// The revocation material this node reads is the CRL *inside* the seal: fixed
/// at sealing time, immutable, and the whole point of the long-term profiles.
/// Re-reading it hourly rather than daily learns nothing new about revocation.
/// The cap would bind the day this node fetches *fresh* revocation data to
/// validate a current signature — which it does not do, and will not without
/// the outbound path that implies.
const SEAL_AUDIT_TARGET_WRAP: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// The batch and interval this node's audit will actually run at.
///
/// # Why these are configurable
///
/// Together they are the only knob on how fresh the stored-seal report can be:
/// a pass covers `batch` seals every `interval`, so a full walk takes the estate
/// divided by that rate, and the report is that old at worst. The defaults suit
/// a node holding thousands of seals. One holding a million would be walking for
/// days — long enough that the answer describes an estate that has moved on, and
/// far past [`SEAL_AUDIT_TARGET_WRAP`].
///
/// # An unparseable value fails the boot rather than falling back
///
/// The default is a fine value, so falling back to it is tempting. It is also
/// exactly the failure this whole surface exists to prevent: an operator who set
/// a cadence, believes their seals are checked at it, and is running at some
/// other one because of a typo. A node told to do something it cannot parse
/// should say so, not quietly do something else.
///
/// # Errors
///
/// An unparseable or out-of-range `SEAL_AUDIT_BATCH` / `SEAL_AUDIT_INTERVAL_SECS`.
fn seal_audit_cadence() -> anyhow::Result<(i64, std::time::Duration)> {
    seal_audit_cadence_from(|name| std::env::var(name).ok())
}

/// The whole of [`seal_audit_cadence`]'s rule over an arbitrary lookup.
///
/// Split out so it is testable as a pure function, the same arrangement
/// `dpp_seal::config::SealProvider::resolve` uses and for the same reasons:
/// exercising it through the real environment means mutating process-global
/// state from a test, which is `unsafe` under Rust 2024, forces the tests to
/// serialise against one another, and lets a stray variable in a developer's
/// shell decide the result.
///
/// # Errors
///
/// An unparseable or out-of-range value.
fn seal_audit_cadence_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<(i64, std::time::Duration)> {
    fn read<T>(
        get: &impl Fn(&str) -> Option<String>,
        name: &str,
        default: T,
        min: T,
        max: T,
    ) -> anyhow::Result<T>
    where
        T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
    {
        let Some(raw) = get(name) else {
            return Ok(default);
        };
        let raw = raw.trim();
        let Ok(value) = raw.parse::<T>() else {
            anyhow::bail!("{name} '{raw}' is not a whole number (expected {min}..={max})");
        };
        anyhow::ensure!(
            value >= min && value <= max,
            "{name} '{value}' is out of range (expected {min}..={max})"
        );
        Ok(value)
    }

    let batch = read(&get, "SEAL_AUDIT_BATCH", SEAL_AUDIT_BATCH, 1, 10_000)?;
    // An hour is the ceiling because a pass this task cannot run within one is
    // not a cadence, it is a manual job with extra steps; one second is the
    // floor because the pass does real cryptographic work per row.
    let interval = read(
        &get,
        "SEAL_AUDIT_INTERVAL_SECS",
        SEAL_AUDIT_INTERVAL.as_secs(),
        1,
        3_600,
    )?;
    Ok((batch, std::time::Duration::from_secs(interval)))
}

/// How long a full walk of `sealed` seals takes at this cadence.
///
/// The `+ 1` is the empty batch that proves the end: a walk publishes when a
/// batch comes back with nothing in it, so the pass that finds nothing is part
/// of the round trip.
fn projected_wrap(sealed: i64, batch: i64, interval: std::time::Duration) -> std::time::Duration {
    let batch = batch.max(1);
    // Rounded up, not down: a final part-full batch is still a whole pass. The
    // floor version under-reported the wrap for every estate that is not an
    // exact multiple of the batch, which is nearly all of them.
    let full = sealed.div_euclid(batch) + i64::from(sealed.rem_euclid(batch) > 0);
    let passes = full + 1;
    interval.saturating_mul(u32::try_from(passes).unwrap_or(u32::MAX))
}

/// Spawn the stored-seal audit.
///
/// # What it finds that nothing else can
///
/// [`spawn_seal_sweep`] and the operator rollup both ask the database whether a
/// passport's `seal` member is **absent**. A seal that is present and worthless
/// answers "no" to that and is therefore invisible: not swept, not counted,
/// healthy in every number the node reports — while the passport is, in
/// substance, unsealed.
///
/// Whether a stored seal stands up is cryptographic rather than relational, so
/// no widening of that query could reach it. This opens them.
///
/// # It reports and does not repair
///
/// [`spawn_seal_sweep`] carries a guarantee worth keeping: it cannot double-bill,
/// because it only queues passports carrying no seal at all. Re-queueing a broken
/// seal breaks exactly that — the row was paid for, and buying a second seal is
/// justified only because the first is worthless. That is a decision to take
/// knowingly rather than one for a background loop to take on an operator's
/// behalf, on the strength of a check that has not yet met a real provider's
/// seal.
///
/// So a finding is logged at `error` and gauged on `seal_broken`. Repair is its
/// own route, driven by an operator.
///
/// # The walk survives a restart
///
/// A pass publishes only when it reaches the end, so both the position and the
/// result are worth keeping across a restart. Without the position, a node whose
/// estate takes longer to walk than it goes between deployments starts again
/// from the beginning every time and never publishes anything at all, while
/// doing every bit of the work. Without the result, the operator surface says
/// "no pass has completed" for a whole walk after each restart, which on a large
/// estate is hours and reads exactly like an audit that is not running.
///
/// `store` is optional so a node without one still audits; it simply forgets
/// across restarts, which is the old behaviour and still honest.
///
/// # Errors
///
/// An unusable `SEAL_AUDIT_BATCH` / `SEAL_AUDIT_INTERVAL_SECS` — see
/// [`seal_audit_cadence`].
pub fn spawn_seal_audit(
    outbox: Arc<dyn SealOutbox>,
    log: Arc<dpp_types::SealAuditLog>,
    store: Option<Arc<dyn dpp_types::SealAuditStore>>,
) -> anyhow::Result<()> {
    let (batch_size, interval) = seal_audit_cadence()?;
    tokio::spawn(async move {
        // The same reader the drain uses to accept a seal, so the audit and the
        // acceptance cannot come to disagree about what a sound seal is.
        let inspector = dpp_seal::CadesInspector::new();
        let mut cursor = None;
        // Accumulated across the whole walk, not per batch. The gauge has to
        // answer "how many broken seals does this node hold", and a value set
        // from a 100-row batch answers "how many were in the last hundred" —
        // which flaps between passes and reads as zero most of the time on an
        // estate where the answer is not zero.
        let mut walk = dpp_node::infra::seal_drain::SealAudit::default();
        // The moment this walk began, and the bound every batch is read against,
        // so one pass is a statement about exactly the seals that existed then.
        let mut started_at = chrono::Utc::now();

        if let Some(store) = store.as_ref() {
            match store.load().await {
                Ok((progress, report)) => {
                    // The report first: it is what the operator surface serves,
                    // and it should be answerable before the first batch runs.
                    if let Some(report) = report {
                        tracing::info!(
                            completed_at = %report.completed_at,
                            checked = report.checked,
                            broken = report.broken,
                            "restored the last completed seal audit"
                        );
                        log.record(report);
                    }
                    if let Some(progress) = progress {
                        tracing::info!(
                            started_at = %progress.started_at,
                            checked = progress.checked,
                            "resuming the seal audit walk where it left off"
                        );
                        cursor = progress.cursor;
                        started_at = progress.started_at;
                        walk = dpp_node::infra::seal_drain::SealAudit {
                            checked: progress.checked,
                            sound: progress.sound,
                            superseded: progress.superseded,
                            broken: progress.broken,
                            certificate_failed: progress.certificate_failed,
                            unreadable: progress.unreadable,
                            broken_passports: progress.broken_passports,
                        };
                    }
                }
                // A cache that cannot be read costs a walk, not the audit.
                Err(e) => tracing::warn!(error = %e, "could not read the stored seal audit"),
            }
        }

        // What the configured cadence actually buys, said once at boot against
        // the estate this node holds — the number is meaningless without it.
        if let Ok(counts) = outbox.status_counts().await {
            let wrap = projected_wrap(counts.sealed, batch_size, interval);
            if wrap > SEAL_AUDIT_TARGET_WRAP {
                tracing::warn!(
                    sealed = counts.sealed,
                    batch = batch_size,
                    interval_secs = interval.as_secs(),
                    wrap_hours = wrap.as_secs() / 3600,
                    "a full pass over this node's stored seals takes longer than 24h at the \
                     configured cadence — raise SEAL_AUDIT_BATCH or lower \
                     SEAL_AUDIT_INTERVAL_SECS. A seal that stops verifying is invisible to \
                     every other number this node reports, so the walk is the only thing that \
                     will ever say so, and this is how long that takes"
                );
            } else {
                tracing::info!(
                    sealed = counts.sealed,
                    batch = batch_size,
                    interval_secs = interval.as_secs(),
                    wrap_mins = wrap.as_secs() / 60,
                    "seal audit cadence"
                );
            }
        }

        loop {
            tokio::time::sleep(interval).await;
            let Some((audit, next)) = dpp_node::infra::seal_drain::audit_seals_once(
                &outbox,
                &inspector,
                batch_size,
                cursor,
                Some(started_at),
            )
            .await
            else {
                // The batch could not be read. Keep the cursor and the totals,
                // publish nothing: a walk that never saw the estate must not
                // report on it.
                continue;
            };

            walk.checked += audit.checked;
            walk.sound += audit.sound;
            walk.superseded += audit.superseded;
            walk.broken += audit.broken;
            walk.certificate_failed += audit.certificate_failed;
            walk.unreadable += audit.unreadable;
            for id in audit.broken_passports {
                if walk.broken_passports.len() < dpp_node::infra::seal_drain::MAX_NAMED_BROKEN {
                    walk.broken_passports.push(id);
                }
            }

            if audit.broken > 0 {
                tracing::error!(
                    broken = audit.broken,
                    checked = audit.checked,
                    "stored seals do not verify — those passports are published and, in \
                     substance, unsealed, and `unsealedPublished` cannot see them"
                );
            }

            // An empty batch means the walk reached the end. Publish the total,
            // then start again from the beginning: a seal sound today can be
            // corrupt tomorrow, and a pass that ran once would only ever catch
            // what was already broken.
            if next.is_none() {
                // No `_total` suffix: these are gauges, and every other gauge
                // here is unsuffixed (`seal_outbox_pending`,
                // `registry_outbox_rejected`) while `_total` marks the counters
                // (`seal_total`, `seal_downgraded_total`). A gauge named like a
                // counter gets `rate()` applied to it, which means nothing.
                metrics::gauge!("seal_broken").set(walk.broken as f64);
                metrics::gauge!("seal_unreadable").set(walk.unreadable as f64);
                // Its own gauge, not folded into `seal_broken`: the two need
                // different responses, and an operator alerting on one should
                // not be woken by the other.
                metrics::gauge!("seal_certificate_failed").set(walk.certificate_failed as f64);
                let report = dpp_types::SealAuditReport {
                    completed_at: chrono::Utc::now(),
                    checked: walk.checked,
                    sound: walk.sound,
                    superseded: walk.superseded,
                    broken: walk.broken,
                    certificate_failed: walk.certificate_failed,
                    unreadable: walk.unreadable,
                    truncated: (walk.broken_passports.len() as u64) < walk.broken,
                    broken_passports: walk.broken_passports.clone(),
                };
                log.record(report.clone());
                if let Some(store) = store.as_ref()
                    && let Err(e) = store.complete(&report).await
                {
                    // Served from memory regardless; what is lost is the answer
                    // surviving the next restart.
                    tracing::warn!(error = %e, "could not store the completed seal audit");
                }
                tracing::debug!(
                    checked = walk.checked,
                    sound = walk.sound,
                    superseded = walk.superseded,
                    broken = walk.broken,
                    certificate_failed = walk.certificate_failed,
                    unreadable = walk.unreadable,
                    "seal audit completed a pass over every stored seal"
                );
                walk = dpp_node::infra::seal_drain::SealAudit::default();
                // The next walk describes the estate as it is now, including
                // everything sealed while this one was running.
                started_at = chrono::Utc::now();
            } else if let Some(store) = store.as_ref()
                && let Err(e) = store
                    .save_progress(&dpp_types::SealAuditProgress {
                        started_at,
                        cursor: next,
                        checked: walk.checked,
                        sound: walk.sound,
                        superseded: walk.superseded,
                        broken: walk.broken,
                        certificate_failed: walk.certificate_failed,
                        unreadable: walk.unreadable,
                        broken_passports: walk.broken_passports.clone(),
                    })
                    .await
            {
                // The walk carries on in memory; only its survival is lost.
                tracing::warn!(error = %e, "could not store the seal audit's position");
            }
            cursor = next;
        }
    });
    Ok(())
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

/// How many snapshots one refresh scan may re-arm.
///
/// With [`SNAPSHOT_REFRESH_SCAN_INTERVAL`] this sets the corpus the tier can
/// keep renewed: `REFRESH_BATCH × (SNAPSHOT_REFRESH_INTERVAL /
/// SNAPSHOT_REFRESH_SCAN_INTERVAL)` snapshots per refresh window. Beyond that
/// the pass falls behind and snapshots begin to lapse while their passports are
/// still published, which is why [`spawn_snapshot_refresh`] says so at boot
/// rather than leaving it to be discovered.
const REFRESH_BATCH: i64 = 500;

/// How many published snapshots can be renewed within one refresh window.
fn refresh_capacity() -> u64 {
    let scans_per_window =
        SNAPSHOT_REFRESH_INTERVAL.as_secs() / SNAPSHOT_REFRESH_SCAN_INTERVAL.as_secs().max(1);
    REFRESH_BATCH.unsigned_abs() * scans_per_window
}

/// Spawn the continuity tier's refresh pass.
///
/// A snapshot vouches for itself only until the `validUntil` signed into it, so
/// a published passport's copy has to be re-signed before that window closes.
/// This loop re-arms the reconciles that do it; the drain then re-renders,
/// re-signs and re-uploads through the same convergent path everything else
/// uses — which is what makes a refresh safe. If the passport was withdrawn
/// while the node was down, the "refresh" the drain performs is a `remove()`.
///
/// Withdrawal itself needs none of this. It is the *absence* of a refresh, so
/// it takes effect on a node that is switched off, and on a copy nobody can
/// reach — the two cases every other mechanism here misses.
///
/// Kept apart from [`spawn_snapshot_sweep`] deliberately. That loop's non-zero
/// result is a defect signal; this one's is the normal state of a healthy
/// deployment. Sharing a counter would bury the first under the second.
pub async fn spawn_snapshot_refresh(outbox: Arc<dyn SnapshotOutbox>) {
    let capacity = refresh_capacity();
    if let Ok(c) = outbox.status_counts().await {
        let tracked = c.pending + c.reconciled + c.exhausted;
        if tracked as u64 > capacity {
            // Not fatal, and not silently survivable either: past this point
            // some published passport's snapshot expires every cycle, and the
            // tier goes on reporting success while doing it.
            tracing::warn!(
                tracked,
                capacity,
                "continuity refresh cannot cover the corpus — snapshots will expire while published; raise the refresh batch or scan more often"
            );
        }
    }
    metrics::gauge!("snapshot_refresh_capacity").set(capacity as f64);

    tokio::spawn(async move {
        let older_than = chrono::Duration::from_std(SNAPSHOT_REFRESH_INTERVAL)
            .expect("SNAPSHOT_REFRESH_INTERVAL is a small constant");
        loop {
            tokio::time::sleep(SNAPSHOT_REFRESH_SCAN_INTERVAL).await;
            match outbox.enqueue_stale(older_than, REFRESH_BATCH).await {
                Ok(0) => tracing::debug!("continuity snapshot refresh: nothing due"),
                Ok(n) => {
                    metrics::counter!("snapshot_refresh_requeued_total").increment(n);
                    tracing::debug!(requeued = n, "continuity snapshot refresh queued renewals");
                }
                // Worth a warning where the sweep's failure is not: a refresh
                // that stops running expires every published snapshot in the
                // deployment once the validity window runs out.
                Err(e) => tracing::warn!(error = %e, "continuity snapshot refresh failed"),
            }
        }
    });
}

/// Spawn the signed-ruleset poller: re-read the configured channel on
/// `interval` and hot-swap anything that verifies and is current.
///
/// This is what makes "adopting a new ruleset does not need a restart" true for
/// an unattended node — the admin route covers the operator who is watching,
/// this covers the fleet that is not. Every refusal is fail-closed and lands on
/// `ruleset_load_failures_total`, which the per-VM self-check already alarms on,
/// so a channel serving bad bytes is visible without new monitoring.
///
/// No-op when no channel is configured, or when the operator set
/// `RULESET_POLL_INTERVAL_SECS=0` to leave the admin route as the only trigger.
pub fn spawn_ruleset_poll(
    active: Arc<dpp_node::infra::ruleset::ActiveRuleset>,
    interval: Option<std::time::Duration>,
) {
    let Some(interval) = interval.filter(|_| active.has_channel()) else {
        return;
    };
    tracing::info!(
        interval_secs = interval.as_secs(),
        "compliance-current ruleset poller started"
    );
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            dpp_node::infra::ruleset::reload_and_report(&active, false).await;
        }
    });
}

#[cfg(test)]
mod seal_audit_cadence_tests {
    use super::*;

    /// A lookup standing in for the process environment.
    ///
    /// Nothing here calls `set_var`: the rule is a pure function over this, so
    /// the tests run in parallel, cannot be changed by a developer's shell, and
    /// need no `unsafe`.
    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let owned: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn the_defaults_are_what_ships() {
        let (batch, interval) = seal_audit_cadence_from(env(&[])).expect("defaults parse");
        assert_eq!(batch, SEAL_AUDIT_BATCH);
        assert_eq!(interval, SEAL_AUDIT_INTERVAL);
    }

    #[test]
    fn a_configured_cadence_is_honoured() {
        let (batch, interval) = seal_audit_cadence_from(env(&[
            ("SEAL_AUDIT_BATCH", " 2000 "),
            ("SEAL_AUDIT_INTERVAL_SECS", "10"),
        ]))
        .expect("parses");
        assert_eq!(
            batch, 2000,
            "surrounding whitespace is not a typo worth failing on"
        );
        assert_eq!(interval.as_secs(), 10);
    }

    /// **A value that cannot be read fails the boot rather than falling back.**
    ///
    /// The default is a perfectly good cadence, which is exactly why falling
    /// back to it is the wrong move: the operator would be told nothing and
    /// would believe their seals were being checked at the rate they set.
    #[test]
    fn an_unparseable_cadence_is_refused() {
        let err = seal_audit_cadence_from(env(&[("SEAL_AUDIT_INTERVAL_SECS", "60s")]))
            .expect_err("'60s' is not a number of seconds");
        assert!(
            err.to_string().contains("SEAL_AUDIT_INTERVAL_SECS"),
            "the message must name the variable: {err}"
        );
    }

    /// Zero is the interesting rejection: it reads as "off", and would be a
    /// busy loop hammering the database with no sleep between passes.
    #[test]
    fn an_out_of_range_cadence_is_refused() {
        assert!(
            seal_audit_cadence_from(env(&[("SEAL_AUDIT_INTERVAL_SECS", "0")])).is_err(),
            "zero seconds is a busy loop"
        );
        assert!(
            seal_audit_cadence_from(env(&[("SEAL_AUDIT_BATCH", "0")])).is_err(),
            "a zero batch never advances the cursor and never wraps"
        );
    }

    /// The arithmetic behind the boot warning, including the empty batch that
    /// proves the end of the walk.
    #[test]
    fn a_walk_costs_one_pass_per_batch_plus_the_one_that_finds_nothing() {
        let minute = std::time::Duration::from_secs(60);
        assert_eq!(
            projected_wrap(0, 200, minute),
            minute,
            "an empty estate still takes the pass that discovers it is empty"
        );
        assert_eq!(projected_wrap(200, 200, minute), 2 * minute);
        assert_eq!(projected_wrap(201, 200, minute), 3 * minute);
    }

    /// The case the warning exists for: an estate large enough that the shipped
    /// cadence cannot get round it inside the day.
    #[test]
    fn a_large_estate_outruns_the_default_cadence() {
        let wrap = projected_wrap(1_000_000, SEAL_AUDIT_BATCH, SEAL_AUDIT_INTERVAL);
        assert!(
            wrap > SEAL_AUDIT_TARGET_WRAP,
            "a million seals at 200/min is days, and the operator must be told: {wrap:?}"
        );
        // And that the knob is the answer, not a rewrite.
        let tuned = projected_wrap(1_000_000, 10_000, std::time::Duration::from_secs(10));
        assert!(
            tuned < SEAL_AUDIT_TARGET_WRAP,
            "the same estate fits inside the day at a cadence the range allows: {tuned:?}"
        );
    }
}
