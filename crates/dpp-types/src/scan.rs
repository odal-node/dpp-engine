//! Scan telemetry — the persistence port and its aggregate read models.
//!
//! # Why this lives here (not in core's `dpp-domain::ports`)
//!
//! Whether a deployment counts how often its passports are resolved is
//! operational, not part of the DPP standard — the standard defines the public
//! view, not analytics over it. So this port stays engine-side alongside
//! `WebhookOutbox` and `SnapshotOutbox`, never promoted to a core port, and
//! carries no tenant/audit/API-key concern into core.
//!
//! # The privacy posture is structural
//!
//! The stored records are aggregate counts keyed by `(passport, day, surface)`
//! only. There is no column for anything about the *scanner*. The refusal to
//! model an IP/agent/session is enforced by the schema, not by policy prose —
//! there is nothing to leak because nothing to leak is representable.
//!
//! Two aggregates, deliberately unmixed: [`ScanIncrement`] (a consumer resolving
//! a passport) and [`QrRenderIncrement`] (an operator producing a label image).
//! They are never summed — a QR render is not a resolution.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use dpp_domain::{DppError, passport::PassportId};

/// One daily scan increment to fold into the running total, parsed and validated
/// from the resolver's flush batch. `variant` is already constrained to a known
/// surface at the ingest boundary (it arrives as a typed enum), so it travels as
/// its DB string here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanIncrement {
    /// The resolved passport.
    pub dpp_id: PassportId,
    /// The UTC day.
    pub day: NaiveDate,
    /// The surface string (`"html"` / `"json"`).
    pub variant: String,
    /// How many scans to add.
    pub count: i64,
}

/// One daily QR-render increment to fold into the running total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrRenderIncrement {
    /// The passport whose QR image was produced.
    pub dpp_id: PassportId,
    /// The UTC day.
    pub day: NaiveDate,
    /// How many renders to add.
    pub count: i64,
}

/// A single day's scan count, for the daily series in the per-passport stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyScanCount {
    /// The UTC day.
    pub day: NaiveDate,
    /// Scans across all surfaces that day.
    pub count: i64,
}

/// Per-passport scan aggregates over a trailing window. `scans` and `qrRenders`
/// are reported side by side and never combined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportScanStats {
    /// The trailing window this covers, in days.
    pub window_days: i64,
    /// Total scans (all surfaces) in the window.
    pub total_scans: i64,
    /// Scans that served the HTML page.
    pub scans_html: i64,
    /// Scans that served JSON-LD.
    pub scans_json: i64,
    /// Per-day scan totals, oldest first.
    pub daily: Vec<DailyScanCount>,
    /// QR-image renders in the window — label production, not resolution.
    pub qr_renders: i64,
    /// Whether scan telemetry is actually reaching this node.
    ///
    /// `false` with `totalScans: 0` means the number is unmeasured, not zero.
    /// The distinction matters and the node cannot infer it from configuration:
    /// `SCAN_INGEST_URL` belongs to the **resolver**, a separate deployable, so
    /// the node has no view of whether telemetry was ever switched on. What it
    /// can observe is whether a resolver has flushed to it, which is what this
    /// reports — the resolver sends an empty batch each interval precisely so
    /// the answer exists with nothing to count.
    ///
    /// The same rule as `SealSummaryResponse.sealing_configured`, which exists so
    /// a reader "cannot mistake 'not sealing' for 'all sealed'". A zero here was
    /// making exactly that mistake available.
    pub ingesting: bool,
    /// When a resolver last flushed to this node, if ever.
    ///
    /// Resets when the node restarts: this is liveness, held in memory, not a
    /// persisted record. A node that has just booted reports `false` until the
    /// next flush arrives — at most one interval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ingest_at: Option<DateTime<Utc>>,
}

/// Operator-wide rollup over a trailing window — the "your passports were
/// resolved N times this month" headline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorScanStats {
    /// The trailing window this covers, in days.
    pub window_days: i64,
    /// Total scans across every passport in the window.
    pub total_scans: i64,
    /// Total QR-image renders across every passport in the window.
    pub total_qr_renders: i64,
    /// How many distinct passports were scanned at least once in the window.
    pub distinct_passports_scanned: i64,
    /// Whether scan telemetry is actually reaching this node.
    ///
    /// `false` with `totalScans: 0` means the number is unmeasured, not zero.
    /// The distinction matters and the node cannot infer it from configuration:
    /// `SCAN_INGEST_URL` belongs to the **resolver**, a separate deployable, so
    /// the node has no view of whether telemetry was ever switched on. What it
    /// can observe is whether a resolver has flushed to it, which is what this
    /// reports — the resolver sends an empty batch each interval precisely so
    /// the answer exists with nothing to count.
    ///
    /// The same rule as `SealSummaryResponse.sealing_configured`, which exists so
    /// a reader "cannot mistake 'not sealing' for 'all sealed'". A zero here was
    /// making exactly that mistake available.
    pub ingesting: bool,
    /// When a resolver last flushed to this node, if ever.
    ///
    /// Resets when the node restarts: this is liveness, held in memory, not a
    /// persisted record. A node that has just booted reports `false` until the
    /// next flush arrives — at most one interval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ingest_at: Option<DateTime<Utc>>,
}

/// How many rows a retention prune removed, per table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanPruneCounts {
    /// Rows deleted from the scan table.
    pub scans: u64,
    /// Rows deleted from the QR-render table.
    pub qr_renders: u64,
}

/// Persistence port for scan telemetry — the aggregate counters and their read
/// models. Implemented by the Postgres DAL; called by the vault's ingest and
/// stats handlers and by the node's retention prune.
#[async_trait]
pub trait ScanTelemetryRepository: Send + Sync {
    /// Fold a flush batch into the daily totals — one transaction over both
    /// tables, each row an upsert (`count = count + delta`). Empty slices are a
    /// no-op.
    async fn record_batch(
        &self,
        scans: &[ScanIncrement],
        qr_renders: &[QrRenderIncrement],
    ) -> Result<(), DppError>;

    /// Per-passport aggregates over the trailing `window_days`.
    async fn passport_stats(
        &self,
        dpp_id: PassportId,
        window_days: i64,
    ) -> Result<PassportScanStats, DppError>;

    /// Operator-wide rollup over the trailing `window_days`.
    async fn operator_stats(&self, window_days: i64) -> Result<OperatorScanStats, DppError>;

    /// Retention: delete rows whose `day` is older than `horizon_days` before
    /// today. Returns how many rows went from each table. This is the time-axis
    /// half of the privacy posture — aggregates do not accumulate forever.
    async fn prune(&self, horizon_days: i64) -> Result<ScanPruneCounts, DppError>;
}
