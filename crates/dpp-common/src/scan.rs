//! Scan-telemetry wire types — the batch the public resolver flushes to the node.
//!
//! These live in `dpp-common` because they are the one contract shared by two
//! processes that otherwise share nothing: the DB-free resolver (which counts)
//! and the vault (which persists). The resolver has no access to `dpp-types` or
//! the DAL by design, so the payload is deliberately minimal, self-describing,
//! and keyed by the passport id as an opaque string — the vault parses and
//! validates it at the trust boundary.
//!
//! **Privacy is in the shape.** A batch carries only *aggregate counts* per
//! passport, per day, per surface. There is no field for an IP, a user agent, a
//! session, or a per-event row — none exists to be populated, so none can leak.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// The resolver surface a scan came through. Only terminal passport views count
/// as scans; the QR-image endpoint is tracked separately (see [`QrRenderBatchEntry`])
/// because rendering a label is production, not resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanVariant {
    /// A human-readable passport page (`GET /dpp/{id}` negotiated to HTML).
    Html,
    /// A machine read of the passport (`GET /dpp/{id}` negotiated to JSON-LD).
    Json,
}

impl ScanVariant {
    /// The exact string persisted in the `variant` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Json => "json",
        }
    }
}

/// One aggregated scan increment: `count` resolutions of `dpp_id` on `day` via
/// `variant`. The resolver sends deltas (what it accumulated since the last
/// flush); the vault adds them to the running daily total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBatchEntry {
    /// The resolved passport id, as an opaque string. Validated at ingest.
    pub dpp_id: String,
    /// The UTC day the scans fell on.
    pub day: NaiveDate,
    /// Which surface served them.
    pub variant: ScanVariant,
    /// How many, since the last flush.
    pub count: u64,
}

/// One aggregated QR-image increment: `count` renders of `dpp_id`'s QR PNG on
/// `day`. Kept separate from scans — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrRenderBatchEntry {
    /// The passport id whose QR image was produced, as an opaque string.
    pub dpp_id: String,
    /// The UTC day the renders fell on.
    pub day: NaiveDate,
    /// How many, since the last flush.
    pub count: u64,
}

/// The full flush payload. Both metrics travel together so one flush is one
/// authenticated round-trip; the vault fans them to their separate tables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBatch {
    /// Terminal-view scan increments.
    pub scans: Vec<ScanBatchEntry>,
    /// QR-image render increments.
    pub qr_renders: Vec<QrRenderBatchEntry>,
}

impl ScanBatch {
    /// True when there is nothing to send — the flush task skips the round-trip.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scans.is_empty() && self.qr_renders.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&ScanVariant::Html).unwrap(),
            r#""html""#
        );
        assert_eq!(ScanVariant::Json.as_db(), "json");
    }

    #[test]
    fn batch_round_trips_camel_case() {
        let batch = ScanBatch {
            scans: vec![ScanBatchEntry {
                dpp_id: "abc-123".into(),
                day: NaiveDate::from_ymd_opt(2026, 7, 24).unwrap(),
                variant: ScanVariant::Json,
                count: 3,
            }],
            qr_renders: vec![QrRenderBatchEntry {
                dpp_id: "abc-123".into(),
                day: NaiveDate::from_ymd_opt(2026, 7, 24).unwrap(),
                count: 1,
            }],
        };
        let json = serde_json::to_string(&batch).unwrap();
        assert!(json.contains("qrRenders"));
        assert!(json.contains("dppId"));
        let back: ScanBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, batch);
    }

    #[test]
    fn empty_batch_detected() {
        assert!(ScanBatch::default().is_empty());
    }
}
