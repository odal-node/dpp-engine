//! `POST /internal/scan-batch` — the mTLS-gated sink for the resolver's flush.
//!
//! The public resolver has no database: it accumulates aggregate counts in memory
//! and flushes them here. This endpoint is mounted off both the public and the
//! authenticated trees and gated by client-certificate mTLS (`CN=odal-resolver`)
//! in the router. That gate is the point of the feature's integrity — an
//! unauthenticated writer here could inflate an operator's resolution counts.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use dpp_common::scan::ScanBatch;
use dpp_domain::{DppError, passport::PassportId};
use dpp_types::scan::{QrRenderIncrement, ScanIncrement, ScanTelemetryRepository};

use super::error::internal_error;
use crate::extract::Json;
use crate::state::AppState;

/// The client-certificate common name the resolver presents when flushing.
const RESOLVER_CN: &str = "odal-resolver";

/// mTLS gate for the internal scan-ingest route: only the resolver may write.
pub async fn scan_ingest_mtls(request: Request, next: Next) -> Response {
    dpp_common::mtls::enforce(request, next, RESOLVER_CN).await
}

/// Fold a flush batch into the daily counters.
pub async fn scan_ingest_handler(
    State(state): State<AppState>,
    Json(batch): Json<ScanBatch>,
) -> impl IntoResponse {
    // Recorded before the rows are stored, and for an empty batch too: this is
    // the heartbeat that lets `GET /stats` tell "nobody scanned" from "nothing
    // is counting". A window with no counts still proves a resolver is there.
    crate::infra::scan_liveness::record_ingest();

    match ingest_batch(state.scan_repo.as_ref(), batch).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => internal_error(e),
    }
}

/// Parse and validate a flush batch at the trust boundary, then hand it to the
/// repository. Rows with an unparseable id are dropped rather than failing the
/// whole window — the resolver only ever sends ids it resolved, so this is
/// defensive, and one bad row must not lose a telemetry window.
async fn ingest_batch(
    repo: &dyn ScanTelemetryRepository,
    batch: ScanBatch,
) -> Result<(), DppError> {
    let scans: Vec<ScanIncrement> = batch
        .scans
        .iter()
        .filter_map(|s| {
            Uuid::parse_str(&s.dpp_id).ok().map(|u| ScanIncrement {
                dpp_id: PassportId(u),
                day: s.day,
                variant: s.variant.as_db().to_owned(),
                count: i64::try_from(s.count).unwrap_or(i64::MAX),
            })
        })
        .collect();

    let qr_renders: Vec<QrRenderIncrement> = batch
        .qr_renders
        .iter()
        .filter_map(|q| {
            Uuid::parse_str(&q.dpp_id).ok().map(|u| QrRenderIncrement {
                dpp_id: PassportId(u),
                day: q.day,
                count: i64::try_from(q.count).unwrap_or(i64::MAX),
            })
        })
        .collect();

    repo.record_batch(&scans, &qr_renders).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::NaiveDate;

    use dpp_common::scan::{QrRenderBatchEntry, ScanBatchEntry, ScanVariant};
    use dpp_types::scan::{OperatorScanStats, PassportScanStats, ScanPruneCounts};

    use super::*;

    /// Records whatever `record_batch` is handed, so a test can assert exactly
    /// what the ingest boundary parsed out of a wire batch.
    #[derive(Default)]
    struct CapturingRepo {
        scans: Mutex<Vec<ScanIncrement>>,
        qr: Mutex<Vec<QrRenderIncrement>>,
    }

    #[async_trait]
    impl ScanTelemetryRepository for CapturingRepo {
        async fn record_batch(
            &self,
            scans: &[ScanIncrement],
            qr_renders: &[QrRenderIncrement],
        ) -> Result<(), DppError> {
            self.scans.lock().unwrap().extend_from_slice(scans);
            self.qr.lock().unwrap().extend_from_slice(qr_renders);
            Ok(())
        }
        async fn passport_stats(
            &self,
            _dpp_id: PassportId,
            _window_days: i64,
        ) -> Result<PassportScanStats, DppError> {
            unreachable!("stats not exercised by ingest tests")
        }
        async fn operator_stats(&self, _window_days: i64) -> Result<OperatorScanStats, DppError> {
            unreachable!("stats not exercised by ingest tests")
        }
        async fn prune(&self, _horizon_days: i64) -> Result<ScanPruneCounts, DppError> {
            unreachable!("prune not exercised by ingest tests")
        }
    }

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 7, 24).unwrap()
    }

    #[tokio::test]
    async fn valid_rows_are_parsed_and_fanned_to_both_tables() {
        let repo = CapturingRepo::default();
        let id = "00000000-0000-4000-9000-000000000001";
        let batch = ScanBatch {
            scans: vec![ScanBatchEntry {
                dpp_id: id.into(),
                day: day(),
                variant: ScanVariant::Html,
                count: 5,
            }],
            qr_renders: vec![QrRenderBatchEntry {
                dpp_id: id.into(),
                day: day(),
                count: 2,
            }],
        };
        ingest_batch(&repo, batch).await.expect("ingest");

        let scans = repo.scans.lock().unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].variant, "html", "wire enum mapped to db string");
        assert_eq!(scans[0].count, 5);
        assert_eq!(scans[0].dpp_id, PassportId(Uuid::parse_str(id).unwrap()));
        assert_eq!(repo.qr.lock().unwrap()[0].count, 2);
    }

    #[tokio::test]
    async fn unparseable_id_is_dropped_not_fatal() {
        let repo = CapturingRepo::default();
        let batch = ScanBatch {
            scans: vec![ScanBatchEntry {
                dpp_id: "not-a-uuid".into(),
                day: day(),
                variant: ScanVariant::Json,
                count: 1,
            }],
            qr_renders: vec![],
        };
        // A bad id must not fail the whole flush — it is silently dropped.
        ingest_batch(&repo, batch).await.expect("ingest still ok");
        assert!(
            repo.scans.lock().unwrap().is_empty(),
            "the unparseable row was dropped"
        );
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        let repo = CapturingRepo::default();
        ingest_batch(&repo, ScanBatch::default())
            .await
            .expect("empty ingest");
        assert!(repo.scans.lock().unwrap().is_empty());
        assert!(repo.qr.lock().unwrap().is_empty());
    }
}
