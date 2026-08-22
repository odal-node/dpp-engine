//! Integration test: `PgJobStore` lifecycle against a real PostgreSQL instance.
//!
//! Guards the bug where `insert()` omitted the required `operatorId` field, so
//! the job record never persisted and import-job status returned `404` forever.
//! The node smoke test uses `InMemoryJobStore`, so this is the only place the
//! *production* store is exercised end to end.
//!
//! Run: `cargo test -p dpp-node --features integration-tests`

#![cfg(feature = "integration-tests")]

use uuid::Uuid;

use dpp_dal::test_harness::start_pg;
use dpp_integrator::{
    domain::batch_runner::{BatchResult, CreatedItem, RowError},
    domain::import_report::{FindingKind, ImportMode, ImportReport, ReportRow, RowFinding},
    infra::job_store::{ImportJob, JobStatus, JobStore},
};
use dpp_node::infra::pg_job_store::PgJobStore;

#[tokio::test(flavor = "multi_thread")]
async fn job_lifecycle_persists_and_is_retrievable() {
    let _container = start_pg().await;
    let dal = _container.dal.clone();
    let store = PgJobStore::new(dal);

    let id = Uuid::now_v7();

    store
        .insert(ImportJob::new(id, 150))
        .await
        .expect("insert must persist the job");

    let job = store
        .get(id)
        .await
        .expect("job retrievable right after insert");
    assert!(matches!(job.status, JobStatus::Queued));
    assert_eq!(job.total_rows, 150);

    store
        .set_status(id, JobStatus::Processing)
        .await
        .expect("set processing");
    assert!(matches!(
        store.get(id).await.unwrap().status,
        JobStatus::Processing
    ));

    let batch = BatchResult {
        created: vec![CreatedItem {
            row: 1,
            passport_id: Uuid::now_v7().to_string(),
        }],
        updated: vec![],
        errors: vec![RowError {
            row: 2,
            field: "gtin".into(),
            message: "O'Brien said \"invalid\"".into(),
        }],
    };
    store.complete(id, batch).await.expect("complete job");

    let done = store.get(id).await.expect("completed job retrievable");
    assert!(matches!(done.status, JobStatus::Completed));
    assert_eq!(done.processed, 150);
    let result = done.result.expect("result populated on completion");
    assert_eq!(result.created.len(), 1);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(
        result.errors[0].message, "O'Brien said \"invalid\"",
        "error message must survive SQL round-trip intact"
    );

    assert!(store.get(Uuid::now_v7()).await.is_none());
}

// A dry-run job never calls `complete` (there is no `BatchResult` without a
// vault call) — `record_report` is its only persistence path, and must
// round-trip through real Postgres independent of `result`.
#[tokio::test(flavor = "multi_thread")]
async fn record_report_persists_and_survives_sql_round_trip() {
    let _container = start_pg().await;
    let dal = _container.dal.clone();
    let store = PgJobStore::new(dal);

    let id = Uuid::now_v7();
    store.insert(ImportJob::new(id, 2)).await.expect("insert");

    let report = ImportReport {
        mode: ImportMode::DryRun,
        total_rows: 2,
        rows: vec![
            ReportRow {
                row: 1,
                valid: true,
                action: Some(dpp_integrator::domain::matcher::RowAction::Create),
                existing_passport_id: None,
                findings: vec![],
            },
            ReportRow {
                row: 2,
                valid: false,
                action: None,
                existing_passport_id: None,
                findings: vec![RowFinding {
                    kind: FindingKind::Validation,
                    field: "gtin".into(),
                    message: "O'Brien said \"invalid\"".into(),
                    severity: None,
                }],
            },
        ],
    };
    store
        .record_report(id, report)
        .await
        .expect("record_report must persist");

    let job = store.get(id).await.expect("job retrievable");
    assert!(
        job.result.is_none(),
        "record_report must not touch the unrelated `result` column"
    );
    assert!(
        matches!(job.status, JobStatus::Queued),
        "record_report must not change status"
    );
    let report = job.report.expect("report populated");
    assert!(matches!(report.mode, ImportMode::DryRun));
    assert_eq!(report.rows.len(), 2);
    assert!(report.rows[0].valid);
    assert!(!report.rows[1].valid);
    assert_eq!(
        report.rows[1].findings[0].message, "O'Brien said \"invalid\"",
        "finding message must survive SQL round-trip intact"
    );
}
