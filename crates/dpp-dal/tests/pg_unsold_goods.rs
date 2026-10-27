//! `PgUnsoldGoodsRepo`: one disclosure per financial year.

#![cfg(feature = "integration-tests")]

use chrono::NaiveDate;

use dpp_dal::pg::PgUnsoldGoodsRepo;
use dpp_dal::test_harness::start_pg;
use dpp_domain::UnsoldGoodsReport;
use dpp_types::UnsoldGoodsStore;

fn report() -> UnsoldGoodsReport {
    serde_json::from_str(include_str!("fixtures/unsold_goods/report.json"))
        .expect("the fixture is a report")
}

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("a valid date")
}

/// A report reads back as it was stored, under the year it covers.
#[tokio::test]
async fn a_stored_report_reads_back_whole() {
    let pg = start_pg().await;
    let store = PgUnsoldGoodsRepo::new(pg.dal.clone());

    let stored = store.put(&report(), "ops-user").await.expect("put");
    assert_eq!(stored.report, report());
    assert_eq!(stored.recorded_by, "ops-user");

    let read = store
        .get(day(2027, 1, 1))
        .await
        .expect("get")
        .expect("the year is stored");
    assert_eq!(read.report, report());
    assert!(store.get(day(2026, 1, 1)).await.expect("get").is_none());
}

/// Recording a year again replaces it rather than adding a second disclosure.
#[tokio::test]
async fn recording_a_year_again_replaces_it() {
    let pg = start_pg().await;
    let store = PgUnsoldGoodsRepo::new(pg.dal.clone());

    let first = store.put(&report(), "ops-user").await.expect("first put");
    let mut corrected = report();
    corrected.measures_planned = "Extending the donation offer window to sixteen weeks.".into();
    let second = store.put(&corrected, "auditor").await.expect("second put");

    assert_eq!(second.report, corrected);
    assert_eq!(second.recorded_by, "auditor");
    assert_eq!(
        second.created_at, first.created_at,
        "the year keeps its first record time"
    );
    assert!(second.updated_at >= first.updated_at);
    assert_eq!(store.list().await.expect("list").len(), 1);
}

/// The listing puts the latest financial year first.
#[tokio::test]
async fn the_latest_year_is_listed_first() {
    let pg = start_pg().await;
    let store = PgUnsoldGoodsRepo::new(pg.dal.clone());

    let mut earlier = report();
    earlier.financial_year.start = day(2026, 1, 1);
    earlier.financial_year.end = day(2026, 12, 31);
    store.put(&earlier, "ops-user").await.expect("put 2026");
    store.put(&report(), "ops-user").await.expect("put 2027");

    let years: Vec<NaiveDate> = store
        .list()
        .await
        .expect("list")
        .iter()
        .map(|d| d.report.financial_year.start)
        .collect();
    assert_eq!(years, [day(2027, 1, 1), day(2026, 1, 1)]);
}

/// The table refuses a year that does not end after it starts.
#[tokio::test]
async fn a_year_that_ends_before_it_starts_is_refused() {
    let pg = start_pg().await;
    let store = PgUnsoldGoodsRepo::new(pg.dal.clone());

    let mut backwards = report();
    backwards.financial_year.end = day(2026, 12, 31);
    assert!(store.put(&backwards, "ops-user").await.is_err());
}
