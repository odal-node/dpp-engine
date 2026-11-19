//! `GET /api/v1/obligations?from=&to=` over real HTTP and PostgreSQL.
//!
//! Three claims: a window answers with each notice of the obligations dated in
//! it, and whether the ledger holds that notice and when; a window that is not an
//! ordered window of ISO dates, or is wider than the route allows, is refused
//! with `422`; and a key with the read scope may read it, since it changes
//! nothing.

#![cfg(feature = "integration-tests")]

mod helpers;

use chrono::NaiveDate;
use dpp_dal::pg::PgObligationNoticeRepo;
use dpp_domain::ObligationCalendar;
use dpp_types::obligation_notice::notice_id;
use dpp_types::{NoticeRecord, ObligationNoticeStore};
use helpers::{TestClient, make_jwt, make_jwt_scoped, start_postgres, start_vault};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

/// Record the battery due-diligence report's 90-day notice, as a pass run on the
/// 20th of May 2027 would have.
async fn record_the_ninety_day_notice(ledger: &PgObligationNoticeRepo) {
    let event = ObligationCalendar::new()
        .events()
        .iter()
        .find(|e| e.id == "battery.due-diligence-report")
        .expect("the calendar holds the battery due-diligence report")
        .clone();
    ledger
        .announce(&[NoticeRecord {
            notice_id: notice_id(&event, Some(90)),
            obligation_id: event.id.clone(),
            obligation_date: event.date,
            obligation_kind: event.kind,
            lead_days: Some(90),
            notice_day: day(2027, 5, 20),
            basis: event.basis,
            event_type: "dpp.obligation.upcoming".to_owned(),
            body: "{}".to_owned(),
        }])
        .await
        .expect("record the notice");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_window_lists_each_notice_of_its_obligations_and_whether_the_ledger_holds_it() {
    let pg = start_postgres().await;
    record_the_ninety_day_notice(&PgObligationNoticeRepo::new(pg.dal.clone())).await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .get("/api/v1/obligations?from=2027-08-01&to=2027-08-31")
        .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["from"], "2027-08-01");
    assert_eq!(body["to"], "2027-08-31");
    assert_eq!(body["conflicts"], serde_json::json!([]));

    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "one obligation takes effect in August");
    let due = &events[0];
    assert_eq!(due["id"], "battery.due-diligence-report");
    assert_eq!(due["date"], "2027-08-18");
    assert_eq!(due["basis"], "sourced");
    assert_eq!(due["productGroup"], "battery");

    // The 90-, 30- and 7-day notices and the day itself, earliest first. Only the
    // first is in the ledger.
    let notices = due["notices"].as_array().unwrap();
    let shown: Vec<(&str, bool)> = notices
        .iter()
        .map(|n| {
            (
                n["noticeDay"].as_str().unwrap(),
                n["announced"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        shown,
        [
            ("2027-05-20", true),
            ("2027-07-19", false),
            ("2027-08-11", false),
            ("2027-08-18", false),
        ]
    );
    assert_eq!(notices[0]["leadDays"], 90);
    assert_eq!(notices[0]["eventType"], "dpp.obligation.upcoming");
    assert!(
        notices[0]["announcedAt"].is_string(),
        "an announced notice says when"
    );
    assert!(notices[1]["announcedAt"].is_null());
    assert!(
        notices[3].get("leadDays").is_none(),
        "the day itself has no lead time"
    );
    assert_eq!(notices[3]["eventType"], "dpp.obligation.effective");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_window_that_is_not_an_ordered_window_of_iso_dates_is_refused() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    for refused in [
        "/api/v1/obligations",
        "/api/v1/obligations?from=2027-08-01",
        "/api/v1/obligations?to=2027-08-31",
        "/api/v1/obligations?from=01-08-2027&to=2027-08-31",
        "/api/v1/obligations?from=2027-08-01&to=2027-02-30",
        "/api/v1/obligations?from=2027-08-31&to=2027-08-01",
        "/api/v1/obligations?from=2016-01-01&to=2027-01-02",
    ] {
        let resp = client.get(refused).await;
        assert_eq!(resp.status(), 422, "{refused} is not a window");
        let problem: serde_json::Value = resp.json().await.unwrap();
        assert!(
            problem["detail"].is_string(),
            "{refused} says why, as a problem document"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_window_of_3660_days_is_answered_and_one_more_day_is_not() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let from = day(2026, 1, 1);
    let widest = from.checked_add_days(chrono::Days::new(3660)).unwrap();
    let too_wide = from.checked_add_days(chrono::Days::new(3661)).unwrap();
    let ok = client
        .get(&format!("/api/v1/obligations?from={from}&to={widest}"))
        .await;
    assert_eq!(ok.status(), 200);
    let refused = client
        .get(&format!("/api/v1/obligations?from={from}&to={too_wide}"))
        .await;
    assert_eq!(refused.status(), 422);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_with_the_read_scope_may_read_the_calendar() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt_scoped(&op(), "read"));

    let resp = client
        .get("/api/v1/obligations?from=2027-08-01&to=2027-08-31")
        .await;
    assert_eq!(
        resp.status(),
        200,
        "a read changes nothing, so any scope may make it"
    );
}
