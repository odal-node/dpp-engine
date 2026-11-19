//! Postgres-backed tests for the dated-obligation ledger (`ops/pg/0050`).
//!
//! The claims here are about the database, which a unit test cannot make:
//!
//! 1. **A notice is queued once.** Two instances that record the same notice
//!    race on its primary key, and only the one that inserted it queues it.
//! 2. **Recording and queueing are one transaction.** A notice that is recorded
//!    without its deliveries would never be sent; deliveries without the record
//!    would be sent again on the next pass.
//! 3. **The ledger is append-only.** A notice cannot be rewritten or removed, by
//!    the app role or by the owner.
//! 4. **Only a sourced date and a consistent notice day can be recorded.**

#![cfg(feature = "integration-tests")]

use chrono::{DateTime, NaiveDate, Utc};
use dpp_dal::pg::{PgObligationNoticeRepo, PgWebhookRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::{DateBasis, ObligationCalendar, ObligationEvent};
use dpp_types::obligation_notice::notice_id;
use dpp_types::{
    CreateWebhookRequest, NoticeRecord, ObligationNoticeStore, WebhookOutbox,
    WebhookSubscriptionStore,
};

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

/// The calendar's own event for the battery due-diligence report.
fn due_diligence() -> ObligationEvent {
    ObligationCalendar::new()
        .events()
        .iter()
        .find(|e| e.id == "battery.due-diligence-report")
        .expect("the calendar holds the battery due-diligence report")
        .clone()
}

/// The record a pass would write for `event` at `lead` (`None` for the day).
fn record(event: &ObligationEvent, lead: Option<u32>, notice_day: NaiveDate) -> NoticeRecord {
    let subject = if lead.is_some() {
        "dpp.obligation.upcoming"
    } else {
        "dpp.obligation.effective"
    };
    NoticeRecord {
        notice_id: notice_id(event, lead),
        obligation_id: event.id.clone(),
        obligation_date: event.date,
        obligation_kind: event.kind,
        lead_days: lead,
        notice_day,
        basis: event.basis,
        event_type: subject.to_owned(),
        body: format!(r#"{{"eventType":"{subject}","leadDays":{lead:?}}}"#),
    }
}

async fn subscribe(store: &PgWebhookRepo, events: &[&str]) {
    store
        .create(
            &CreateWebhookRequest {
                url: "https://receiver.example/hook".into(),
                events: events.iter().map(|e| (*e).to_owned()).collect(),
                description: None,
            },
            // A fresh secret per run: no secret is written into the source, tests
            // included.
            &format!("whsec_{}", uuid::Uuid::now_v7().simple()),
        )
        .await
        .expect("create subscription");
}

#[tokio::test]
async fn a_recorded_notice_is_queued_for_each_matching_subscription_and_not_again() {
    let pg = start_pg().await;
    let ledger = PgObligationNoticeRepo::new(pg.dal.clone());
    let webhooks = PgWebhookRepo::new(pg.dal.clone());
    subscribe(&webhooks, &["*"]).await;
    subscribe(&webhooks, &["dpp.obligation.effective"]).await;
    subscribe(&webhooks, &["dpp.passport.published"]).await;

    let event = due_diligence();
    let effective = record(&event, None, day(2027, 8, 18));
    let upcoming = record(&event, Some(7), day(2027, 8, 11));
    let recorded = ledger
        .announce(&[effective.clone(), upcoming.clone()])
        .await
        .unwrap();
    assert_eq!(recorded.len(), 2);
    // The wildcard takes both; the exact effective filter takes the day itself;
    // the passport filter takes neither.
    assert_eq!(webhooks.due(10).await.unwrap().len(), 3);

    let again = ledger.announce(&[effective, upcoming]).await.unwrap();
    assert!(
        again.is_empty(),
        "a notice already recorded is not recorded again"
    );
    assert_eq!(
        webhooks.due(10).await.unwrap().len(),
        3,
        "and nothing is queued a second time"
    );
}

#[tokio::test]
async fn two_instances_racing_to_record_one_notice_queue_it_once() {
    let pg = start_pg().await;
    let a = PgObligationNoticeRepo::new(pg.dal.clone());
    let b = PgObligationNoticeRepo::new(pg.dal.clone());
    let webhooks = PgWebhookRepo::new(pg.dal.clone());
    subscribe(&webhooks, &["*"]).await;

    let notice = [record(&due_diligence(), None, day(2027, 8, 18))];
    let (left, right) = tokio::join!(a.announce(&notice), b.announce(&notice));
    let won = left.unwrap().len() + right.unwrap().len();
    assert_eq!(won, 1, "exactly one instance records the notice");
    assert_eq!(
        webhooks.due(10).await.unwrap().len(),
        1,
        "and one delivery is queued"
    );
}

#[tokio::test]
async fn the_first_pass_day_is_written_once_and_read_back_by_every_later_pass() {
    let pg = start_pg().await;
    let ledger = PgObligationNoticeRepo::new(pg.dal.clone());

    assert_eq!(
        ledger.ensure_active_since(day(2027, 5, 1)).await.unwrap(),
        day(2027, 5, 1)
    );
    assert_eq!(
        ledger.ensure_active_since(day(2027, 8, 18)).await.unwrap(),
        day(2027, 5, 1),
        "a later pass reads the day the first one wrote"
    );
}

#[tokio::test]
async fn a_recorded_notice_cannot_be_rewritten_or_removed() {
    let pg = start_pg().await;
    let ledger = PgObligationNoticeRepo::new(pg.dal.clone());
    let notice = record(&due_diligence(), None, day(2027, 8, 18));
    ledger
        .announce(std::slice::from_ref(&notice))
        .await
        .unwrap();

    // The owner, past the app role's grants, is still stopped by the trigger.
    let admin = sqlx::PgPool::connect(&pg.admin_url).await.unwrap();
    let rewrite = sqlx::query("UPDATE odal.obligation_notice SET body = 'changed'")
        .execute(&admin)
        .await
        .expect_err("an announced notice is append-only");
    assert!(rewrite.to_string().contains("append-only"), "{rewrite}");
    let removal = sqlx::query("DELETE FROM odal.obligation_notice")
        .execute(&admin)
        .await
        .expect_err("an announced notice is append-only");
    assert!(removal.to_string().contains("append-only"), "{removal}");

    // And the app role has no UPDATE or DELETE to begin with.
    assert!(
        sqlx::query("DELETE FROM odal.obligation_notice")
            .execute(pg.dal.pool())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_assumed_date_or_an_inconsistent_notice_day_is_not_recorded() {
    let pg = start_pg().await;
    let ledger = PgObligationNoticeRepo::new(pg.dal.clone());

    let mut assumed = record(&due_diligence(), None, day(2027, 8, 18));
    assumed.basis = DateBasis::Assumed;
    assert!(
        ledger.announce(&[assumed]).await.is_err(),
        "a date no adopted text fixes is never announced"
    );

    // An upcoming notice must fall on its lead time before the date, not any day.
    let wrong_day = record(&due_diligence(), Some(7), day(2027, 8, 12));
    assert!(ledger.announce(&[wrong_day]).await.is_err());

    assert!(
        ledger
            .announced(day(2000, 1, 1), day(2100, 1, 1))
            .await
            .unwrap()
            .is_empty(),
        "a refused notice leaves nothing behind"
    );
}

#[tokio::test]
async fn announced_reports_the_notices_of_obligations_dated_in_the_window() {
    let pg = start_pg().await;
    let ledger = PgObligationNoticeRepo::new(pg.dal.clone());
    let event = due_diligence();
    let upcoming = record(&event, Some(90), day(2027, 5, 20));
    let effective = record(&event, None, day(2027, 8, 18));
    ledger
        .announce(&[upcoming.clone(), effective.clone()])
        .await
        .unwrap();

    // Both notices belong to an obligation dated 18 August, so a window that holds
    // that date returns both, the earlier notice first.
    let within = ledger
        .announced(day(2027, 8, 1), day(2027, 12, 31))
        .await
        .unwrap();
    assert_eq!(within.len(), 2);
    assert_eq!(within[0].notice_id, upcoming.notice_id);
    assert_eq!(within[0].lead_days, Some(90));
    assert_eq!(within[0].notice_day, day(2027, 5, 20));
    assert_eq!(within[1].notice_id, effective.notice_id);
    assert_eq!(within[1].lead_days, None);
    assert_eq!(within[1].notice_day, day(2027, 8, 18));
    assert_eq!(within[1].obligation_date, day(2027, 8, 18));
    let at: DateTime<Utc> = within[1].announced_at;
    assert!(at <= Utc::now(), "the ledger's own clock stamps the row");

    assert!(
        ledger
            .announced(day(2027, 8, 19), day(2027, 12, 31))
            .await
            .unwrap()
            .is_empty(),
        "a window that starts after the obligation's date holds none of its notices"
    );
}
