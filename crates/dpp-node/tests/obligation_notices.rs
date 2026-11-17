//! Two node instances over one database announce each dated obligation once.
//!
//! The unit tests of the notice pass run it against an in-memory ledger. This
//! one runs the real pass over the real ledger and webhook queue, with two
//! instances racing on the same day, which only PostgreSQL can make the
//! claim about.

#![cfg(feature = "integration-tests")]

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::NaiveDate;
use dpp_common::event::{DppEvent, EventBus, EventBusError};
use dpp_dal::pg::{PgObligationNoticeRepo, PgWebhookRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::ObligationCalendar;
use dpp_node::infra::obligation_notices::run_pass;
use dpp_types::{
    CreateWebhookRequest, ObligationNoticeStore, WebhookOutbox, WebhookSubscriptionStore,
};

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

/// Records the subjects it was asked to publish.
#[derive(Default)]
struct RecordingBus(Mutex<Vec<String>>);

#[async_trait]
impl EventBus for RecordingBus {
    async fn publish(&self, event: &DppEvent) -> Result<(), EventBusError> {
        self.0.lock().unwrap().push(event.event_type.clone());
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_instances_over_one_database_announce_each_notice_once() {
    let pg = start_pg().await;
    let webhooks = PgWebhookRepo::new(pg.dal.clone());
    webhooks
        .create(
            &CreateWebhookRequest {
                url: "https://receiver.example/hook".into(),
                events: vec!["*".into()],
                description: None,
            },
            "whsec_test",
        )
        .await
        .expect("create subscription");

    // The ledger began in May. On 20 July the battery due-diligence report,
    // which takes effect on 18 August, has its 90-day notice (20 May, already
    // due) and its 30-day notice (19 July) to announce.
    let first = PgObligationNoticeRepo::new(pg.dal.clone());
    let second = PgObligationNoticeRepo::new(pg.dal.clone());
    first
        .ensure_active_since(day(2027, 5, 1))
        .await
        .expect("start the ledger");

    let calendar = ObligationCalendar::new();
    let bus_a = RecordingBus::default();
    let bus_b = RecordingBus::default();
    let today = day(2027, 7, 20);
    let (a, b) = tokio::join!(
        run_pass(&first, &bus_a, &calendar, today, &[90, 30, 7]),
        run_pass(&second, &bus_b, &calendar, today, &[90, 30, 7]),
    );

    assert_eq!(
        a.unwrap() + b.unwrap(),
        2,
        "the two notices are recorded between the two instances, not twice"
    );
    assert_eq!(
        bus_a.0.lock().unwrap().len() + bus_b.0.lock().unwrap().len(),
        2,
        "and each is published by the instance that recorded it"
    );
    assert_eq!(
        webhooks.due(10).await.unwrap().len(),
        2,
        "and each is queued for delivery once"
    );

    // A pass later the same day finds both already recorded.
    assert_eq!(
        run_pass(&first, &bus_a, &calendar, today, &[90, 30, 7])
            .await
            .unwrap(),
        0
    );
    assert_eq!(webhooks.due(10).await.unwrap().len(), 2);
}
