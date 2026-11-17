//! Dated-obligation notices: the pass that announces, through the node's signed
//! webhooks and its event bus, the obligations dpp-core's calendar holds.
//!
//! | Variable                      | Values                          | Effect |
//! |-------------------------------|---------------------------------|--------|
//! | `OBLIGATION_NOTICES`          | unset / `on`                    | Whether to announce dated obligations (default: off) |
//! | `OBLIGATION_NOTICE_LEAD_DAYS` | comma-separated days, `90,30,7` | When to announce `dpp.obligation.upcoming` ahead of a date (default: `90,30,7`) |
//!
//! # What a pass does
//!
//! It asks the calendar in force what takes effect, and it announces each notice
//! that falls on a day from the node's first pass through today (UTC):
//!
//! - **`dpp.obligation.effective`** on the day an obligation takes effect;
//! - **`dpp.obligation.upcoming`** on each configured lead time before it.
//!
//! Every notice it announces is recorded in the ledger (migration `0050`), and
//! the webhook deliveries for it are queued in the same transaction. The record
//! is what keeps a notice to one announcement: a notice already in the ledger is
//! skipped, so a node that was down on the day announces it on restart, and two
//! instances over one database announce each notice once.
//!
//! # What it never does
//!
//! - **Announce an assumed date.** Only a date an adopted text fixes is a
//!   deadline. The calendar still returns the others, with their basis, for
//!   anyone reading it directly.
//! - **Announce history.** The first pass covers the day it runs on, and nothing
//!   earlier, so switching notices on does not replay the calendar.
//! - **Send an upcoming notice late.** An upcoming notice whose date has already
//!   been reached is not sent: the day itself announces the obligation, and a
//!   notice that it is still ahead would mislead.
//! - **Decide which law governs a passport.** The clock answers one question
//!   here, which UTC day it is. Every obligation the calendar holds binds
//!   products placed on the market from its date, so on the day it reaches no
//!   passport already published, and the payload carries no count of them.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{NaiveDate, NaiveTime, TimeZone, Utc};
use dpp_common::event::{DppEvent, EventBus, obligation_subject};
use dpp_domain::{
    DppError, InstrumentCatalog, ObligationCalendar, ObligationEvent, ScheduleBundleError,
};
use dpp_types::ObligationNoticeStore;
use dpp_types::STANDALONE_OPERATOR_ID;
use dpp_types::obligation_notice::{
    DEFAULT_LEAD_DAYS, NoticeRecord, NoticeSlot, notice_id, notice_slots,
};
use dpp_vault::state::ObligationSchedule;
use uuid::Uuid;

use crate::infra::ruleset::{ActiveRuleset, RulesetAcceptance};

/// The largest lead time accepted, in days. A century. Anything larger is
/// refused at boot, rather than silently producing no notice at all.
const MAX_LEAD_DAYS: u32 = 36_500;

/// Whether this node was asked to announce dated obligations.
///
/// Anything other than `on` is off, as for `TRUSTED_LIST_REFRESH`: a switch that
/// starts outbound traffic by accident is worse than one that does nothing.
#[must_use]
pub fn obligation_notices_enabled() -> bool {
    obligation_notices_enabled_from(std::env::var("OBLIGATION_NOTICES").ok().as_deref())
}

/// [`obligation_notices_enabled`] over a given value, so it is testable without
/// touching the process environment.
#[must_use]
pub fn obligation_notices_enabled_from(raw: Option<&str>) -> bool {
    raw.is_some_and(|v| v.trim().eq_ignore_ascii_case("on"))
}

/// The lead times from `OBLIGATION_NOTICE_LEAD_DAYS`, largest first.
///
/// # Errors
///
/// A value that is not a comma-separated list of whole days from 1 to
/// [`MAX_LEAD_DAYS`]. Zero is refused because the day itself is
/// `dpp.obligation.effective`'s.
pub fn lead_days() -> anyhow::Result<Vec<u32>> {
    lead_days_from(std::env::var("OBLIGATION_NOTICE_LEAD_DAYS").ok().as_deref())
}

/// [`lead_days`] over a given value.
///
/// # Errors
///
/// As [`lead_days`].
pub fn lead_days_from(raw: Option<&str>) -> anyhow::Result<Vec<u32>> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(DEFAULT_LEAD_DAYS.to_vec());
    };
    let mut days = raw
        .split(',')
        .map(|part| {
            let part = part.trim();
            let whole = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            match part.parse::<u32>() {
                Ok(d) if whole && (1..=MAX_LEAD_DAYS).contains(&d) => Ok(d),
                _ => Err(anyhow::anyhow!(
                    "OBLIGATION_NOTICE_LEAD_DAYS must list whole days from 1 to {MAX_LEAD_DAYS}, \
                     comma-separated (e.g. 90,30,7); got {part:?}"
                )),
            }
        })
        .collect::<anyhow::Result<Vec<u32>>>()?;
    days.sort_unstable_by(|a, b| b.cmp(a));
    days.dedup();
    Ok(days)
}

/// The calendar a node announces from: dpp-core's built-in calendar, with the
/// schedule of the signed ruleset in force laid over it when that carries one.
///
/// A baseline ruleset has no signature, so its schedule is never read and the
/// built-in calendar answers. A bundle whose schedule cannot be read is logged
/// and the built-in calendar answers, so one malformed bundle cannot stop the
/// node from announcing what its build knows.
#[must_use]
pub fn calendar_for(acceptance: &RulesetAcceptance) -> ObligationCalendar {
    let catalog = InstrumentCatalog::new();
    match ObligationCalendar::with_bundle(&catalog, acceptance) {
        Ok(calendar) => calendar,
        Err(ScheduleBundleError::Unverified { .. }) => ObligationCalendar::from_catalog(&catalog),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "the ruleset in force carries an obligations schedule that cannot be read; \
                 the built-in calendar is used"
            );
            ObligationCalendar::from_catalog(&catalog)
        }
    }
}

/// The obligation schedule a node reads from its ruleset in force.
pub struct RulesetObligationSchedule {
    ruleset: Arc<ActiveRuleset>,
    lead_days: Vec<u32>,
}

impl RulesetObligationSchedule {
    /// A schedule over `ruleset`, announcing at `lead_days`.
    #[must_use]
    pub fn new(ruleset: Arc<ActiveRuleset>, lead_days: Vec<u32>) -> Self {
        Self { ruleset, lead_days }
    }
}

impl ObligationSchedule for RulesetObligationSchedule {
    fn calendar(&self) -> ObligationCalendar {
        calendar_for(&self.ruleset.get())
    }

    fn lead_days(&self) -> Vec<u32> {
        self.lead_days.clone()
    }
}

/// One notice a pass announces: what the ledger records, and the event it is
/// delivered as.
#[derive(Debug, Clone)]
pub struct Notice {
    /// What the ledger records for it.
    pub record: NoticeRecord,
    /// The event published on the bus, whose serialisation is the record's body.
    pub event: DppEvent,
}

/// The notice for `event` at `slot`.
fn notice(event: &ObligationEvent, slot: NoticeSlot) -> Result<Notice, DppError> {
    let id = notice_id(event, slot.lead_days);
    let subject = obligation_subject(slot.lead_days);
    let mut data = serde_json::json!({ "obligation": event });
    if let Some(days) = slot.lead_days {
        data["leadDays"] = days.into();
    }
    let envelope = DppEvent {
        version: 1,
        event_id: id,
        event_type: subject.to_owned(),
        // The start of the notice day, not the moment of the pass: the body is
        // the same whichever instance builds it. Each delivery attempt still signs
        // its own sending time with it, so a retry's signature differs.
        timestamp: Utc.from_utc_datetime(&slot.day.and_time(NaiveTime::MIN)),
        operator_id: STANDALONE_OPERATOR_ID.to_owned(),
        data,
    };
    let body = serde_json::to_string(&envelope)
        .map_err(|e| DppError::Serialisation(format!("obligation notice: {e}")))?;
    Ok(Notice {
        record: NoticeRecord {
            notice_id: id,
            obligation_id: event.id.clone(),
            obligation_date: event.date,
            obligation_kind: event.kind,
            lead_days: slot.lead_days,
            notice_day: slot.day,
            basis: event.basis,
            event_type: subject.to_owned(),
            body,
        },
        event: envelope,
    })
}

/// Every notice of `calendar` due from `active_since` through `today`, both days
/// included, in the order a pass announces them: by day, then by obligation, and
/// for one obligation the shortest lead first.
///
/// Only a sourced date has notices. An upcoming notice is left out once its
/// obligation's date has been reached, as the module doc says.
///
/// # Errors
///
/// Serialising a notice, which does not fail for the calendar's own types.
pub fn due_notices(
    calendar: &ObligationCalendar,
    active_since: NaiveDate,
    today: NaiveDate,
    lead_days: &[u32],
) -> Result<Vec<Notice>, DppError> {
    let mut due = Vec::new();
    for event in calendar.events() {
        for slot in notice_slots(event, lead_days) {
            let upcoming_after_its_date = slot.lead_days.is_some() && event.date <= today;
            if upcoming_after_its_date || slot.day < active_since || slot.day > today {
                continue;
            }
            due.push(notice(event, slot)?);
        }
    }
    due.sort_by(|a, b| {
        a.record
            .notice_day
            .cmp(&b.record.notice_day)
            .then_with(|| a.record.obligation_id.cmp(&b.record.obligation_id))
            .then_with(|| a.record.lead_days.cmp(&b.record.lead_days))
    });
    Ok(due)
}

/// One pass: start the ledger if this is the first, record every due notice not
/// yet in it, and publish the ones this pass recorded.
///
/// Returns how many notices this pass recorded. A notice another pass recorded
/// first is not counted, and is not published here.
///
/// The publish follows the commit and is best-effort, as every event on this node
/// is: the ledger and the webhook queue are the record, and a failed publish is
/// logged rather than undone.
///
/// # Errors
///
/// The store's failure, in which case nothing was recorded or queued and the next
/// pass covers the same days.
pub async fn run_pass(
    store: &dyn ObligationNoticeStore,
    events: &dyn EventBus,
    calendar: &ObligationCalendar,
    today: NaiveDate,
    lead_days: &[u32],
) -> Result<usize, DppError> {
    for conflict in calendar.conflicts() {
        tracing::warn!(
            obligation = %conflict.id,
            build_date = %conflict.build_date,
            bundle_date = %conflict.bundle_date,
            bundle_version = %conflict.bundle.bundle_version,
            "a signed ruleset offers a different date for an obligation this build holds from \
             an adopted text; the build's date is the one announced"
        );
    }
    let active_since = store.ensure_active_since(today).await?;
    let due = due_notices(calendar, active_since, today, lead_days)?;
    let records: Vec<NoticeRecord> = due.iter().map(|n| n.record.clone()).collect();
    let recorded: HashSet<Uuid> = store.announce(&records).await?.into_iter().collect();
    let fresh: Vec<&Notice> = due
        .iter()
        .filter(|n| recorded.contains(&n.record.notice_id))
        .collect();
    for notice in &fresh {
        if let Err(e) = events.publish(&notice.event).await {
            tracing::warn!(
                event_type = %notice.event.event_type,
                event_id = %notice.event.event_id,
                error = %e,
                "failed to publish an obligation notice (non-fatal)"
            );
        }
    }
    Ok(fresh.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::{DateTime, Days};
    use dpp_common::event::NoOpEventBus;
    use dpp_domain::{DateBasis, InstrumentCatalog, ObligationDate, PassportObligation};
    use dpp_rules::bundle::JwsVerify;
    use dpp_types::AnnouncedNotice;
    use std::sync::Mutex;

    use crate::infra::ruleset::{
        AcceptancePolicy, RulesetError, RulesetManifest, SignedBundle, content_hash, verify_bundle,
    };

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    const DUE_DILIGENCE: &str = "battery.due-diligence-report";

    /// Notices as `(event type, obligation id, lead days, notice day)`.
    type Shape = (String, String, Option<u32>, NaiveDate);

    fn shape(notices: &[Notice]) -> Vec<Shape> {
        notices
            .iter()
            .map(|n| {
                (
                    n.record.event_type.clone(),
                    n.record.obligation_id.clone(),
                    n.record.lead_days,
                    n.record.notice_day,
                )
            })
            .collect()
    }

    fn expect(event_type: &str, id: &str, lead: Option<u32>, on: NaiveDate) -> Shape {
        (event_type.to_owned(), id.to_owned(), lead, on)
    }

    fn due(
        calendar: &ObligationCalendar,
        from: NaiveDate,
        to: NaiveDate,
        leads: &[u32],
    ) -> Vec<Notice> {
        due_notices(calendar, from, to, leads).unwrap()
    }

    #[test]
    fn the_switch_is_on_only_for_on() {
        assert!(!obligation_notices_enabled_from(None), "unset is off");
        assert!(obligation_notices_enabled_from(Some("on")));
        assert!(obligation_notices_enabled_from(Some(" ON ")));
        for off in ["", "off", "1", "true", "yes", "onn", "o n"] {
            assert!(
                !obligation_notices_enabled_from(Some(off)),
                "{off:?} is not `on`, and a near-miss must not start outbound traffic"
            );
        }
    }

    #[test]
    fn lead_days_parse_strictly_largest_first() {
        assert_eq!(lead_days_from(None).unwrap(), DEFAULT_LEAD_DAYS);
        assert_eq!(lead_days_from(Some("  ")).unwrap(), DEFAULT_LEAD_DAYS);
        assert_eq!(lead_days_from(Some("7, 30,30")).unwrap(), [30, 7]);
        assert_eq!(lead_days_from(Some("7,30,90")).unwrap(), [90, 30, 7]);
        for bad in ["0", "7,x", "-1", "7,,30", "+7", "7.5", "7,", "36501"] {
            assert!(
                lead_days_from(Some(bad)).is_err(),
                "{bad:?} must stop the boot"
            );
        }
    }

    #[test]
    fn an_upcoming_notice_is_sent_on_each_lead_day_and_the_day_itself() {
        let calendar = ObligationCalendar::new();
        // Due diligence takes effect 2027-08-18 (sourced).
        let from = day(2027, 5, 1);
        assert_eq!(
            shape(&due(&calendar, from, day(2027, 5, 20), &[90, 30, 7])),
            [expect(
                "dpp.obligation.upcoming",
                DUE_DILIGENCE,
                Some(90),
                day(2027, 5, 20)
            )]
        );
        assert!(due(&calendar, day(2027, 5, 21), day(2027, 7, 18), &[90, 30, 7]).is_empty());
        assert_eq!(
            shape(&due(
                &calendar,
                day(2027, 7, 19),
                day(2027, 7, 19),
                &[90, 30, 7]
            )),
            [expect(
                "dpp.obligation.upcoming",
                DUE_DILIGENCE,
                Some(30),
                day(2027, 7, 19)
            )]
        );
        let day_of = due(&calendar, day(2027, 8, 18), day(2027, 8, 18), &[90, 30, 7]);
        assert_eq!(
            shape(&day_of),
            [expect(
                "dpp.obligation.effective",
                DUE_DILIGENCE,
                None,
                day(2027, 8, 18)
            )]
        );
        assert!(
            !day_of[0].record.body.contains("\"leadDays\""),
            "the day itself carries no lead time"
        );
        assert_eq!(
            day_of[0].event.timestamp.to_rfc3339(),
            "2027-08-18T00:00:00+00:00"
        );
    }

    #[test]
    fn a_pass_that_was_down_announces_what_it_missed_but_not_stale_upcoming_notices() {
        // Down from 2027-07-01 to 2027-08-20: the 30- and 7-day notices fell in
        // the outage, and the day itself did too. Only the day is sent late.
        let calendar = ObligationCalendar::new();
        let got = due(&calendar, day(2027, 7, 1), day(2027, 8, 20), &[30, 7]);
        assert_eq!(
            shape(&got),
            [expect(
                "dpp.obligation.effective",
                DUE_DILIGENCE,
                None,
                day(2027, 8, 18)
            )],
            "a notice that the date is still ahead is not sent after the date"
        );
    }

    #[test]
    fn the_first_pass_covers_its_own_day_and_no_history() {
        let calendar = ObligationCalendar::new();
        // Switched on 2026-10-22: the lead restriction took effect in 2024, and
        // nothing is due on the first day.
        assert!(
            due(
                &calendar,
                day(2026, 10, 22),
                day(2026, 10, 22),
                &[90, 30, 7]
            )
            .is_empty()
        );
        let today = due(&calendar, day(2027, 8, 18), day(2027, 8, 18), &[]);
        assert_eq!(today.len(), 1);
    }

    #[test]
    fn an_assumed_date_is_never_announced() {
        let mut catalog = InstrumentCatalog::new();
        let mut assumed = catalog.get("toy-safety-2025-2509").unwrap().clone();
        assumed.id = "an-assumed-act".to_owned();
        assumed.passport = PassportObligation::Required {
            from: Some(ObligationDate {
                date: "2031-01-01".to_owned(),
                basis: DateBasis::Assumed,
            }),
        };
        for binding in &mut assumed.product_groups {
            binding.passport = None;
        }
        catalog.register(assumed).unwrap();
        let calendar = ObligationCalendar::from_catalog(&catalog);
        assert!(
            calendar
                .events()
                .iter()
                .any(|e| e.basis == DateBasis::Assumed),
            "the calendar still returns it"
        );
        let got = due(&calendar, day(2030, 1, 1), day(2031, 1, 1), &[30]);
        assert!(
            !shape(&got)
                .iter()
                .any(|(_, id, _, _)| id.starts_with("an-assumed-act")),
            "{:?}",
            shape(&got)
        );
    }

    /// Verify a bundle whose content is `content`, with a verifier that accepts
    /// any signature. The signature check is not what these tests are about; the
    /// content, and how the calendar reads it, is.
    fn verified(content: serde_json::Value) -> RulesetAcceptance {
        struct AcceptAll;
        impl JwsVerify for AcceptAll {
            fn verify_eddsa(&self, _: &str, _: &str) -> Result<bool, RulesetError> {
                Ok(true)
            }
        }
        use base64::Engine;
        let manifest = RulesetManifest {
            bundle_version: "2026-Q3.1".into(),
            effective_date: "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
            act_citations: vec![],
            schema_versions: Default::default(),
            content_sha256: content_hash(&content).unwrap(),
        };
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&manifest).unwrap());
        let bundle = SignedBundle {
            manifest_jws: format!("e30.{payload}.sig"),
            content,
        };
        let now: DateTime<Utc> = "2026-11-17T00:00:00Z".parse().unwrap();
        verify_bundle(
            &bundle,
            "publisher-key",
            &AcceptAll,
            &AcceptancePolicy {
                now,
                in_force: None,
            },
        )
        .unwrap()
    }

    fn unverified() -> RulesetAcceptance {
        RulesetAcceptance::unverified_baseline(
            RulesetManifest {
                bundle_version: "baseline".into(),
                effective_date: "2026-01-01T00:00:00Z".parse().unwrap(),
                act_citations: vec![],
                schema_versions: Default::default(),
                content_sha256: content_hash(&serde_json::json!({})).unwrap(),
            },
            serde_json::json!({}),
        )
    }

    #[test]
    fn a_baseline_that_was_never_verified_leaves_the_built_in_calendar() {
        let calendar = calendar_for(&unverified());
        assert_eq!(calendar, ObligationCalendar::new());
    }

    #[test]
    fn a_bundle_moving_a_sourced_date_is_a_conflict_and_the_build_keeps_its_date() {
        let content = serde_json::json!({ "obligations": [{
            "id": DUE_DILIGENCE,
            "date": "2027-09-01",
            "kind": "contentRequirement",
            "citation": "moved by a bundle",
            "summary": "moved by a bundle",
            "productGroup": "battery",
            "categories": [],
            "basis": "sourced",
        }]});
        let calendar = calendar_for(&verified(content));
        assert_eq!(calendar.conflicts().len(), 1);
        assert_eq!(calendar.conflicts()[0].build_date, day(2027, 8, 18));
        let kept = calendar
            .events()
            .iter()
            .find(|e| e.id == DUE_DILIGENCE)
            .unwrap();
        assert_eq!(
            kept.date,
            day(2027, 8, 18),
            "the build's sourced date is announced"
        );
    }

    #[test]
    fn a_bundle_adds_an_obligation_the_build_does_not_hold_with_its_origin() {
        let content = serde_json::json!({ "obligations": [{
            "id": "an-act-after-this-build",
            "date": "2027-03-03",
            "kind": "passportStart",
            "citation": "adopted after this build",
            "summary": "a passport from this date",
            "productGroup": null,
            "categories": [],
            "basis": "sourced",
        }]});
        let calendar = calendar_for(&verified(content));
        let added = calendar
            .events()
            .iter()
            .find(|e| e.id == "an-act-after-this-build")
            .expect("the bundle's date is added");
        assert_eq!(
            added.bundle.as_ref().map(|b| b.bundle_version.as_str()),
            Some("2026-Q3.1")
        );
        assert!(calendar.conflicts().is_empty());
    }

    #[test]
    fn a_malformed_schedule_is_refused_and_the_built_in_calendar_answers() {
        let content = serde_json::json!({ "obligations": [
            { "id": "dup", "date": "2027-03-03", "kind": "passportStart", "citation": "c",
              "summary": "s", "categories": [], "basis": "sourced" },
            { "id": "dup", "date": "2027-03-04", "kind": "passportStart", "citation": "c",
              "summary": "s", "categories": [], "basis": "sourced" },
        ]});
        let calendar = calendar_for(&verified(content));
        assert_eq!(
            calendar,
            ObligationCalendar::from_catalog(&InstrumentCatalog::new())
        );
    }

    /// A store in memory with the ledger's own rule: a notice is recorded once,
    /// and only a notice recorded by the call is returned.
    #[derive(Default)]
    struct MemoryStore {
        active_since: Mutex<Option<NaiveDate>>,
        ledger: Mutex<Vec<NoticeRecord>>,
        queued: Mutex<Vec<NoticeRecord>>,
    }

    #[async_trait]
    impl ObligationNoticeStore for MemoryStore {
        async fn ensure_active_since(&self, today: NaiveDate) -> Result<NaiveDate, DppError> {
            Ok(*self.active_since.lock().unwrap().get_or_insert(today))
        }
        async fn announce(&self, notices: &[NoticeRecord]) -> Result<Vec<Uuid>, DppError> {
            let mut ledger = self.ledger.lock().unwrap();
            let mut recorded = Vec::new();
            for n in notices {
                if ledger.iter().any(|l| l.notice_id == n.notice_id) {
                    continue;
                }
                ledger.push(n.clone());
                self.queued.lock().unwrap().push(n.clone());
                recorded.push(n.notice_id);
            }
            Ok(recorded)
        }
        async fn announced(
            &self,
            _: NaiveDate,
            _: NaiveDate,
        ) -> Result<Vec<AnnouncedNotice>, DppError> {
            Ok(Vec::new())
        }
    }

    /// Counts the events published on the bus.
    #[derive(Default)]
    struct CountingBus(Mutex<Vec<String>>);

    #[async_trait]
    impl EventBus for CountingBus {
        async fn publish(&self, event: &DppEvent) -> Result<(), dpp_common::event::EventBusError> {
            self.0.lock().unwrap().push(event.event_type.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_restart_announces_the_missed_day_once() {
        let store = MemoryStore::default();
        let calendar = ObligationCalendar::new();
        let bus = CountingBus::default();
        let pass = |today| run_pass(&store, &bus, &calendar, today, &[]);

        assert_eq!(pass(day(2027, 8, 10)).await.unwrap(), 0);
        // Down from the 11th to the 19th: the day itself was missed.
        assert_eq!(pass(day(2027, 8, 20)).await.unwrap(), 1);
        assert_eq!(
            pass(day(2027, 8, 20)).await.unwrap(),
            0,
            "a second pass the same day is a no-op"
        );
        assert_eq!(pass(day(2027, 8, 21)).await.unwrap(), 0);
        assert_eq!(*bus.0.lock().unwrap(), ["dpp.obligation.effective"]);
        assert_eq!(
            store.queued.lock().unwrap().len(),
            1,
            "queued once, not per pass"
        );
    }

    /// A calendar of one act's passport date, `id` taking effect on `date`.
    fn one_act_on(id: &str, date: &str) -> ObligationCalendar {
        let mut catalog = InstrumentCatalog::new();
        let mut act = catalog.get("toy-safety-2025-2509").unwrap().clone();
        act.id = id.to_owned();
        act.passport = PassportObligation::Required {
            from: Some(ObligationDate {
                date: date.to_owned(),
                basis: DateBasis::Sourced,
            }),
        };
        for binding in &mut act.product_groups {
            binding.passport = None;
        }
        catalog.register(act).unwrap();
        ObligationCalendar::from_catalog(&catalog)
    }

    #[tokio::test]
    async fn an_obligation_added_behind_the_last_pass_is_still_announced() {
        let store = MemoryStore::default();
        let bus = NoOpEventBus;
        run_pass(
            &store,
            &bus,
            &ObligationCalendar::new(),
            day(2027, 8, 10),
            &[],
        )
        .await
        .unwrap();

        // A later release adds an act dated 2027-08-15: behind the pass that runs
        // on the 20th, but on or after the day the ledger started from. The 18th
        // also falls in the outage, so the pass announces that day too.
        let later = one_act_on("added-after-the-last-pass", "2027-08-15");
        assert_eq!(
            run_pass(&store, &bus, &later, day(2027, 8, 20), &[])
                .await
                .unwrap(),
            2
        );
        // A catalog act with product-group bindings names its date per group, so
        // its id carries the group after the act's own id.
        assert!(
            store
                .ledger
                .lock()
                .unwrap()
                .iter()
                .any(|n| n.obligation_id.starts_with("added-after-the-last-pass")),
            "the added act's date is recorded"
        );
    }

    #[tokio::test]
    async fn a_postponed_date_is_announced_under_its_new_date() {
        let store = MemoryStore::default();
        let bus = NoOpEventBus;
        // The 18th has the battery's due-diligence notice as well as this act's.
        let first = one_act_on("postponed", "2027-08-18");
        assert_eq!(
            run_pass(&store, &bus, &first, day(2027, 8, 18), &[])
                .await
                .unwrap(),
            2
        );

        // The same obligation, moved to the 25th by a later build.
        let moved = one_act_on("postponed", "2027-08-25");
        assert_eq!(
            run_pass(&store, &bus, &moved, day(2027, 8, 25), &[])
                .await
                .unwrap(),
            1,
            "the new date is a new notice, announced on its own day"
        );
        let ledger = store.ledger.lock().unwrap();
        let ids: HashSet<Uuid> = ledger.iter().map(|n| n.notice_id).collect();
        assert_eq!(ids.len(), ledger.len(), "each date is its own notice");
    }

    #[tokio::test]
    async fn a_pass_that_lost_the_race_publishes_nothing() {
        let store = MemoryStore::default();
        let calendar = ObligationCalendar::new();
        // The other instance recorded the 18th's notice first.
        let theirs = due(&calendar, day(2027, 8, 18), day(2027, 8, 18), &[]);
        store.announce(&[theirs[0].record.clone()]).await.unwrap();
        let bus = CountingBus::default();
        assert_eq!(
            run_pass(&store, &bus, &calendar, day(2027, 8, 18), &[])
                .await
                .unwrap(),
            0
        );
        assert!(bus.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_later_pass_recomputes_the_same_ids_and_bodies() {
        let calendar = ObligationCalendar::new();
        let a = due(&calendar, day(2027, 7, 1), day(2027, 8, 12), &[30, 7]);
        let b = due(&calendar, day(2027, 7, 1), day(2027, 8, 12), &[30, 7]);
        assert_eq!(a.len(), 2, "the 30- and 7-day notices");
        assert_eq!(
            a.iter().map(|n| n.record.notice_id).collect::<Vec<_>>(),
            b.iter().map(|n| n.record.notice_id).collect::<Vec<_>>(),
            "the same window gives the same ids"
        );
        assert_eq!(
            a.iter().map(|n| n.record.body.clone()).collect::<Vec<_>>(),
            b.iter().map(|n| n.record.body.clone()).collect::<Vec<_>>(),
            "and byte-identical bodies"
        );
        assert_eq!(
            day(2027, 8, 18).checked_sub_days(Days::new(7)),
            Some(day(2027, 8, 11))
        );
    }
}
