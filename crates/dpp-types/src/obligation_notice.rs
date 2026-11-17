//! Dated-obligation notices: the identity of each notice, and the ledger a node
//! records what it has announced in.
//!
//! dpp-core's obligation calendar says which dated obligations take effect on a
//! day. A node announces each one through its signed webhooks, on the day and at
//! configured lead times before it. Announcing once when several instances share
//! one database needs a record the calendar cannot hold, because it is this
//! deployment's state rather than the law's:
//!
//! - **a ledger** with one row per announced notice, keyed by the notice id. The
//!   primary key is what gives once-only delivery: an instance that tries to
//!   record a notice another instance already recorded inserts nothing, and so
//!   enqueues nothing;
//! - **a singleton** holding the first day a notice pass covers, so that switching
//!   notices on does not replay the calendar's history.
//!
//! The notice id is a name-based UUID of the obligation, its date, its kind and
//! its lead time. A postponed date is a new name, so it is announced again.

use async_trait::async_trait;
use chrono::{DateTime, Days, NaiveDate, Utc};
use dpp_domain::{DateBasis, DppError, ObligationEvent, ObligationKind};
use serde::Serialize;
use uuid::Uuid;

/// The lead times, in days, a node announces at when `OBLIGATION_NOTICE_LEAD_DAYS`
/// is unset.
pub const DEFAULT_LEAD_DAYS: &[u32] = &[90, 30, 7];

/// Namespace of the notice ids. Fixed, so an id derived by this release is the
/// same id a later release derives for the same notice.
const NOTICE_NAMESPACE: Uuid = Uuid::from_u128(0xd5bd_488c_c1d5_424a_b292_c236_f888_9606);

/// The wire name of a serialisable unit variant, as the webhook payload and the
/// API spell it (`passportStart`, `sourced`).
fn wire_name<T: Serialize + std::fmt::Debug>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{value:?}"))
}

/// The wire name of an obligation kind, as the ledger stores it.
#[must_use]
pub fn kind_name(kind: ObligationKind) -> String {
    wire_name(&kind)
}

/// The wire name of a date basis, as the ledger stores it.
#[must_use]
pub fn basis_name(basis: DateBasis) -> String {
    wire_name(&basis)
}

/// The identity of one notice: the obligation, the day it takes effect, its kind
/// and the lead time it is announced at (`None` for the day itself).
///
/// The same notice always has the same id, on any instance and in any release
/// that uses this scheme, so a redelivery is recognisable and a second instance
/// cannot record it twice.
#[must_use]
pub fn notice_id(event: &ObligationEvent, lead_days: Option<u32>) -> Uuid {
    let lead = lead_days.map_or_else(|| "effective".to_owned(), |d| format!("upcoming-{d}"));
    let name = format!(
        "{}|{}|{}|{lead}",
        event.id,
        event.date,
        kind_name(event.kind)
    );
    Uuid::new_v5(&NOTICE_NAMESPACE, name.as_bytes())
}

/// One notice an obligation gives rise to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoticeSlot {
    /// The day the notice is due.
    pub day: NaiveDate,
    /// The lead time it is announced at, or `None` for the day the obligation
    /// takes effect.
    pub lead_days: Option<u32>,
}

/// The notices an event gives rise to, earliest first: the day it takes effect,
/// and one for each lead time, `day` being that many days before it.
///
/// Nothing for a date that is not [`DateBasis::Sourced`]. An assumed date is never
/// announced, so it has no notice to name.
#[must_use]
pub fn notice_slots(event: &ObligationEvent, lead_days: &[u32]) -> Vec<NoticeSlot> {
    if event.basis != DateBasis::Sourced {
        return Vec::new();
    }
    let mut slots: Vec<NoticeSlot> = lead_days
        .iter()
        .filter_map(|&days| {
            event
                .date
                .checked_sub_days(Days::new(u64::from(days)))
                .map(|day| NoticeSlot {
                    day,
                    lead_days: Some(days),
                })
        })
        .collect();
    slots.push(NoticeSlot {
        day: event.date,
        lead_days: None,
    });
    slots.sort_by_key(|slot| slot.day);
    slots
}

/// One notice a pass has decided to announce, ready to be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeRecord {
    /// The notice's id, from [`notice_id`].
    pub notice_id: Uuid,
    /// The obligation's id, as the calendar names it.
    pub obligation_id: String,
    /// The day the obligation takes effect.
    pub obligation_date: NaiveDate,
    /// The obligation's kind.
    pub obligation_kind: ObligationKind,
    /// The lead time the notice is announced at, or `None` for the day itself.
    pub lead_days: Option<u32>,
    /// The day the notice is announced.
    pub notice_day: NaiveDate,
    /// The basis the date rests on. Only a sourced date is ever recorded.
    pub basis: DateBasis,
    /// The subject the notice is delivered under.
    pub event_type: String,
    /// The serialised event, exactly as it is delivered and signed.
    pub body: String,
}

/// A notice the ledger holds, as the read route reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedNotice {
    /// The notice's id.
    pub notice_id: Uuid,
    /// The obligation's id.
    pub obligation_id: String,
    /// The day the obligation takes effect.
    pub obligation_date: NaiveDate,
    /// The lead time the notice was announced at, or `None` for the day itself.
    pub lead_days: Option<u32>,
    /// The day the notice was announced for.
    pub notice_day: NaiveDate,
    /// When the ledger recorded it.
    pub announced_at: DateTime<Utc>,
}

/// The ledger of announced notices, and the singleton day a notice pass starts from.
#[async_trait]
pub trait ObligationNoticeStore: Send + Sync {
    /// The first day a notice pass covers: `today` when none is recorded yet, and
    /// the recorded day otherwise. Only the first pass writes it.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn ensure_active_since(&self, today: NaiveDate) -> Result<NaiveDate, DppError>;

    /// Record each notice not yet in the ledger and queue its webhook deliveries,
    /// in one transaction. Returns the ids this call recorded. A notice an
    /// earlier call or another instance recorded is skipped, and nothing is
    /// queued for it.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure, in which case nothing was recorded or
    /// queued.
    async fn announce(&self, notices: &[NoticeRecord]) -> Result<Vec<Uuid>, DppError>;

    /// The notices recorded for obligations dated from `from` through `to`, both
    /// days included.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn announced(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<AnnouncedNotice>, DppError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_domain::ObligationCalendar;

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn due_diligence() -> ObligationEvent {
        ObligationCalendar::new()
            .events()
            .iter()
            .find(|e| e.id == "battery.due-diligence-report")
            .expect("the calendar holds the battery due-diligence report")
            .clone()
    }

    #[test]
    fn a_notice_id_is_pinned_so_a_release_cannot_re_announce_under_new_ids() {
        // Changing the name or the namespace gives every notice a new id, and a
        // receiver that de-duplicates on the id would take each one as new.
        assert_eq!(
            notice_id(&due_diligence(), None).to_string(),
            "a4379068-b7a0-58cf-a65f-e4b76ed40461"
        );
        assert_eq!(
            notice_id(&due_diligence(), Some(30)).to_string(),
            "0130b7e4-81bd-56c8-9598-1a9a287fa8e5"
        );
    }

    #[test]
    fn a_notice_id_is_a_version_5_uuid() {
        let id = notice_id(&due_diligence(), None);
        assert_eq!(id.get_version_num(), 5);
    }

    #[test]
    fn each_of_the_date_the_kind_and_the_lead_time_names_a_different_notice() {
        let event = due_diligence();
        let mut moved = event.clone();
        moved.date = day(2027, 9, 1);
        let mut other_kind = event.clone();
        other_kind.kind = ObligationKind::Restriction;
        let mut other_obligation = event.clone();
        other_obligation.id = "some-other-obligation".to_owned();

        let ids = [
            notice_id(&event, None),
            notice_id(&event, Some(30)),
            notice_id(&event, Some(7)),
            notice_id(&moved, None),
            notice_id(&other_kind, None),
            notice_id(&other_obligation, None),
        ];
        let mut distinct = ids.to_vec();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), ids.len());
    }

    #[test]
    fn a_sourced_date_has_a_notice_on_each_lead_day_and_on_the_day() {
        let slots = notice_slots(&due_diligence(), &[90, 30, 7]);
        assert_eq!(
            slots,
            [
                NoticeSlot {
                    day: day(2027, 5, 20),
                    lead_days: Some(90)
                },
                NoticeSlot {
                    day: day(2027, 7, 19),
                    lead_days: Some(30)
                },
                NoticeSlot {
                    day: day(2027, 8, 11),
                    lead_days: Some(7)
                },
                NoticeSlot {
                    day: day(2027, 8, 18),
                    lead_days: None
                },
            ],
            "earliest first"
        );
    }

    #[test]
    fn an_assumed_date_has_no_notice_at_all() {
        let mut assumed = due_diligence();
        assumed.basis = DateBasis::Assumed;
        assert!(notice_slots(&assumed, &[90, 30, 7]).is_empty());
    }

    #[test]
    fn the_wire_names_are_the_ones_the_payload_and_the_api_spell() {
        assert_eq!(kind_name(ObligationKind::PassportStart), "passportStart");
        assert_eq!(
            kind_name(ObligationKind::ContentRequirement),
            "contentRequirement"
        );
        assert_eq!(basis_name(DateBasis::Sourced), "sourced");
    }
}
