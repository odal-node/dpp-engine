//! `GET /api/v1/obligations?from=&to=` — the dated obligations the node's calendar
//! holds in a window, and for each notice of them whether and when it was
//! announced.
//!
//! The answer is the same source the webhooks are sent from: the calendar in
//! force, read with the lead times the node announces at, and the ledger of
//! notices it has recorded. A notice the calendar would send that the ledger does
//! not hold reads as not announced. That covers a notice that is still to come,
//! and a notice whose day passed while the node was not announcing.
//!
//! The route reads no clock. Whether an upcoming notice whose date has already
//! passed is still wanted is the notice pass's question, and it is not answered
//! here: such a notice reads as not announced.

use std::collections::HashMap;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, NaiveDate, Utc};
use dpp_common::event::obligation_subject;
use dpp_domain::{ObligationEvent, ScheduleConflict};
use dpp_types::AnnouncedNotice;
use dpp_types::obligation_notice::{notice_id, notice_slots};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    extract::{Json, Query},
    middleware::auth::AuthContext,
    state::AppState,
};

use super::error::{internal_error, validation_error};

/// The widest window a read may ask for, in days between `from` and `to`.
const MAX_WINDOW_DAYS: i64 = 3660;

/// `?from=YYYY-MM-DD&to=YYYY-MM-DD`. Both are required; a missing or malformed
/// value is refused with `422`, the status this service gives every invalid
/// query value.
#[derive(Debug, Serialize, Deserialize)]
pub struct ObligationsQuery {
    /// First day of the window, inclusive.
    pub from: Option<String>,
    /// Last day of the window, inclusive.
    pub to: Option<String>,
}

/// `raw` as a day, when it is spelled `YYYY-MM-DD` exactly. chrono also reads
/// `2027-8-1`, which is not the form the route documents.
fn iso_day(raw: &str) -> Option<NaiveDate> {
    if raw.len() != 10 {
        return None;
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()
}

/// The window the route answers, or the reason it refuses one.
#[allow(clippy::result_large_err)]
fn window(query: &ObligationsQuery) -> Result<(NaiveDate, NaiveDate), Response> {
    let (Some(from), Some(to)) = (query.from.as_deref(), query.to.as_deref()) else {
        return Err(validation_error(
            "from and to are required: ISO dates, YYYY-MM-DD.",
        ));
    };
    let (Some(from), Some(to)) = (iso_day(from), iso_day(to)) else {
        return Err(validation_error(
            "from and to must be ISO dates, YYYY-MM-DD.",
        ));
    };
    if from > to {
        return Err(validation_error("from must not be after to."));
    }
    if (to - from).num_days() > MAX_WINDOW_DAYS {
        return Err(validation_error(
            "the window between from and to may span at most 3660 days.",
        ));
    }
    Ok((from, to))
}

/// One notice of an obligation: where it is due, and whether the ledger holds it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeEntry {
    /// The notice's id, the same one a webhook delivery carries as its event id.
    pub notice_id: Uuid,
    /// `dpp.obligation.upcoming` for a notice sent ahead, `dpp.obligation.effective`
    /// for the day itself.
    pub event_type: &'static str,
    /// The lead time, in days, for an upcoming notice. Absent for the day itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lead_days: Option<u32>,
    /// The day the notice is due.
    pub notice_day: NaiveDate,
    /// Whether the ledger holds this notice.
    pub announced: bool,
    /// When the ledger recorded it. `null` while it is not announced.
    pub announced_at: Option<DateTime<Utc>>,
}

/// One dated obligation: the calendar's event, with its notices.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObligationEntry {
    /// The calendar's event, as the webhook payload carries it.
    #[serde(flatten)]
    pub event: ObligationEvent,
    /// The notices of this obligation, earliest first. Empty for a date that is
    /// not sourced, which is never announced.
    pub notices: Vec<NoticeEntry>,
}

/// The response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObligationsResponse {
    /// First day of the window, as asked.
    pub from: NaiveDate,
    /// Last day of the window, as asked.
    pub to: NaiveDate,
    /// The obligations taking effect in the window, in date order.
    pub events: Vec<ObligationEntry>,
    /// Dates a signed ruleset offered that this build's own dates overruled,
    /// as the calendar holds them.
    pub conflicts: Vec<ScheduleConflict>,
}

/// The notices of `event`, each matched against the ledger by its id.
fn entry(
    event: &ObligationEvent,
    lead_days: &[u32],
    announced: &HashMap<Uuid, &AnnouncedNotice>,
) -> ObligationEntry {
    let notices = notice_slots(event, lead_days)
        .into_iter()
        .map(|slot| {
            let id = notice_id(event, slot.lead_days);
            let row = announced.get(&id);
            NoticeEntry {
                notice_id: id,
                event_type: obligation_subject(slot.lead_days),
                lead_days: slot.lead_days,
                notice_day: slot.day,
                announced: row.is_some(),
                announced_at: row.map(|r| r.announced_at),
            }
        })
        .collect();
    ObligationEntry {
        event: event.clone(),
        notices,
    }
}

/// `GET /api/v1/obligations` — the calendar's obligations in a window, with the
/// notices announced for each.
pub async fn obligations_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Query(query): Query<ObligationsQuery>,
) -> Response {
    let (from, to) = match window(&query) {
        Ok(window) => window,
        Err(refusal) => return refusal,
    };
    let calendar = state.obligation_schedule.calendar();
    let lead_days = state.obligation_schedule.lead_days();
    let announced = match state.obligation_notices.announced(from, to).await {
        Ok(rows) => rows,
        Err(e) => return internal_error(e),
    };
    let by_id: HashMap<Uuid, &AnnouncedNotice> =
        announced.iter().map(|row| (row.notice_id, row)).collect();
    let events = calendar
        .between(from, to)
        .map(|event| entry(event, &lead_days, &by_id))
        .collect();
    let body = ObligationsResponse {
        from,
        to,
        events,
        conflicts: calendar.conflicts().to_vec(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(from: Option<&str>, to: Option<&str>) -> ObligationsQuery {
        ObligationsQuery {
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
        }
    }

    fn status_of(q: &ObligationsQuery) -> Option<StatusCode> {
        window(q).err().map(|r| r.status())
    }

    #[test]
    fn a_window_needs_both_ends_as_iso_dates() {
        assert_eq!(
            status_of(&query(None, Some("2027-01-01"))),
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );
        assert_eq!(
            status_of(&query(Some("2027-01-01"), None)),
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );
        assert_eq!(
            status_of(&query(Some("01/01/2027"), Some("2027-01-02"))),
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );
        assert_eq!(
            status_of(&query(Some("2027-01-01"), Some("2027-02-30"))),
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );
        assert!(
            window(&query(Some("2027-01-01"), Some("2027-01-01"))).is_ok(),
            "a single day is a window"
        );
    }

    #[test]
    fn a_window_that_ends_before_it_starts_is_refused() {
        assert_eq!(
            status_of(&query(Some("2027-01-02"), Some("2027-01-01"))),
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );
    }

    #[test]
    fn a_day_is_refused_unless_it_is_spelled_yyyy_mm_dd() {
        assert!(status_of(&query(Some("2027-8-1"), Some("2027-08-02"))).is_some());
        assert!(status_of(&query(Some("2027-08-01"), Some("2027-8-2"))).is_some());
        assert!(window(&query(Some("2027-08-01"), Some("2027-08-02"))).is_ok());
    }

    #[test]
    fn a_window_of_3660_days_is_the_widest_accepted() {
        let from = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap();
        let fits = from.checked_add_days(chrono::Days::new(3660)).unwrap();
        let too_wide = from.checked_add_days(chrono::Days::new(3661)).unwrap();
        assert!(window(&query(Some("2027-01-01"), Some(&fits.to_string()))).is_ok());
        assert_eq!(
            status_of(&query(Some("2027-01-01"), Some(&too_wide.to_string()))),
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
}
