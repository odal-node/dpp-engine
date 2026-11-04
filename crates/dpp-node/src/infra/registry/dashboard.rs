//! Reading a submission back from the registry's dashboard.
//!
//! A registration is a task on the operator's dashboard. The registry's own web
//! interface finds it by listing the operator's tasks and reads what became of it
//! from the task's result, so those are the two routes used here
//! ([`TASKS_PATH`](dpp_registry::TASKS_PATH) and
//! [`TASK_RESULT_PATH_TEMPLATE`](dpp_registry::TASK_RESULT_PATH_TEMPLATE)). No
//! route that takes a correlation identifier has been seen, so the task is found
//! by paging the list.
//!
//! The field names are the ones the interface reads, as `dpp-registry` records
//! them. None of this is a published schema, and a state this node has no name
//! for is reported as unrecognised, never as a verdict.

use dpp_domain::ports::registry_sync::SubmissionReport;
use dpp_registry::{PassportOutcome, PassportResult, SubmissionOutcome};
use serde::Deserialize;

/// The task type the registry gives a registration request.
pub(super) const REGISTRATION_TASK_TYPE: &str = "DPP_REGISTRATION";

/// One page of the operator's tasks.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TaskPage {
    /// The tasks on this page.
    #[serde(default)]
    pub content: Vec<Task>,
    /// How many tasks the list holds in all, which the registry's interface
    /// reads to page it. Observed, but a reply without it is read as a list of
    /// unknown length rather than refused.
    #[serde(default)]
    pub total_elements: Option<u64>,
}

/// Which pages of the list to read, and whether reading them covers it all.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PagePlan {
    /// The page numbers after the first, in the order to read them.
    pub pages: Vec<u32>,
    /// Whether every task in the list is on a page that will be read.
    pub covers_all: bool,
}

/// How the list is ordered, as the first page shows it.
///
/// The list is asked for newest first ([`TASKS_SORT_NEWEST_FIRST`](dpp_registry::TASKS_SORT_NEWEST_FIRST), what
/// the registry's own interface sends), but what was asked for is not what was
/// delivered, so the order is **checked on the data**, not assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListOrder {
    /// The first page's tasks run from the latest submission to the earliest, so
    /// a task just submitted is on the front of the list.
    NewestFirst,
    /// The page does not show it: too few tasks to compare, a submission time that
    /// is missing or unreadable, a run that is ascending, or one that is not
    /// monotonic. Nothing is concluded about where a new task is.
    Unknown,
}

/// Read the order off a page of tasks.
///
/// [`ListOrder::NewestFirst`] only when at least two tasks carry a readable
/// `submittedAt`, no later task is newer than an earlier one, and at least one
/// is strictly older. A page of equal times, or of one task, says nothing about
/// direction. Every task that carries a time is compared; one that carries none
/// is skipped, not guessed at.
pub(super) fn order_of(tasks: &[Task]) -> ListOrder {
    let times: Vec<chrono::DateTime<chrono::Utc>> = tasks
        .iter()
        .filter_map(|task| task.submitted_at.as_deref())
        .map(|text| chrono::DateTime::parse_from_rfc3339(text).map(|t| t.to_utc()))
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    let descending = times.windows(2).all(|pair| pair[0] >= pair[1]);
    let some_older = times.windows(2).any(|pair| pair[0] > pair[1]);
    if times.len() >= 2 && descending && some_older {
        ListOrder::NewestFirst
    } else {
        ListOrder::Unknown
    }
}

/// Decide which pages to read after the first, given how long the list is and how
/// it is ordered.
///
/// A list short enough for `cap` pages is read in full, whatever its order. A
/// longer one is read according to what the first page showed:
///
/// - [`ListOrder::NewestFirst`]: from the **front**, `cap` pages deep. A task just
///   submitted is on the first page, so the budget goes where the answer is, and
///   covers the most recent submissions twice as deep as splitting it would.
/// - [`ListOrder::Unknown`]: from **both ends**, interleaved. A task just submitted
///   is at the front of a newest-first list and at the back of an oldest-first
///   one, and reading only the front never finds it in the second kind once the
///   list outgrows the cap.
///
/// A reply that gave no length is read from the front only, `cap` pages deep,
/// and covers nothing it cannot show.
pub(super) fn plan_pages(
    total_elements: Option<u64>,
    page_size: usize,
    cap: u32,
    order: ListOrder,
) -> PagePlan {
    let Some(total) = total_elements else {
        return PagePlan {
            pages: (1..cap).collect(),
            covers_all: false,
        };
    };
    let page_size = u64::try_from(page_size.max(1)).unwrap_or(u64::MAX);
    let total_pages = total.div_ceil(page_size);
    if total_pages <= u64::from(cap) {
        return PagePlan {
            pages: (1..u32::try_from(total_pages).unwrap_or(cap)).collect(),
            covers_all: true,
        };
    }

    if order == ListOrder::NewestFirst {
        return PagePlan {
            pages: (1..cap).collect(),
            covers_all: false,
        };
    }

    let last = u32::try_from(total_pages - 1).unwrap_or(u32::MAX);
    let front = cap.div_ceil(2);
    let back = cap - front;
    let mut pages = Vec::new();
    for i in 0..front.max(back) {
        if i > 0 && i < front {
            pages.push(i);
        }
        if i < back {
            pages.push(last - i);
        }
    }
    PagePlan {
        pages,
        covers_all: false,
    }
}

/// One dashboard task, as far as finding a submission needs it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Task {
    /// The task's own identifier, which its result is read by. Kept as it came:
    /// nothing says whether it is a string or a number. Defaulted, because a
    /// `Value` is not an `Option` and a missing field is an error for it: one
    /// listed task without an identifier would fail the whole page. A task with
    /// none reads as having none ([`Task::id_segment`] is `None`).
    #[serde(default)]
    pub task_id: serde_json::Value,
    /// The submission's correlation identifier.
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// What kind of task this is. A registration is
    /// [`REGISTRATION_TASK_TYPE`].
    #[serde(default, rename = "type")]
    pub task_type: Option<String>,
    /// Where the submission has got to.
    #[serde(default)]
    pub status: Option<SubmissionOutcome>,
    /// When the task was submitted. What the list is sorted by, and what
    /// [`order_of`] reads the order off. Kept as it came: a value that is not an
    /// RFC 3339 time is read as no order shown, never as an error.
    #[serde(default)]
    pub submitted_at: Option<String>,
}

impl Task {
    /// Whether this is the registration submitted under `correlation_id`.
    pub(super) fn is_submission(&self, correlation_id: &str) -> bool {
        self.correlation_id.as_deref() == Some(correlation_id)
            && self
                .task_type
                .as_deref()
                .is_none_or(|kind| kind == REGISTRATION_TASK_TYPE)
    }

    /// Whether this is a registration request. A task that names no type is read
    /// as one, as [`is_submission`](Self::is_submission) reads it.
    pub(super) fn is_registration(&self) -> bool {
        self.task_type
            .as_deref()
            .is_none_or(|kind| kind == REGISTRATION_TASK_TYPE)
    }

    /// Whether the registry has finished with this task, so it has a result that
    /// names passports. A task still being checked reports none.
    pub(super) fn is_finished(&self) -> bool {
        matches!(
            self.status,
            Some(SubmissionOutcome::Success | SubmissionOutcome::Failure)
        )
    }

    /// The task identifier as a path segment.
    pub(super) fn id_segment(&self) -> Option<String> {
        match &self.task_id {
            serde_json::Value::String(id) if !id.trim().is_empty() => Some(id.clone()),
            serde_json::Value::Number(id) => Some(id.to_string()),
            _ => None,
        }
    }
}

/// One task's result.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TaskResult {
    /// The submission's status, in the task spelling.
    #[serde(default)]
    pub status: Option<SubmissionOutcome>,
    /// What the registry reported about the submission.
    #[serde(default)]
    pub result_payload: Option<ResultPayload>,
}

impl TaskResult {
    /// The unique product identifier of each passport this result reports on.
    ///
    /// What a result is matched to a passport by, and the only thing it is: the
    /// registry reports each passport against the URL it was submitted under, and
    /// nothing published says results come back in submission order.
    pub(super) fn unique_product_identifiers(&self) -> impl Iterator<Item = &str> {
        self.result_payload
            .iter()
            .filter_map(|p| p.report.as_ref())
            .flat_map(|r| r.item_details.iter())
            .map(|item| item.unique_product_identifier.as_str())
    }
}

/// The body of a task result.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResultPayload {
    /// The outcome in the result spelling (`SUCCEEDED`, `FAILED`), which the
    /// interface shows when it is present.
    #[serde(default)]
    pub outcome_result: Option<SubmissionOutcome>,
    /// What the registry says about each passport.
    #[serde(default)]
    pub report: Option<Report>,
}

/// The per-passport report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Report {
    /// One entry per passport the report names.
    #[serde(default)]
    pub item_details: Vec<PassportResult>,
}

/// What a task and its result say became of the one passport this node
/// submitted under it.
///
/// This node submits one passport per request, so the report is read as being
/// about that one. A result that does not fit is **not** a verdict, because
/// reading it as a refusal would discard a submission that may have succeeded
/// and reading it as a registration would record one that may not exist: it is
/// reported as unrecognised, which keeps the poll going.
pub(super) fn report_for(task: &Task, result: Option<&TaskResult>) -> SubmissionReport {
    let results: &[PassportResult] = result
        .and_then(|r| r.result_payload.as_ref())
        .and_then(|p| p.report.as_ref())
        .map_or(&[], |r| r.item_details.as_slice());

    // The result spelling wins where there is one, as in the interface; the task
    // spelling is the fallback. Both read as the same outcome.
    let outcome = result
        .and_then(|r| r.result_payload.as_ref())
        .and_then(|p| p.outcome_result.as_ref())
        .or_else(|| result.and_then(|r| r.status.as_ref()))
        .or(task.status.as_ref());

    match outcome {
        None | Some(SubmissionOutcome::Processing) => SubmissionReport::Processing,
        Some(SubmissionOutcome::Success) => registered(results),
        Some(SubmissionOutcome::Failure) => SubmissionReport::Refused {
            reason: refusal(results),
        },
        Some(other) => SubmissionReport::Unrecognised {
            state: other.wire_str().to_owned(),
        },
    }
}

/// The registration a successful submission produced.
fn registered(results: &[PassportResult]) -> SubmissionReport {
    match results {
        [only] if only.outcome != Some(PassportOutcome::Rejected) => {
            match only.registration_identifier.as_deref().map(str::trim) {
                Some(id) if !id.is_empty() => SubmissionReport::Registered {
                    registration_id: id.to_owned(),
                },
                _ => SubmissionReport::Unrecognised {
                    state: "SUCCESS, with no registration identifier for the passport".to_owned(),
                },
            }
        }
        _ => SubmissionReport::Unrecognised {
            state: format!(
                "SUCCESS, with {} passport results for a submission of one",
                results.len()
            ),
        },
    }
}

/// Why a failed submission failed, in the registry's own terms.
///
/// A submission is refused as a whole, so the passport may carry no error of its
/// own, and that is said rather than left blank.
fn refusal(results: &[PassportResult]) -> String {
    match results.iter().find_map(|r| r.error_code.as_deref()) {
        Some(code) => format!("the registry refused the submission: {code}"),
        None => {
            "the registry refused the submission and named no error for this passport".to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn task(status: &str) -> Task {
        serde_json::from_value(json!({
            "taskId": 7,
            "correlationId": "corr-1",
            "type": "DPP_REGISTRATION",
            "status": status,
        }))
        .expect("a task")
    }

    fn result(value: serde_json::Value) -> TaskResult {
        serde_json::from_value(value).expect("a task result")
    }

    fn accepted(registration: Option<&str>) -> serde_json::Value {
        json!({
            "uniqueProductIdentifier": "https://id.example.com/01/09506000134352",
            "outcome": "ACCEPTED",
            "registrationIdentifier": registration,
        })
    }

    #[test]
    fn a_submission_is_found_by_its_correlation_id_and_its_type() {
        assert!(task("PROCESSING").is_submission("corr-1"));
        assert!(!task("PROCESSING").is_submission("corr-2"));

        let other_kind: Task = serde_json::from_value(json!({
            "taskId": "t", "correlationId": "corr-1", "type": "SOMETHING_ELSE",
        }))
        .expect("a task");
        assert!(
            !other_kind.is_submission("corr-1"),
            "a task of another kind is not this registration"
        );
    }

    #[test]
    fn a_task_id_is_a_path_segment_whether_it_arrives_as_a_string_or_a_number() {
        assert_eq!(task("PROCESSING").id_segment().as_deref(), Some("7"));
        let string_id: Task = serde_json::from_value(json!({ "taskId": "abc" })).expect("a task");
        assert_eq!(string_id.id_segment().as_deref(), Some("abc"));
        let missing: Task = serde_json::from_value(json!({ "taskId": null })).expect("a task");
        assert_eq!(missing.id_segment(), None);
        let absent: Task = serde_json::from_value(json!({})).expect("a task with no id at all");
        assert_eq!(absent.id_segment(), None);
    }

    /// 🚨 The list holds all of the operator's tasks, not only registrations, and
    /// its shape is not published. One entry without an identifier must not fail
    /// the page it is on: the whole page would then be an error, the poll would
    /// back off, and every submission waiting behind that page would stall with it.
    #[test]
    fn one_task_without_an_identifier_does_not_fail_the_page() {
        let page: TaskPage = serde_json::from_value(json!({
            "content": [
                { "correlationId": "someone-else", "type": "SOMETHING_ELSE" },
                {
                    "taskId": 7,
                    "correlationId": "corr-1",
                    "type": "DPP_REGISTRATION",
                    "status": "PROCESSING",
                },
            ]
        }))
        .expect("a page with one odd task still reads");

        let found = page
            .content
            .into_iter()
            .find(|task| task.is_submission("corr-1"))
            .expect("the submission on the same page is still found");
        assert_eq!(found.id_segment().as_deref(), Some("7"));
    }

    #[test]
    fn a_task_still_processing_is_not_ruled_on() {
        assert_eq!(
            report_for(&task("PROCESSING"), None),
            SubmissionReport::Processing
        );
    }

    #[test]
    fn a_successful_submission_reports_the_registration_identifier() {
        let result = result(json!({
            "status": "SUCCESS",
            "resultPayload": { "report": { "itemDetails": [accepted(Some("REG-1"))] } },
        }));
        assert_eq!(
            report_for(&task("SUCCESS"), Some(&result)),
            SubmissionReport::Registered {
                registration_id: "REG-1".to_owned()
            }
        );
    }

    #[test]
    fn the_result_spelling_of_an_outcome_is_read_as_the_same_outcome() {
        let result = result(json!({
            "resultPayload": {
                "outcomeResult": "SUCCEEDED",
                "report": { "itemDetails": [accepted(Some("REG-2"))] },
            },
        }));
        assert_eq!(
            report_for(&task("PROCESSING"), Some(&result)),
            SubmissionReport::Registered {
                registration_id: "REG-2".to_owned()
            },
            "the result's own word wins over the task's"
        );
    }

    #[test]
    fn a_failed_submission_is_refused_with_the_error_code_the_registry_gave() {
        let result = result(json!({
            "status": "FAILURE",
            "resultPayload": { "report": { "itemDetails": [{
                "uniqueProductIdentifier": "https://id.example.com/01/09506000134352",
                "outcome": "REJECTED",
                "errorCode": "NOT_RESOLVABLE_UPI",
            }] } },
        }));
        let SubmissionReport::Refused { reason } = report_for(&task("FAILURE"), Some(&result))
        else {
            panic!("a failed submission is refused");
        };
        assert!(reason.contains("NOT_RESOLVABLE_UPI"), "{reason}");
    }

    #[test]
    fn a_refusal_with_no_error_of_its_own_says_so() {
        let result = result(json!({ "status": "FAILURE" }));
        let SubmissionReport::Refused { reason } = report_for(&task("FAILURE"), Some(&result))
        else {
            panic!("a failed submission is refused");
        };
        assert!(reason.contains("named no error"), "{reason}");
    }

    /// 🚨 A success that cannot be read as one registration is not a verdict.
    /// Recording it as a refusal would discard a submission that may have
    /// succeeded; recording a registration out of it would invent one.
    #[test]
    fn a_success_that_names_no_registration_keeps_the_poll_going() {
        for body in [
            json!({ "status": "SUCCESS" }),
            json!({ "status": "SUCCESS", "resultPayload": { "report": { "itemDetails": [accepted(None)] } } }),
            json!({ "status": "SUCCESS", "resultPayload": { "report": { "itemDetails": [accepted(Some("A")), accepted(Some("B"))] } } }),
        ] {
            let report = report_for(&task("SUCCESS"), Some(&result(body.clone())));
            assert!(
                matches!(report, SubmissionReport::Unrecognised { .. }) && !report.is_terminal(),
                "{body} must stay unresolved, got {report:?}"
            );
        }
    }

    #[test]
    fn a_state_the_node_has_no_name_for_is_reported_as_given() {
        let report = report_for(&task("ON_HOLD"), None);
        assert_eq!(
            report,
            SubmissionReport::Unrecognised {
                state: "ON_HOLD".to_owned()
            }
        );
    }

    // ── which pages are read ─────────────────────────────────────────────────

    /// A list that fits the cap is read whole, and says so.
    #[test]
    fn a_short_list_is_read_in_full() {
        // 120 tasks at 50 a page is three pages; page 0 is already read.
        assert_eq!(
            plan_pages(Some(120), 50, 20, ListOrder::Unknown),
            PagePlan {
                pages: vec![1, 2],
                covers_all: true
            }
        );
        // An empty list and a one-page list need nothing more.
        for total in [0, 1, 50] {
            assert_eq!(
                plan_pages(Some(total), 50, 20, ListOrder::Unknown),
                PagePlan {
                    pages: vec![],
                    covers_all: true
                },
                "{total} tasks"
            );
        }
        // Exactly the cap is still covered.
        assert!(plan_pages(Some(20 * 50), 50, 20, ListOrder::Unknown).covers_all);
    }

    /// 🚨 A list longer than the cap is read from both ends. The registry's
    /// order is not known, and a task just submitted is at the front of a
    /// newest-first list and at the back of an oldest-first one: reading only the
    /// front never finds it in the second kind.
    #[test]
    fn a_long_list_is_read_from_both_ends() {
        // 5 000 tasks is 100 pages; the cap of 20 is split between the ends.
        let plan = plan_pages(Some(5_000), 50, 20, ListOrder::Unknown);
        assert!(!plan.covers_all, "it cannot cover what it does not read");

        let mut pages = plan.pages.clone();
        pages.sort_unstable();
        pages.dedup();
        assert_eq!(pages.len(), plan.pages.len(), "no page is read twice");
        assert_eq!(
            plan.pages.len() + 1,
            20,
            "page 0 plus the rest is exactly the cap"
        );

        assert!(plan.pages.contains(&99), "the last page is read");
        assert!(plan.pages.contains(&90), "and the ten before it");
        assert!(plan.pages.contains(&9), "and the front, past page 0");
        assert!(
            !plan.pages.contains(&50),
            "the middle is not read, and the plan does not claim it was"
        );

        // Interleaved, so a hit at either end is found as early as at the other.
        assert_eq!(&plan.pages[..4], &[99, 1, 98, 2]);
    }

    /// A page of tasks carrying these submission times, in this order.
    fn page_submitted(times: &[Option<&str>]) -> Vec<Task> {
        times
            .iter()
            .enumerate()
            .map(|(n, time)| {
                serde_json::from_value(json!({ "taskId": n, "submittedAt": time })).expect("a task")
            })
            .collect()
    }

    /// 🚨 Newest first is concluded from the data, never from having asked: the
    /// times run from the latest to the earliest, and at least one step is real.
    #[test]
    fn a_page_running_from_latest_to_earliest_is_newest_first() {
        let page = page_submitted(&[
            Some("2026-10-20T12:00:00Z"),
            Some("2026-10-20T11:00:00Z"),
            Some("2026-10-19T09:30:00Z"),
        ]);
        assert_eq!(order_of(&page), ListOrder::NewestFirst);

        // Offsets are times, not text: the same instant written two ways is equal,
        // and 11:00 at +02:00 is earlier than 12:00Z.
        let mixed = page_submitted(&[
            Some("2026-10-20T12:00:00Z"),
            Some("2026-10-20T11:00:00+02:00"),
        ]);
        assert_eq!(order_of(&mixed), ListOrder::NewestFirst);
    }

    /// Everything short of that concludes nothing about where a new task is, so the
    /// plan falls back to both ends: an ascending page (the sort was ignored, or
    /// honoured the other way), one that is not monotonic, one too short to compare,
    /// one of equal times, and a time that is missing or not a time.
    #[test]
    fn anything_short_of_newest_first_is_unknown() {
        let unknown = |times: &[Option<&str>]| order_of(&page_submitted(times));

        assert_eq!(
            unknown(&[Some("2026-10-19T09:00:00Z"), Some("2026-10-20T09:00:00Z")]),
            ListOrder::Unknown,
            "ascending: a new task is at the back"
        );
        assert_eq!(
            unknown(&[
                Some("2026-10-20T09:00:00Z"),
                Some("2026-10-19T09:00:00Z"),
                Some("2026-10-20T10:00:00Z"),
            ]),
            ListOrder::Unknown,
            "not monotonic"
        );
        assert_eq!(unknown(&[Some("2026-10-20T09:00:00Z")]), ListOrder::Unknown);
        assert_eq!(unknown(&[]), ListOrder::Unknown);
        assert_eq!(
            unknown(&[Some("2026-10-20T09:00:00Z"), Some("2026-10-20T09:00:00Z")]),
            ListOrder::Unknown,
            "equal times say nothing about direction"
        );
        assert_eq!(
            unknown(&[Some("2026-10-20T09:00:00Z"), Some("yesterday-ish")]),
            ListOrder::Unknown,
            "a time that is not a time shows nothing, and is not skipped past"
        );
        assert_eq!(
            unknown(&[None, None, None]),
            ListOrder::Unknown,
            "tasks that carry no time at all"
        );
        // One task without a time among ones with is skipped, not guessed at.
        assert_eq!(
            unknown(&[
                Some("2026-10-20T10:00:00Z"),
                None,
                Some("2026-10-20T09:00:00Z"),
            ]),
            ListOrder::NewestFirst
        );
    }

    /// 🚨 A long list verified newest first is read from the front, the whole budget
    /// where the answer is. A new submission is on the first page of such a list, and
    /// splitting the budget with the back would halve how far into the recent past
    /// the search reaches.
    #[test]
    fn a_long_list_verified_newest_first_is_read_from_the_front() {
        let plan = plan_pages(Some(5_000), 50, 20, ListOrder::NewestFirst);
        assert_eq!(plan.pages, (1..20).collect::<Vec<_>>());
        assert!(!plan.covers_all, "it cannot cover what it does not read");
        assert!(
            !plan.pages.contains(&99),
            "the back is not read: a new task is not there"
        );
    }

    /// The order changes where the budget goes and nothing about what is covered: a
    /// list that fits the cap is read in full whichever order it came in.
    #[test]
    fn the_order_does_not_change_what_a_short_list_covers() {
        for order in [ListOrder::NewestFirst, ListOrder::Unknown] {
            assert_eq!(
                plan_pages(Some(120), 50, 20, order),
                PagePlan {
                    pages: vec![1, 2],
                    covers_all: true
                },
                "{order:?}"
            );
        }
    }

    /// A reply without a length is read from the front only and claims nothing.
    #[test]
    fn a_list_of_unknown_length_covers_nothing_it_cannot_show() {
        let plan = plan_pages(None, 50, 20, ListOrder::Unknown);
        assert_eq!(plan.pages, (1..20).collect::<Vec<_>>());
        assert!(!plan.covers_all);
    }

    #[test]
    fn a_result_is_matched_by_the_identifier_it_reports() {
        let result = result(json!({
            "status": "SUCCESS",
            "resultPayload": { "report": { "itemDetails": [
                accepted(Some("A")),
                {
                    "uniqueProductIdentifier": "https://id.example.com/01/09506000134369",
                    "outcome": "ACCEPTED",
                    "registrationIdentifier": "B",
                },
            ] } },
        }));
        assert_eq!(
            result.unique_product_identifiers().collect::<Vec<_>>(),
            [
                "https://id.example.com/01/09506000134352",
                "https://id.example.com/01/09506000134369"
            ]
        );
        // A result with nothing in it names nothing.
        assert_eq!(
            self::result(json!({})).unique_product_identifiers().count(),
            0
        );
    }

    #[test]
    fn a_task_without_a_type_is_read_as_a_registration_and_one_of_another_kind_is_not() {
        let untyped: Task = serde_json::from_value(json!({ "taskId": 1 })).expect("a task");
        assert!(untyped.is_registration());
        let other: Task =
            serde_json::from_value(json!({ "taskId": 2, "type": "ENROLMENT" })).expect("a task");
        assert!(!other.is_registration());
        assert!(!untyped.is_finished(), "no status is not a finished task");
        assert!(task("SUCCESS").is_finished() && task("FAILURE").is_finished());
        assert!(!task("PROCESSING").is_finished());
    }
}
