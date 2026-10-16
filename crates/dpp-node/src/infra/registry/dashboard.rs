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
}

/// One dashboard task, as far as finding a submission needs it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Task {
    /// The task's own identifier, which its result is read by. Kept as it came:
    /// nothing says whether it is a string or a number.
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
}
