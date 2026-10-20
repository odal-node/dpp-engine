//! `POST /api/v1/dpp/{dppId}/registry/abandon` — give up, on a person's say-so, on
//! a registration the registry never accepted.
//!
//! A registration the registry refuses on every attempt, or whose product is
//! withdrawn before it was ever registered, used to be retried with backoff for as
//! long as the passport stayed published. This ends the queue row.
//!
//! # It does not take their word for it
//!
//! A `pending` row whose first attempt got through and whose reply was lost looks
//! exactly like one that never did, and abandoning it would leave a registration
//! the registry may grant that this node believes it dropped. So the registry's
//! task list is read, and the route refuses unless **all** of it was read and none
//! of it reports the unique product identifier this passport was submitted under.
//!
//! # Not idempotency-keyed, and why
//!
//! A row that is already abandoned answers `200` with `alreadyAbandoned: true` and
//! touches nothing, asks the registry nothing and writes the trail nothing, so a
//! retry after a lost response does not fail on its own success.
//!
//! `404` when the passport has no registration, `409` when the row is in a state
//! this does not end or the registry holds a submission for it, `422` when the
//! registry could not be shown to hold nothing.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_domain::ports::registry_sync::SubmissionLookup;
use dpp_types::RegistrySyncStatus;
use serde::{Deserialize, Serialize};

use crate::{
    domain::service::registry_abandon::{AbandonError, Abandoned},
    extract::Json,
    middleware::scope::RequireAdmin,
    state::AppState,
};

use super::error::{
    api_error, conflict_error, internal_error, not_found_error, parse_passport_id, validation_error,
};

/// The longest reason accepted. It is stored on the row, shown on the registry
/// route and kept in the audit trail, so it is bounded.
const MAX_REASON_CHARS: usize = 500;

/// `POST /api/v1/dpp/{dppId}/registry/abandon` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbandonRegistrationRequest {
    /// Why the registration is being given up on. Required: the write ends an
    /// obligation the node was tracking, and the trail is the only account of why.
    pub reason: String,
}

/// `POST /api/v1/dpp/{dppId}/registry/abandon` response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbandonRegistrationResponse {
    pub passport_id: String,
    /// `true` when the row was already abandoned, in which case nothing was read
    /// from the registry and nothing was written.
    pub already_abandoned: bool,
    /// Stated, not implied: what this did and did not do.
    pub note: &'static str,
}

const NOTE: &str = "the registration is abandoned and the node will no longer try it. The \
     passport stays published and is counted as abandoned on GET /api/v1/registry. Publishing it \
     again queues it afresh.";

/// Why the registration was not abandoned, as the HTTP answer to it.
fn refusal(why: AbandonError) -> Response {
    match why {
        AbandonError::NotConfigured => api_error(
            StatusCode::NOT_IMPLEMENTED,
            "REGISTRY_QUEUES_DISABLED",
            "This node has no registry queues, so there is no registration to abandon.",
        ),
        AbandonError::NoRegistration => not_found_error(
            "This passport has no registry registration. It owes one only once published.",
        ),
        AbandonError::NotAbandonable(status) => conflict_error(match status {
            RegistrySyncStatus::Submitted => {
                "The registry has accepted this passport's submission, so it holds a registration \
                 or is deciding one. That is not abandoned from here: wait for its ruling, or \
                 record its correlation identifier if the row has none."
            }
            RegistrySyncStatus::Registered
            | RegistrySyncStatus::Rejected
            | RegistrySyncStatus::Deactivated => {
                "The registry has already ruled on this passport's submission, so there is \
                 nothing to abandon."
            }
            // Pending and Abandoned are handled before this can be reached.
            RegistrySyncStatus::Pending | RegistrySyncStatus::Abandoned => {
                "The registration changed while it was being abandoned."
            }
        }),
        AbandonError::DueForAnAttempt => conflict_error(
            "The node has not tried this registration yet, or is about to try it or is trying it \
             now. A registration is abandoned only after an attempt has failed, while it waits \
             for the next one, so the abandon cannot race the attempt. Try again once an attempt \
             has failed.",
        ),
        AbandonError::CannotSayWhatWasSubmitted => validation_error(
            "This registration's stored payload is missing or unreadable, so the registry cannot \
             be asked whether it holds a submission for it. A registration that cannot be checked \
             is not abandoned.",
        ),
        AbandonError::RegistryHoldsIt(lookup) => conflict_error(&held(&lookup)),
        AbandonError::NotShownAbsent(lookup) => validation_error(&not_shown(&lookup)),
        AbandonError::Registry(e) => {
            tracing::warn!(error = %e, "could not read the registry to check before abandoning");
            api_error(
                StatusCode::BAD_GATEWAY,
                "REGISTRY_UNREADABLE",
                "The registry could not be read, so it could not be shown to hold nothing for \
                 this passport and the registration was not abandoned. Try again.",
            )
        }
        AbandonError::Storage(e) => internal_error(e),
    }
}

/// What the registry does hold, worded as the reason nothing was abandoned.
fn held(lookup: &SubmissionLookup) -> String {
    let what = match lookup {
        SubmissionLookup::Found { correlation_id, .. } => {
            format!("under correlation identifier {correlation_id}")
        }
        SubmissionLookup::Ambiguous { candidates } => format!(
            "under more than one correlation identifier ({})",
            candidates.join(", ")
        ),
        _ => "under a correlation identifier this node does not know".to_owned(),
    };
    format!(
        "The registry holds a submission for this passport's unique product identifier, {what}. \
         It was accepted, so this registration is not abandoned. The node's drain finds it on \
         its next attempt; if the registration is waiting for a person, record the handle with \
         POST /api/v1/dpp/{{dppId}}/registry/handle."
    )
}

/// Why the registry could not be shown to hold nothing, worded as the reason the
/// registration was not abandoned.
fn not_shown(lookup: &SubmissionLookup) -> String {
    let why = match lookup {
        SubmissionLookup::NotFound { exhaustive: false } => {
            "Part of the registry's task list was not read, or a task is still being checked and \
             reports no passport yet, so a submission for this passport may be among what was not \
             seen."
        }
        _ => "This node's registry connection cannot look a submission up.",
    };
    format!("{why} The registration was not abandoned.")
}

/// Whether `reason` is something worth keeping in an audit trail: not blank,
/// bounded, and free of control characters.
fn well_formed(reason: &str) -> bool {
    !reason.is_empty()
        && reason.chars().count() <= MAX_REASON_CHARS
        && !reason.chars().any(char::is_control)
}

/// `POST /api/v1/dpp/{dppId}/registry/abandon` — give up on a registration the
/// registry never accepted, once it has been shown to hold nothing for the passport.
pub async fn abandon_registration_handler(
    State(state): State<AppState>,
    // The gate is an extractor and precedes the body extractor, so a wrong-scope
    // caller is refused before the body is parsed.
    RequireAdmin(auth): RequireAdmin,
    Path(dpp_id): Path<String>,
    Json(body): Json<AbandonRegistrationRequest>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let reason = body.reason.trim();
    if !well_formed(reason) {
        return validation_error(&format!(
            "reason must say why the registration is being given up on: not empty, at most \
             {MAX_REASON_CHARS} characters, and without control characters."
        ));
    }

    match state
        .service
        .abandon_registration(passport_id, reason, &auth)
        .await
    {
        Ok(Abandoned { already }) => (
            StatusCode::OK,
            Json(AbandonRegistrationResponse {
                passport_id: dpp_id,
                already_abandoned: already,
                note: NOTE,
            }),
        )
            .into_response(),
        Err(why) => refusal(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_domain::DppError;

    /// Each way a registration goes un-abandoned has the status its documentation
    /// gives it, whatever the route's tests can reach over HTTP.
    #[test]
    fn each_refusal_has_the_status_the_route_documents() {
        use AbandonError as E;
        let status = |why| refusal(why).status();

        assert_eq!(status(E::NotConfigured), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(status(E::NoRegistration), StatusCode::NOT_FOUND);
        for held in [
            RegistrySyncStatus::Submitted,
            RegistrySyncStatus::Registered,
            RegistrySyncStatus::Rejected,
            RegistrySyncStatus::Deactivated,
        ] {
            assert_eq!(status(E::NotAbandonable(held)), StatusCode::CONFLICT);
        }
        assert_eq!(status(E::DueForAnAttempt), StatusCode::CONFLICT);
        assert_eq!(
            status(E::CannotSayWhatWasSubmitted),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status(E::RegistryHoldsIt(SubmissionLookup::Ambiguous {
                candidates: vec!["A".into(), "B".into()]
            })),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status(E::NotShownAbsent(SubmissionLookup::NotFound {
                exhaustive: false
            })),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status(E::Registry(DppError::Internal("unreachable".into()))),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status(E::Storage(DppError::Internal("down".into()))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// 🚨 A submission the registry holds is a `409`, not a `422`: the registration
    /// is not unproven, it is there. A client reading `422` as "try again later"
    /// would keep asking to abandon one the registry has accepted.
    #[test]
    fn a_submission_the_registry_holds_names_where_to_find_it() {
        let found = SubmissionLookup::Found {
            correlation_id: "CORR-7".into(),
            report: dpp_domain::ports::registry_sync::SubmissionReport::Processing,
        };
        assert!(held(&found).contains("CORR-7"));
        let several = SubmissionLookup::Ambiguous {
            candidates: vec!["CORR-1".into(), "CORR-2".into()],
        };
        let text = held(&several);
        assert!(text.contains("CORR-1") && text.contains("CORR-2"), "{text}");
    }

    #[test]
    fn a_reason_is_something_worth_keeping() {
        assert!(well_formed(
            "the product was withdrawn before it was registered"
        ));
        assert!(!well_formed(""));
        assert!(!well_formed("tab\there"));
        assert!(!well_formed("line\nbreak"));
        assert!(!well_formed(&"x".repeat(MAX_REASON_CHARS + 1)));
        assert!(well_formed(&"x".repeat(MAX_REASON_CHARS)));
    }
}
