//! `POST /api/v1/dpp/{dppId}/registry/handle` — record, by hand, the correlation
//! identifier of a registry submission this node lost the handle of.
//!
//! The registry drain recovers a lost handle itself where it can. What it leaves
//! — several submissions reporting the passport's identifier, none it could place,
//! an adapter that cannot look one up — stays `submitted` and says why on
//! `GET /api/v1/dpp/{dppId}/registry`. This is how a person who has read the
//! right handle off the registry's own interface gives it to the row.
//!
//! # It does not take their word for it
//!
//! The submission the handle names is read back from the registry, and the route
//! refuses unless that submission reports the unique product identifier this
//! passport was submitted under. A typo, or the handle of a neighbouring passport,
//! would otherwise give this passport another passport's registration, and
//! nothing downstream could tell.
//!
//! # Not idempotency-keyed, and why
//!
//! The write is naturally idempotent: a row that already holds this handle
//! answers `200` with `recorded: false` and touches nothing, so a retry after a
//! lost response does not fail on its own success. A row that holds a
//! *different* handle is refused with `409`, which is the answer a keyed replay
//! could not improve on.
//!
//! `404` when the passport has no registration, `409` when the row is not in a
//! state that takes a handle, `422` when the registry does not show the handle to
//! be the passport's. The same split the transfer routes draw: `404` is "no such
//! thing", `409` and `422` are "it exists and this is wrong for it".

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_domain::ports::registry_sync::{SubmissionConfirmation, SubmissionReport};
use dpp_types::RegistrySyncStatus;
use serde::{Deserialize, Serialize};

use crate::{
    domain::service::registry_handle::{RecordHandleError, RecordedHandle},
    extract::Json,
    middleware::scope::RequireAdmin,
    state::AppState,
};

use super::error::{
    api_error, conflict_error, internal_error, not_found_error, parse_passport_id, validation_error,
};

/// The longest correlation identifier accepted.
///
/// The registry's identifiers are short; this only bounds what a caller can make
/// this node hold in a row and echo in a message.
const MAX_CORRELATION_ID_CHARS: usize = 200;

/// `POST /api/v1/dpp/{dppId}/registry/handle` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordHandleRequest {
    /// The submission's correlation identifier, as the registry lists it.
    pub correlation_id: String,
}

/// `POST /api/v1/dpp/{dppId}/registry/handle` response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordHandleResponse {
    pub passport_id: String,
    /// The correlation identifier the row now holds.
    pub correlation_id: String,
    /// `true` when this request recorded the handle. `false` when the row already
    /// held it, in which case nothing was checked or written.
    pub recorded: bool,
    /// What the registry reported about the submission when the handle was
    /// checked. Absent when `recorded` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<SubmissionReport>,
    /// Stated, not implied: this records the handle and nothing else.
    pub note: &'static str,
}

const NOTE: &str = "the handle is recorded and nothing else. The node's drain polls the \
     submission by it on its next pass and applies the registry's ruling then, which is the one \
     place that decides what a registration or a refusal does to a row.";

/// Why the handle was not recorded, as the HTTP answer to it.
fn refusal(passport_id: &str, why: RecordHandleError) -> Response {
    match why {
        RecordHandleError::NotConfigured => api_error(
            StatusCode::NOT_IMPLEMENTED,
            "REGISTRY_QUEUES_DISABLED",
            "This node has no registry queues, so there is no registration to record a handle \
             on.",
        ),
        RecordHandleError::NoRegistration => not_found_error(
            "This passport has no registry registration. It owes one only once published.",
        ),
        RecordHandleError::NotAwaitingAHandle(status) => conflict_error(match status {
            RegistrySyncStatus::Pending => {
                "The registry has not accepted this passport's submission yet, so there is no \
                 handle to record. The node's drain submits it and records the handle the \
                 registry gives."
            }
            RegistrySyncStatus::Submitted => {
                "The registration changed while the handle was being recorded."
            }
            RegistrySyncStatus::Registered
            | RegistrySyncStatus::Rejected
            | RegistrySyncStatus::Deactivated => {
                "The registry has already ruled on this passport's submission, so it no longer \
                 needs a handle."
            }
        }),
        RecordHandleError::HoldsAnotherHandle => conflict_error(
            "This registration already holds a correlation identifier. One the registry gave is \
             never overwritten.",
        ),
        RecordHandleError::CannotSayWhatWasSubmitted => validation_error(
            "This registration's stored payload is missing or unreadable, so there is nothing to \
             check the handle against. A handle that cannot be checked is not recorded.",
        ),
        RecordHandleError::NotConfirmed(confirmation) => {
            validation_error(&unconfirmed(passport_id, &confirmation))
        }
        RecordHandleError::Registry(e) => {
            tracing::warn!(passport_id, error = %e, "could not read the registry to check a handle");
            api_error(
                StatusCode::BAD_GATEWAY,
                "REGISTRY_UNREADABLE",
                "The registry could not be read, so the handle could not be checked and was not \
                 recorded. Try again.",
            )
        }
        RecordHandleError::Storage(e) => internal_error(e),
    }
}

/// What the registry did show, worded as the reason the handle was not recorded.
///
/// Every answer ends by saying so: a caller reading only the last sentence of a
/// refusal should not have to infer it.
fn unconfirmed(passport_id: &str, confirmation: &SubmissionConfirmation) -> String {
    format!(
        "{} The handle was not recorded.",
        why_unconfirmed(passport_id, confirmation)
    )
}

fn why_unconfirmed(passport_id: &str, confirmation: &SubmissionConfirmation) -> String {
    match confirmation {
        SubmissionConfirmation::Mismatch { reported } if reported.is_empty() => format!(
            "The registry has that submission and it reports no passport, so it cannot be shown \
             to be passport {passport_id}'s."
        ),
        SubmissionConfirmation::Mismatch { reported } => format!(
            "The registry has that submission and it does not report the unique product \
             identifier passport {passport_id} was submitted under. It reports: {}.",
            reported.join(", ")
        ),
        SubmissionConfirmation::StillChecking => "The registry has not finished checking that \
             submission, and a submission still being checked reports no passport to match \
             against. Try again once the registry has ruled on it."
            .to_owned(),
        SubmissionConfirmation::Unlisted { exhaustive: true } => "The registry lists no \
             submission with that correlation identifier. Check it against the registry's own \
             interface."
            .to_owned(),
        SubmissionConfirmation::Unlisted { exhaustive: false } => "No submission with that \
             correlation identifier was found in the part of the registry's task list this node \
             read, and the list is longer than that. It may be further on, so the handle could \
             not be checked."
            .to_owned(),
        // Unsupported, and anything the answer grows later: a handle that cannot be
        // checked is not recorded.
        _ => "This node's registry connection cannot read a submission's contents, so a handle \
              cannot be checked against it."
            .to_owned(),
    }
}

/// Whether `correlation_id` is the shape of something the registry could have
/// given: not empty, bounded, and free of whitespace and control characters.
fn well_formed(correlation_id: &str) -> bool {
    !correlation_id.is_empty()
        && correlation_id.chars().count() <= MAX_CORRELATION_ID_CHARS
        && !correlation_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

/// `POST /api/v1/dpp/{dppId}/registry/handle` — record the correlation identifier
/// of a submission whose handle this node lost, once the registry shows it to be
/// the passport's.
pub async fn record_registry_handle_handler(
    State(state): State<AppState>,
    // The gate is an extractor and precedes the body extractor, so a wrong-scope
    // caller is refused before the body is parsed.
    RequireAdmin(auth): RequireAdmin,
    Path(dpp_id): Path<String>,
    Json(body): Json<RecordHandleRequest>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let correlation_id = body.correlation_id.trim();
    if !well_formed(correlation_id) {
        return validation_error(&format!(
            "correlationId must be the registry's identifier for the submission: not empty, at \
             most {MAX_CORRELATION_ID_CHARS} characters, and without spaces or control \
             characters."
        ));
    }

    match state
        .service
        .record_registry_handle(passport_id, correlation_id, &auth)
        .await
    {
        Ok(RecordedHandle {
            correlation_id,
            report,
        }) => (
            StatusCode::OK,
            Json(RecordHandleResponse {
                passport_id: dpp_id,
                correlation_id,
                recorded: report.is_some(),
                registry: report,
                note: NOTE,
            }),
        )
            .into_response(),
        Err(why) => refusal(&dpp_id, why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each way a handle goes unrecorded has the status its documentation gives
    /// it, whatever the route's tests can or cannot reach: this pins the mapping
    /// itself, and `registry_handle_route` pins the ones it can construct over
    /// HTTP, including `NotConfigured`, on a node harnessed with no queues.
    #[test]
    fn each_refusal_has_the_status_the_route_documents() {
        use RecordHandleError as E;
        use dpp_domain::DppError;
        let status = |why| refusal("p", why).status();

        assert_eq!(status(E::NotConfigured), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(status(E::NoRegistration), StatusCode::NOT_FOUND);
        for held in [
            RegistrySyncStatus::Pending,
            RegistrySyncStatus::Submitted,
            RegistrySyncStatus::Registered,
            RegistrySyncStatus::Rejected,
            RegistrySyncStatus::Deactivated,
        ] {
            assert_eq!(status(E::NotAwaitingAHandle(held)), StatusCode::CONFLICT);
        }
        assert_eq!(status(E::HoldsAnotherHandle), StatusCode::CONFLICT);
        assert_eq!(
            status(E::CannotSayWhatWasSubmitted),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status(E::NotConfirmed(SubmissionConfirmation::StillChecking)),
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

    #[test]
    fn a_correlation_identifier_is_one_token() {
        assert!(well_formed("7c9e6679-7425-40de-944b-e07fc1f90ae7"));
        assert!(well_formed("corr:1/a_b-c"));
    }

    /// What is refused is what could not be an identifier, and what would make a
    /// stored value misleading when echoed in a message.
    #[test]
    fn what_could_not_be_an_identifier_is_refused() {
        assert!(!well_formed(""));
        assert!(!well_formed("two words"));
        assert!(!well_formed("tab\there"));
        assert!(!well_formed("line\nbreak"));
        assert!(!well_formed("nul\0byte"));
        assert!(!well_formed(&"x".repeat(MAX_CORRELATION_ID_CHARS + 1)));
        assert!(well_formed(&"x".repeat(MAX_CORRELATION_ID_CHARS)));
    }
}
