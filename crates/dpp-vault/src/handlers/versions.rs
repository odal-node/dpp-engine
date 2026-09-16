//! `GET /api/v1/dpp/{dppId}/versions` — the passport's archived versions.
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — *"the archived version
//! corresponding to a given point in time shall be retrievable by authenticated
//! and authorized actors"*.
//!
//! 🚨 **Not `POST .../archive`**, which moves a passport to the terminal
//! `archived` lifecycle state after its retention period. Two different things
//! wear the word; this is the standard's sense — historical versions of a
//! passport that is still live. The naming collision is tracked upstream, where
//! the lifecycle status lives.

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::{domain::service::VersionAt, middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id, validation_error};

/// `?asOf=<RFC 3339>` — which moment to reconstitute.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsOf {
    /// The instant to answer for. Absent lists every archived version instead.
    pub as_of: Option<String>,
}

/// `GET /api/v1/dpp/{dppId}/versions` — list archived versions, or reconstitute one.
///
/// Without `asOf`, returns every archived version oldest first. With it, returns
/// the single version that was current at that instant — as a one-element array,
/// so the route answers with one shape rather than two.
///
/// # What `asOf` answers when nothing is archived for it
///
/// `404` in all cases, but **not with the same sentence**, because they are not
/// the same fact:
///
/// - the passport had not changed by then, or the moment is after its most
///   recent change — the live record is the state at that time, and the caller
///   already has a route for it;
/// - the moment is **before the passport was created**, where nothing was its
///   state, not even the live record.
///
/// 🚨 The third one is why this is not an `Option`. The store answers "the
/// earliest version that stopped being current after `at`", which for any
/// instant before the first change is the initial version — including instants
/// before the passport existed. Left alone, asking what a passport said in 1990
/// returned `200` and the initial record, asserting it existed in 1990.
///
/// # Access
///
/// Bearer, like every other operator route. The clause requires archived
/// attributes to carry *"the same access restrictions as the corresponding
/// attributes in the current digital product passport"*, and for the operator
/// reading its own passport those restrictions are none — so the whole record is
/// the correct answer here.
///
/// ⚠️ That equivalence is what makes this route simple, and it does **not**
/// extend to a credential-scoped reader. Serving versions to an audience-scoped
/// caller means running the live passport's policy over the archived document —
/// the *live* policy, because the clause ties archived attributes to the
/// **current** passport's restrictions rather than to the ones in force when the
/// version was taken. No such route exists yet; building one without that step
/// would disclose fields the current passport withholds.
pub async fn versions_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
    Query(query): Query<AsOf>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match query.as_of {
        None => match state.service.versions(passport_id).await {
            Ok(versions) => (StatusCode::OK, Json(versions)).into_response(),
            Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
            Err(e) => internal_error(e),
        },
        Some(raw) => {
            let Ok(at) = chrono::DateTime::parse_from_rfc3339(&raw) else {
                return validation_error("asOf must be an RFC 3339 timestamp.");
            };
            match state
                .service
                .version_at(passport_id, at.with_timezone(&chrono::Utc))
                .await
            {
                // A one-element array, not the bare object. `200` is one shape
                // on this route whether `asOf` was given or not, so a client
                // parses the body the same way either way and the description
                // has one schema rather than a `oneOf` the caller has to
                // discriminate by recalling what it sent.
                Ok(VersionAt::Found(version)) => {
                    (StatusCode::OK, Json(vec![version])).into_response()
                }
                Ok(VersionAt::Live) => not_found_error(
                    "No archived version covers that moment — the passport had not changed by \
                     then, or the moment is after its most recent change. The live record is \
                     the state at that time.",
                ),
                // A different 404, and the wording is the whole point: the
                // sentence above would tell a caller that the live record is the
                // state at a moment when there was no record at all.
                Ok(VersionAt::BeforeItExisted) => not_found_error(
                    "That moment is before this passport was created, so nothing was its state \
                     then — not the archive, and not the live record either.",
                ),
                Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
                Err(e) => internal_error(e),
            }
        }
    }
}
