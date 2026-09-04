//! `POST /api/v1/dpp/{dppId}/lint` — on-demand plausibility-lint re-check (N10).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use crate::domain::passport_scope;
use crate::{extract::Json, middleware::scope::RequireWrite, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id};

/// One reason a publish would be refused, addressed to the field that causes it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishBlocker {
    /// JSON-Pointer-ish path, e.g. `/productGroupData/batteryModelId`.
    pub field: String,
    pub message: String,
}

/// Whether this passport would clear the publish gates that can be answered
/// without attempting the transition.
///
/// # What it covers, and what it cannot
///
/// The **category mandatory-content** gate and the product-group data/schema
/// gates. Not the registry-identity requirement, which is operator state rather
/// than passport state, and not the binding-compliance gate, which needs a
/// determination this endpoint does not run.
///
/// The mandatory-content half is the one that matters here. It is the gate that
/// most often refuses a battery — 38 fields for an EV — and until now it could
/// not be previewed anywhere: `dpp-core` made `check_mandatory_content` public
/// precisely so a caller could ask, but the method takes a `Passport` and the
/// only preview the engine had wired (`POST /dpp/validate`) holds an unsaved
/// request body. This route already loads the record, so it can simply ask.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishReadiness {
    /// `true` when the gates below would pass right now.
    pub ready: bool,
    /// Every blocking field, named individually. Empty when `ready`.
    pub blockers: Vec<PublishBlocker>,
    /// Whether Art. 77(1) requires a passport for this record at all.
    ///
    /// Reported beside the gates rather than instead of them. A caller being
    /// asked for thirty-eight data points deserves to know whether the article
    /// asks for them, and an operator publishing a portable battery deserves to
    /// know the record is their own artefact rather than a discharged duty —
    /// neither of which the blocker list can say.
    pub passport_scope: PassportScopeReport,
}

/// The Art. 77(1) answer, and a sentence when it is worth explaining.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportScopeReport {
    /// `required`, `voluntary`, or `notApplicable` for a non-battery.
    pub status: &'static str,
    /// Present when the answer needs justifying: an industrial battery with no
    /// declared capacity, or a voluntary passport this node still gates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The lint response: the passport, plus what publishing it would say.
///
/// `#[serde(flatten)]` keeps every field a client already reads exactly where it
/// was and adds one alongside, so this is additive rather than a reshape.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LintResponse {
    #[serde(flatten)]
    pub passport: crate::api::PassportResponse,
    pub publish_readiness: PublishReadiness,
}

/// Collect every gate this route can answer, as addressed blockers.
fn readiness_of(passport: &dpp_domain::passport::Passport) -> PublishReadiness {
    let mut blockers = Vec::new();

    if let Err(dpp_domain::DppError::Validation(errors)) = passport.check_mandatory_content() {
        blockers.extend(errors.errors.iter().map(|e| PublishBlocker {
            field: e.field.clone(),
            message: e.message.clone(),
        }));
    }

    let obligation = passport_scope::scope_of(passport.product_group_data.as_ref());
    PublishReadiness {
        ready: blockers.is_empty(),
        blockers,
        passport_scope: PassportScopeReport {
            status: match obligation {
                passport_scope::PassportScope::Required => "required",
                passport_scope::PassportScope::Voluntary => "voluntary",
                passport_scope::PassportScope::NotApplicable => "notApplicable",
            },
            note: passport_scope::scope_note(obligation, passport.product_group_data.as_ref()),
        },
    }
}

/// `POST /api/v1/dpp/{dppId}/lint` — recompute and persist the plausibility
/// lint pack's findings against the passport's current product group data, and
/// report whether the passport would publish.
///
/// Non-binding: findings never block publish and this endpoint never fails
/// on their account. Works regardless of passport status (Draft or
/// Published) — see [`crate::domain::service::PassportService::relint`].
///
/// **Write-scoped**, despite the findings being advisory. `relint` persists
/// (`patch_fields`), so this is a database write on every published passport
/// the caller can name — and it deliberately appends no audit entry, so the
/// write is also absent from the hash-chained trail. A `read` credential
/// performing an unlogged write is a scope-model violation whatever the field
/// is worth; the guard costs one line, and arguing about the field's importance
/// is the wrong axis.
pub async fn lint_handler(
    State(state): State<AppState>,
    RequireWrite(_auth): RequireWrite,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.relint(passport_id).await {
        Ok(p) => (
            StatusCode::OK,
            Json(LintResponse {
                publish_readiness: readiness_of(&p),
                passport: crate::api::PassportResponse::from(&p),
            }),
        )
            .into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(e) => internal_error(e),
    }
}
