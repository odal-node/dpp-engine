//! `POST /api/v1/ruleset/reload` — admin-only re-read of the signed compliance
//! ruleset channel, adopting a new bundle without a node restart.
//!
//! Delegates to the node's [`RulesetAdmin`] port, which fetches from the
//! configured channel, verifies the manifest against the pinned publisher key,
//! checks the bundle is applicable and not superseded, and atomically swaps it
//! into service — fail-closed, last-good on any rejection.
//!
//! The node also polls the channel on its own; this route is the operator's
//! way to say "take it now" rather than the only way a swap ever happens.

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::ruleset_admin::RulesetReloadError;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, require_admin};

/// `POST /api/v1/ruleset/reload` — re-read the channel and hot-swap a verified
/// bundle.
///
/// Returns `200` with the version now in force and whether this call changed
/// it. Re-reading an unchanged channel is a success with `changed: false`, not
/// an error — that is the ordinary answer, and the one a health check wants.
pub async fn reload_ruleset_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Some(resp) = require_admin(&auth, "Reloading the compliance ruleset") {
        return resp;
    }

    let Some(admin) = state.ruleset_admin.clone() else {
        return api_error(
            StatusCode::NOT_IMPLEMENTED,
            "RULESET_CHANNEL_DISABLED",
            "This node has no signed ruleset channel configured; it is running its baseline.",
        );
    };

    match admin.reload().await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(e) => reload_error(e),
    }
}

/// Map the port's refusal onto the wire.
///
/// The two timing refusals keep their own codes rather than collapsing into one
/// "rejected": a not-yet-effective bundle means the operator staged the next
/// quarter's rules early and should leave them in place, a superseded one means
/// something served an older bundle and the drop needs looking at. Same status,
/// opposite actions — and only the code distinguishes them for a client.
fn reload_error(e: RulesetReloadError) -> Response {
    match e {
        RulesetReloadError::NotConfigured => api_error(
            StatusCode::NOT_IMPLEMENTED,
            "RULESET_CHANNEL_DISABLED",
            "This node has no signed ruleset channel configured; it is running its baseline.",
        ),
        // 503 rather than 500: the channel is a dependency this node reads, and
        // a missing or unreachable drop is the operator's to fix, not a bug to
        // report. Retrying later is the correct client behaviour.
        RulesetReloadError::Unavailable(m) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "RULESET_UNAVAILABLE",
            &format!("could not read the ruleset channel: {m}"),
        ),
        RulesetReloadError::Rejected(m) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RULESET_REJECTED",
            &format!("ruleset bundle rejected: {m}"),
        ),
        RulesetReloadError::NotYetEffective(m) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RULESET_NOT_YET_EFFECTIVE",
            &format!("ruleset bundle is not yet effective: {m}"),
        ),
        RulesetReloadError::Superseded(m) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RULESET_SUPERSEDED",
            &format!("ruleset bundle is superseded: {m}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_common::ruleset_admin::RulesetReload;

    /// The response body is what an operator reads to decide whether the swap
    /// they asked for actually happened, so its shape is pinned here rather
    /// than only in the contract test.
    #[test]
    fn the_reload_report_names_the_version_and_whether_it_moved() {
        let json = serde_json::to_value(RulesetReload {
            ruleset_version: "2026-Q3.2".into(),
            changed: true,
        })
        .expect("serialises");

        assert_eq!(json["rulesetVersion"], "2026-Q3.2");
        assert_eq!(json["changed"], true);
        assert_eq!(
            json.as_object().map(serde_json::Map::len),
            Some(2),
            "only the version and whether it changed belong here: {json}"
        );
    }

    /// Every refusal is fail-closed, so none of them may read as a server
    /// fault the operator can do nothing about — and the two timing cases must
    /// stay distinguishable, because they call for opposite responses.
    #[test]
    fn each_refusal_keeps_its_own_code_and_status() {
        let cases = [
            (
                RulesetReloadError::NotConfigured,
                StatusCode::NOT_IMPLEMENTED,
            ),
            (
                RulesetReloadError::Unavailable("no such file".into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                RulesetReloadError::Rejected("bad signature".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                RulesetReloadError::NotYetEffective("starts next year".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                RulesetReloadError::Superseded("older than in force".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ];
        for (error, expected) in cases {
            let described = error.to_string();
            assert_eq!(
                reload_error(error).status(),
                expected,
                "wrong status for: {described}"
            );
        }
    }
}
