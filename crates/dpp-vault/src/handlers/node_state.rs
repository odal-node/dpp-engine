use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use dpp_types::STANDALONE_OPERATOR_ID;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::internal_error;

/// Setup/readiness state for a node, used by the CLI to keep `odal bootstrap`
/// idempotent.
/// Public so the OpenAPI contract test can serialise it and check the shape
/// against `components/schemas/NodeState`. A response type only the handler can
/// name is a response type nothing can gate.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeState {
    /// True once the node has been claimed — i.e. at least one active API key
    /// has been minted. Re-running bootstrap on a claimed node is refused.
    pub bootstrapped: bool,
    /// True once the operator's responsible-economic-operator identity is
    /// complete enough to publish passports.
    pub operator_complete: bool,
    /// Deployment profile and per-port trust modes — the ghost-honesty signal.
    /// Absent on a standalone vault, which resolves no trust ports.
    ///
    /// Untyped and flattened, so the keys it contributes (`profile`,
    /// `trustMode`) are **not** covered by the OpenAPI contract test the way
    /// the typed fields are — a `serde_json::Value` has no field list to check
    /// a schema against. Giving this a real type is the way to close that.
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub trust: Option<serde_json::Value>,
    /// Active Compliance Current ruleset version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_version: Option<String>,
}

/// `GET /api/v1/node/state` — report whether the node is claimed, whether the
/// operator identity is complete, and the node's trust posture. Authenticated
/// (API key or local admin), so the CLI can call it during bootstrap before any
/// key exists.
///
/// The trust posture lives here rather than on the public `/health` because
/// which trust ports are degraded, and how, is a targeting signal — the same
/// reasoning that keeps `/metrics` off the public router. `/health` answers
/// liveness to anyone; what the node's trust actually rests on is for a caller
/// who is entitled to ask.
pub async fn node_state_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let bootstrapped = match state.api_key_service.list().await {
        Ok(keys) => !keys.is_empty(),
        Err(e) => return internal_error(e),
    };
    let operator_complete = match state.operator_service.get(STANDALONE_OPERATOR_ID).await {
        Ok(cfg) => cfg.is_complete(),
        Err(e) => return internal_error(e),
    };

    (
        StatusCode::OK,
        Json(NodeState {
            bootstrapped,
            operator_complete,
            trust: state.trust.as_ref().map(|t| t.posture_json()),
            ruleset_version: state.ruleset_version.clone(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::NodeState;
    use dpp_types::trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort};

    fn report() -> NodeTrustReport {
        NodeTrustReport::new(
            NodeProfile::Development,
            vec![TrustPort {
                port: "seal",
                mode: TrustMode::Ghost,
                required: true,
            }],
        )
    }

    /// Pins the wire shape, because it is documented in the API description and
    /// two of its keys arrive by a different route from the rest: `profile` and
    /// `trustMode` are flattened in from the trust report's own JSON, which emits
    /// them already in `camelCase`, matching the rest of this response.
    #[test]
    fn trust_fields_flatten_in_beside_the_setup_state() {
        let json = serde_json::to_value(NodeState {
            bootstrapped: true,
            operator_complete: false,
            trust: Some(report().posture_json()),
            ruleset_version: Some("baseline".into()),
        })
        .expect("serialises");

        assert_eq!(json["bootstrapped"], true);
        assert_eq!(json["operatorComplete"], false);
        assert_eq!(json["rulesetVersion"], "baseline");
        assert_eq!(json["profile"], "development");
        assert_eq!(json["trustMode"]["seal"], "ghost");
    }

    /// A standalone vault resolves no trust ports, and must say nothing rather
    /// than report a null posture a client could read as "no ghosts".
    #[test]
    fn a_node_without_a_trust_report_omits_the_fields_entirely() {
        let json = serde_json::to_value(NodeState {
            bootstrapped: true,
            operator_complete: true,
            trust: None,
            ruleset_version: None,
        })
        .expect("serialises");

        assert_eq!(
            json.as_object().map(serde_json::Map::len),
            Some(2),
            "only the two setup-state fields belong here: {json}"
        );
        for absent in ["profile", "trustMode", "rulesetVersion"] {
            assert!(json.get(absent).is_none(), "`{absent}` must be omitted");
        }
    }
}
