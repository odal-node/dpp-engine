//! Shared parameter and outcome types passed between `core` actions and rendering.

use std::collections::BTreeMap;

use serde::Serialize;

// ── Infrastructure ───────────────────────────────────────────────────────────

/// What `odal status` found.
///
/// HTTP probes and container checks are kept apart deliberately. A probe has a
/// URL and a round-trip latency; a container has a name and a state and no
/// latency at all. Holding them in one list forced an `Option` on the latency
/// and rendered them in one table, which implied a uniformity that is not there.
pub struct StatusReport {
    pub probes: Vec<ServiceHealth>,
    pub containers: Vec<ContainerHealth>,
    /// The node's own account of itself, when the caller could read it.
    /// `None` when unauthenticated, unreachable, or not entitled — `status`
    /// reports what it could see rather than failing over what it could not.
    pub node: Option<NodeState>,
}

impl StatusReport {
    /// True when every check that ran came back healthy.
    pub fn all_ok(&self) -> bool {
        self.probes.iter().all(|s| s.status.is_ok())
            && self.containers.iter().all(|c| c.status.is_ok())
    }
}

/// One HTTP health probe: the URL reached and how long it took.
pub struct ServiceHealth {
    pub name: String,
    pub url: String,
    pub status: ServiceStatus,
    pub latency_ms: u64,
}

/// One Docker container, as `docker compose ps` reports it.
pub struct ContainerHealth {
    /// The compose service name (`postgres`, `nats`, …).
    pub service: String,
    /// The running container's name. Empty when nothing is running.
    pub container: String,
    pub status: ServiceStatus,
}

pub enum ServiceStatus {
    Ok,
    HttpError(u16),
    Failed(String),
}

impl ServiceStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, ServiceStatus::Ok)
    }
}

// ── Import ───────────────────────────────────────────────────────────────────

pub struct ImportParams {
    pub file: String,
}

pub struct ImportSummary {
    pub created: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

// ── Validate ─────────────────────────────────────────────────────────────────

pub struct ValidationReport {
    pub records: Vec<ValidationRecord>,
}

pub struct ValidationRecord {
    pub id: String,
    pub product_name: String,
    pub issues: Vec<String>,
}

// ── Publish ──────────────────────────────────────────────────────────────────

pub struct PublishParams {
    pub id: Option<String>,
}

pub struct PublishSummary {
    pub published: usize,
    pub failed: usize,
    pub errors: Vec<String>,
    pub items: Vec<PassportPublishResult>,
}

pub struct PassportPublishResult {
    pub id: String,
    pub name: String,
    pub success: bool,
    pub qr_url: Option<String>,
    pub error: Option<String>,
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

pub struct SuspendParams {
    pub id: String,
}

pub struct ArchiveParams {
    pub id: String,
}

pub struct HistoryParams {
    pub id: String,
}

pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub actor: String,
}

// ── Export ───────────────────────────────────────────────────────────────────

pub struct ExportParams {
    pub format: String,
    pub status_filter: Option<String>,
}

pub struct ExportResult {
    pub data: String,
}

// ── List / Browse ────────────────────────────────────────────────────────────

pub struct ListParams {
    pub status: Option<String>,
    pub q: Option<String>,
    /// Exact match on the facility identifier (ESPR Annex III).
    pub facility_id: Option<String>,
    pub limit: u32,
    pub skip: u32,
}

/// One row in a passport list — enough to recognise and act on a passport
/// without ever handling its UUID by hand.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportSummary {
    pub id: String,
    pub product_name: String,
    pub product_group: String,
    pub status: String,
    pub batch: Option<String>,
    pub updated: String,
}

#[derive(Serialize)]
pub struct PassportPage {
    pub rows: Vec<PassportSummary>,
    /// Status-filtered count from the vault. NOTE: the vault's `count()` ignores
    /// the text search `q`, so this is only exact when `q` is empty.
    pub total: u64,
    pub skip: u32,
    pub limit: u32,
    /// Whether more pages exist. Computed robustly (full page ⇒ maybe more) so it
    /// stays correct even when `total` doesn't reflect a `q` search.
    pub has_more: bool,
}

// ── Onboarding ───────────────────────────────────────────────────────────────

/// Operator-identity fields supplied to bootstrap. All optional: bootstrap's job
/// is to mint the first key; the legal identity is editable later via
/// `operator set` and is enforced at publish time, not at key-mint.
pub struct BootstrapParams {
    pub legal_name: Option<String>,
    pub country: Option<String>,
    pub address: Option<String>,
    pub contact_email: Option<String>,
    pub did_web_url: Option<String>,
}

pub struct BootstrapResult {
    pub api_key: String,
}

/// Node setup/readiness state (from `GET /api/v1/node/state`).
pub struct NodeState {
    /// True once at least one active API key exists (node has been claimed).
    pub bootstrapped: bool,
    /// True once the operator identity is complete enough to publish.
    pub operator_complete: bool,
    /// Deployment profile (`development` / `production`). Absent on a
    /// standalone vault, which resolves no trust ports.
    pub profile: Option<String>,
    /// Per-port trust mode, e.g. `seal → ghost`. Empty when the node reports
    /// no posture — which is not the same as reporting no ghosts, so an empty
    /// map must render as "not reported", never as "all real".
    pub trust_mode: BTreeMap<String, String>,
    /// Active Compliance Current ruleset version.
    pub ruleset_version: Option<String>,
}

impl NodeState {
    /// True when the node reported any trust posture at all.
    pub fn has_trust_posture(&self) -> bool {
        self.profile.is_some() || !self.trust_mode.is_empty()
    }

    /// The trust ports running on a stand-in rather than the real thing.
    pub fn ghost_ports(&self) -> Vec<&str> {
        self.trust_mode
            .iter()
            .filter(|(_, mode)| mode.as_str() == "ghost")
            .map(|(port, _)| port.as_str())
            .collect()
    }
}

/// What the presented credential actually is (`GET /api/v1/whoami`).
pub struct WhoAmI {
    pub user_id: String,
    pub scope: String,
    /// The API key's row id. Absent for local-admin Basic auth, which has no
    /// key row — rendered as such rather than as a placeholder id.
    pub key_id: Option<String>,
}

/// The verdict from `POST /api/v1/dpp/validate` — would this body be accepted,
/// without creating anything.
pub struct DryRunVerdict {
    /// Would `POST /api/v1/dpp` accept it?
    pub create_valid: bool,
    /// Would the product group data clear the publish-time schema gates?
    ///
    /// Deliberately not named for publish: it is one of publish's
    /// preconditions, not all of them. Registry identity and
    /// category-mandatory content also gate publish and are not checked here.
    pub product_group_data_valid: bool,
    /// Why not, when either verdict is false.
    pub detail: Option<String>,
}

pub struct OperatorUpdateParams {
    pub legal_name: Option<String>,
    pub trade_name: Option<String>,
    pub address: Option<String>,
    pub country: Option<String>,
    pub contact_email: Option<String>,
    pub did_web_url: Option<String>,
    pub retention_policy_days: Option<i64>,
}

impl OperatorUpdateParams {
    pub fn is_empty(&self) -> bool {
        self.legal_name.is_none()
            && self.trade_name.is_none()
            && self.address.is_none()
            && self.country.is_none()
            && self.contact_email.is_none()
            && self.did_web_url.is_none()
            && self.retention_policy_days.is_none()
    }
}

// ── API keys ─────────────────────────────────────────────────────────────────

pub struct KeyCreateParams {
    pub name: String,
}

pub struct KeyCreateResult {
    pub secret: String,
    pub name: String,
}

pub struct KeyEntry {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub is_active: bool,
}

pub struct KeyRevokeParams {
    pub id: String,
}

// ── Schema ───────────────────────────────────────────────────────────────────

/// What `odal schema check` could actually read from the node.
///
/// Every field is optional because every one of them can be unreadable: the
/// health probe may not answer, and the ruleset lives behind authentication.
/// Reporting "unknown" for a value that was never fetched is what made the old
/// output indistinguishable from a real answer.
pub struct SchemaCheckResult {
    /// The node's own build version.
    pub node_version: Option<String>,
    /// The `dpp-core` version it applies — what decides which regulatory
    /// schemas and rules are in force for this node.
    pub core_version: Option<String>,
    /// Active Compliance Current ruleset. `None` without a credential.
    pub ruleset_version: Option<String>,
}

// ── Progress ─────────────────────────────────────────────────────────────────

pub enum ProgressEvent {
    Started { total: Option<u64> },
    Tick { current: u64 },
    Done,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture(ports: &[(&str, &str)]) -> NodeState {
        NodeState {
            bootstrapped: true,
            operator_complete: true,
            profile: Some("development".into()),
            trust_mode: ports
                .iter()
                .map(|(p, m)| ((*p).to_owned(), (*m).to_owned()))
                .collect(),
            ruleset_version: Some("baseline".into()),
        }
    }

    /// Only `ghost` is a stand-in. `sandbox` is a real service in a test tier,
    /// so warning about it would cry wolf and teach operators to ignore the line
    /// that matters.
    #[test]
    fn only_ghost_ports_are_called_stand_ins() {
        let node = posture(&[
            ("seal", "ghost"),
            ("compliance", "sandbox"),
            ("archive", "live"),
        ]);
        assert_eq!(node.ghost_ports(), vec!["seal"]);
    }

    /// A node that resolves no trust ports must render nothing, because "not
    /// reported" and "nothing is a ghost" are different claims and only one of
    /// them is safe to make on an operator's behalf.
    #[test]
    fn a_node_reporting_no_posture_makes_no_claim() {
        let silent = NodeState {
            bootstrapped: true,
            operator_complete: true,
            profile: None,
            trust_mode: BTreeMap::new(),
            ruleset_version: None,
        };
        assert!(!silent.has_trust_posture());
        assert!(silent.ghost_ports().is_empty());
        assert!(posture(&[("seal", "ghost")]).has_trust_posture());
    }

    /// A container failure must fail the run. Before the split these lived in
    /// one list, so it is worth pinning that both halves still count.
    #[test]
    fn all_ok_covers_probes_and_containers() {
        let probe = |status| ServiceHealth {
            name: "vault".into(),
            url: "http://localhost:8001/vault/health".into(),
            status,
            latency_ms: 3,
        };
        let container = |status| ContainerHealth {
            service: "postgres".into(),
            container: "odal-node-postgres-1".into(),
            status,
        };

        let healthy = StatusReport {
            probes: vec![probe(ServiceStatus::Ok)],
            containers: vec![container(ServiceStatus::Ok)],
            node: None,
        };
        assert!(healthy.all_ok());

        let bad_probe = StatusReport {
            probes: vec![probe(ServiceStatus::HttpError(503))],
            containers: vec![container(ServiceStatus::Ok)],
            node: None,
        };
        assert!(!bad_probe.all_ok());

        let bad_container = StatusReport {
            probes: vec![probe(ServiceStatus::Ok)],
            containers: vec![container(ServiceStatus::Failed("exited".into()))],
            node: None,
        };
        assert!(!bad_container.all_ok());
    }
}
