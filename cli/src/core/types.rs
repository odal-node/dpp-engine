//! Shared parameter and outcome types passed between `core` actions and rendering.

use serde::Serialize;

// ── Infrastructure ───────────────────────────────────────────────────────────

pub struct StatusReport {
    pub services: Vec<ServiceHealth>,
}

pub struct ServiceHealth {
    pub name: String,
    /// For HTTP checks, the health URL probed. For container checks, the
    /// container name (no URL to probe).
    pub url: String,
    pub status: ServiceStatus,
    /// HTTP round-trip latency. `None` for container checks (not applicable).
    pub latency_ms: Option<u64>,
}

pub enum ServiceStatus {
    Ok,
    HttpError(u16),
    Failed(String),
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
    /// Exact match on the facility identifier (ESPR Annex III; ADR-006).
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
    pub sector: String,
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

pub struct SchemaCheckResult {
    pub local_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub offline: bool,
    pub warning: Option<String>,
}

// ── Progress ─────────────────────────────────────────────────────────────────

pub enum ProgressEvent {
    Started { total: Option<u64> },
    Tick { current: u64 },
    Done,
}
