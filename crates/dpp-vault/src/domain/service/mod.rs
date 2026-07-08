//! Core domain service for the passport lifecycle (create → publish → suspend → archive).
//!
//! Split by lifecycle stage — each sibling file is one or more `impl
//! PassportService` blocks for the same type. Every method here owes the
//! same two side-effects unless its own doc says otherwise: an audit entry
//! (`self.audit.append`, always awaited — a failure propagates) and a
//! best-effort event (`self.emit`, fire-after-commit — a failure is logged,
//! never propagated, since the DB write is the source of truth).
//!
//! - [`query`] — read paths: `find_*`, `list`, `count`, `history`
//! - [`create`] — `create`, `update`, and their private helpers `apply_patch`/`apply_compliance`
//! - [`publish`] — `publish` and its private helpers `validate_schema_for_publish`/`build_gs1_or_fallback_url`
//! - [`lifecycle`] — `suspend`, `archive`
//! - [`eol`] — `declare_eol`
//! - [`transfer`] — `initiate_transfer`, `accept_transfer`
//! - [`evidence`] — `export_evidence` (N02 offline-verifiable dossier)
//! - [`seal`] — reserved seat for the eIDAS seal step in `publish` (not wired yet)

mod create;
mod eol;
mod evidence;
mod lifecycle;
mod publish;
mod query;
mod seal;
mod transfer;

use std::sync::Arc;

use dpp_common::event::{DppEvent, EventBus};
use dpp_domain::ports::{
    archive::ArchivePort, compliance::ComplianceRegistry, identity_port::IdentityPort,
    passport_repo::PassportRepository, registry_sync::RegistrySyncPort,
};
use dpp_types::{
    STANDALONE_OPERATOR_ID, audit::AuditRepository, operator::OperatorConfigRepository,
    registry_sync::RegistrySyncOutbox, transfer::TransferStore,
};

/// Core domain service for the passport lifecycle.
///
/// Orchestrates create / update / publish / suspend / archive and history
/// with audit logging, event emission, compliance enrichment, and EU registry sync.
/// Single-tenant: the service has no tenant/operator scope — one service per node.
pub struct PassportService {
    pub repo: Arc<dyn PassportRepository>,
    pub identity: Arc<dyn IdentityPort>,
    pub compliance: Arc<dyn ComplianceRegistry>,
    pub audit: Arc<dyn AuditRepository>,
    pub events: Arc<dyn EventBus>,
    pub registry_sync: Arc<dyn RegistrySyncPort>,
    pub archive: Arc<dyn ArchivePort>,
    /// Transactional outbox for EU registry registration. When present (the
    /// Postgres node), publish persists the passport and enqueues its
    /// registration atomically, and a background drain task calls
    /// `registry_sync` — so a killed node never loses a registration. When
    /// `None` (test doubles / in-memory repo), publish falls back to the legacy
    /// inline path.
    pub registry_outbox: Option<Arc<dyn RegistrySyncOutbox>>,
    /// Persistence for transfer-of-responsibility chains. `None` disables
    /// the transfer endpoints (test doubles without a transfer store).
    pub transfer_store: Option<Arc<dyn TransferStore>>,
    /// ISO 3166-1 alpha-2 country code of this operator, sourced from
    /// `OperatorConfig.country` at startup. Used in EU registry registration payloads.
    pub operator_country: String,
    /// Reader for the operator's registry identity (default facility per ESPR
    /// Annex III, primary operator identifier per Art. 13). Read **live** on
    /// create so changes made via the API/CLI take effect without a node restart.
    /// `None` disables stamping (e.g. in tests that don't exercise it).
    pub registry_reader: Option<Arc<dyn OperatorConfigRepository>>,
}

impl PassportService {
    /// Construct the service with all required port adapters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: Arc<dyn PassportRepository>,
        identity: Arc<dyn IdentityPort>,
        compliance: Arc<dyn ComplianceRegistry>,
        audit: Arc<dyn AuditRepository>,
        events: Arc<dyn EventBus>,
        registry_sync: Arc<dyn RegistrySyncPort>,
        archive: Arc<dyn ArchivePort>,
        operator_country: String,
    ) -> Self {
        Self {
            repo,
            identity,
            compliance,
            audit,
            events,
            registry_sync,
            archive,
            registry_outbox: None,
            transfer_store: None,
            operator_country,
            registry_reader: None,
        }
    }

    /// Provide the transfer-chain store, enabling the transfer-of-responsibility
    /// endpoints.
    #[must_use]
    pub fn with_transfer_store(mut self, store: Arc<dyn TransferStore>) -> Self {
        self.transfer_store = Some(store);
        self
    }

    /// Provide the transactional registry-sync outbox. When set, publish routes
    /// the passport write + registration enqueue through a single transaction
    /// (`commit_publish`) and the inline fire-after-commit register call is
    /// skipped — the node's drain task performs registration instead.
    #[must_use]
    pub fn with_registry_outbox(mut self, outbox: Arc<dyn RegistrySyncOutbox>) -> Self {
        self.registry_outbox = Some(outbox);
        self
    }

    /// Provide the reader used to stamp the default facility (ESPR Annex III) and
    /// primary operator identifier (ESPR Art. 13) onto new passports. Read live on
    /// each create, so `odal facility`/`operator-id` changes apply immediately.
    #[must_use]
    pub fn with_registry_reader(mut self, reader: Arc<dyn OperatorConfigRepository>) -> Self {
        self.registry_reader = Some(reader);
        self
    }

    /// Emit an event after a successful commit. Failures are logged, never
    /// propagated — the DB write is the source of truth.
    async fn emit(&self, event_type: &str, data: serde_json::Value) {
        let event = DppEvent::v1(event_type, STANDALONE_OPERATOR_ID, data);
        if let Err(e) = self.events.publish(&event).await {
            tracing::warn!(
                event_type = %event.event_type,
                event_id = %event.event_id,
                error = %e,
                "failed to publish event (non-fatal)"
            );
        }
    }
}

/// Process-wide sector catalog (manifests parsed once). Shared across the
/// split lifecycle files — `super::catalog()` from any of them.
fn catalog() -> &'static dpp_domain::SectorCatalog {
    static CATALOG: std::sync::OnceLock<dpp_domain::SectorCatalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(dpp_domain::SectorCatalog::new)
}

/// Process-wide versioned JSON Schema registry (parsed once).
fn schema_registry() -> &'static dpp_domain::schemas::VersionedSchemaRegistry {
    static REGISTRY: std::sync::OnceLock<dpp_domain::schemas::VersionedSchemaRegistry> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(dpp_domain::schemas::VersionedSchemaRegistry::new)
}
