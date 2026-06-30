//! Core domain service for the passport lifecycle (create → publish → suspend → archive).

use std::sync::Arc;

use chrono::Utc;
use dpp_digital_link::build_qr_url;
use dpp_domain::{
    domain::{
        error::DppError,
        passport::{Passport, PassportId},
        sector::{CarbonFootprint, RepairabilityScore, SectorData},
        status::PassportStatus,
    },
    ports::{
        archive::ArchivePort,
        compliance::ComplianceRegistry,
        identity_port::IdentityPort,
        passport_repo::PassportRepository,
        registry_sync::{RegistrationRequest, RegistrySyncPort},
    },
};
use metrics;

use dpp_common::{
    event::{self, DppEvent, EventBus},
    event_codes,
};
use dpp_types::{
    STANDALONE_OPERATOR_ID,
    audit::{AuditEntry, AuditRepository},
    auth::AuthContext,
    operator::OperatorConfigRepository,
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
            operator_country,
            registry_reader: None,
        }
    }

    /// Provide the reader used to stamp the default facility (ESPR Annex III) and
    /// primary operator identifier (ESPR Art. 13) onto new passports. Read live on
    /// each create, so `odal facility`/`operator-id` changes apply immediately.
    #[must_use]
    pub fn with_registry_reader(mut self, reader: Arc<dyn OperatorConfigRepository>) -> Self {
        self.registry_reader = Some(reader);
        self
    }

    /// Create a new passport in `Draft` status.
    ///
    /// Assigns a fresh `PassportId`, normalises `schema_version` from the sector
    /// catalog, runs compliance enrichment, persists, appends an audit entry,
    /// and emits `dpp.passport.created` (non-blocking — failure is logged only).
    #[tracing::instrument(skip(self, passport), fields(passport_id = tracing::field::Empty))]
    pub async fn create(
        &self,
        mut passport: Passport,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        passport.id = PassportId::new();
        tracing::Span::current().record("passport_id", passport.id.to_string().as_str());
        passport.status = PassportStatus::Draft;
        passport.created_at = Utc::now();
        passport.updated_at = Utc::now();
        passport.schema_version = catalog()
            .current_schema_version(passport.sector.catalog_key())
            .unwrap_or("1.0.0")
            .to_owned();

        // Stamp the economic-operator registry identifiers (ESPR Annex III
        // facility + Art. 13 operator identifier) when the caller didn't supply
        // them, so EU registry payloads are complete. Read live from the operator
        // config so identifiers managed via the API/CLI apply without a restart.
        if let Some(reader) = &self.registry_reader {
            if passport.facility_id.is_none() {
                passport.facility_id = reader
                    .default_facility_identifier(STANDALONE_OPERATOR_ID)
                    .await
                    .unwrap_or(None);
            }
            if passport.operator_identifier.is_none() {
                passport.operator_identifier = reader
                    .primary_operator_identifier(STANDALONE_OPERATOR_ID)
                    .await
                    .unwrap_or(None);
            }
        }

        apply_compliance(&mut passport, &*self.compliance);

        let created = self.repo.create(passport).await?;

        let entry = AuditEntry::new(
            &created.id.to_string(),
            "created",
            auth,
            None,
            Some(&PassportStatus::Draft.to_string()),
        );
        self.audit.append(entry).await?;

        // Event emitted after commit — failure is logged, not propagated.
        self.emit(
            event::subjects::PASSPORT_CREATED,
            serde_json::json!({
                "passportId": created.id.to_string(),
                "status": "draft",
            }),
        )
        .await;

        Ok(created)
    }

    /// Fetch a passport by id regardless of status.
    ///
    /// # Errors
    ///
    /// Returns `DppError::NotFound` if the id is unknown.
    pub async fn find_by_id(&self, id: PassportId) -> Result<Passport, DppError> {
        match self.repo.find_by_id(id).await? {
            Some(p) => Ok(p),
            None => Err(DppError::NotFound(id.to_string())),
        }
    }

    /// Fetch a published passport by id, or `None` if unpublished or unknown.
    pub async fn find_published(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.repo.find_published_by_id(id).await
    }

    /// Fetch a published passport by GS1 GTIN (O(n) scan — see `PgPassportRepo`).
    pub async fn find_published_by_gtin(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        self.repo.find_published_by_gtin(gtin).await
    }

    /// Fetch a passport in any status, including `Archived`. Returns `None` if unknown.
    pub async fn find_by_id_any_status(
        &self,
        id: PassportId,
    ) -> Result<Option<Passport>, DppError> {
        self.repo.find_by_id_any_status(id).await
    }

    /// Paginated list of passports with optional status, text, and facility filter.
    pub async fn list(
        &self,
        status: Option<PassportStatus>,
        q: Option<&str>,
        facility_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        self.repo.list(status, q, facility_id, limit, offset).await
    }

    /// Count passports, optionally filtered by status and/or facility.
    pub async fn count(
        &self,
        status: Option<PassportStatus>,
        facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        self.repo.count(status, facility_id).await
    }

    /// Partial-update a draft passport.
    ///
    /// Rejects updates to non-`Draft` passports. Validates the patch, enriches
    /// compliance fields, writes only the changed fields to the DB (`patch_fields`),
    /// appends an audit entry, and emits `dpp.passport.updated`.
    #[tracing::instrument(skip(self, patch), fields(passport_id = %id))]
    pub async fn update(
        &self,
        id: PassportId,
        patch: serde_json::Value,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        let mut passport = self.find_by_id(id).await?;

        if !matches!(passport.status, PassportStatus::Draft) {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Draft.to_string(),
            });
        }

        // Validate patch fields using a temporary copy, then build a
        // minimal delta — only the changed fields are written (B-03).
        apply_patch(&mut passport, &patch)?;
        let pre_compliance_co2e = passport.co2e_per_unit.clone();
        let pre_compliance_repair = passport.repairability_score.clone();
        apply_compliance(&mut passport, &*self.compliance);

        // Start delta from the patch body (already camelCase DB field names).
        let mut delta = patch;
        if let serde_json::Value::Object(ref mut m) = delta {
            // Add compliance-enriched values if they were filled in.
            if passport.co2e_per_unit != pre_compliance_co2e
                && let Some(ref v) = passport.co2e_per_unit
            {
                m.insert("co2ePerUnit".into(), serde_json::json!(v));
            }
            if passport.repairability_score != pre_compliance_repair
                && let Some(ref v) = passport.repairability_score
            {
                m.insert("repairabilityScore".into(), serde_json::json!(v));
            }
        }

        let updated = self.repo.patch_fields(id, delta).await?;

        let entry = AuditEntry::new(&updated.id.to_string(), "updated", auth, None, None);
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_UPDATED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": updated.status.to_string(),
            }),
        )
        .await;

        Ok(updated)
    }

    /// Sign and publish a draft passport with Ed25519 / JWS.
    ///
    /// Validates sector data, calls the identity service to sign, atomically
    /// writes the JWS + QR URL + `Published` status, seals the retention clock,
    /// fires non-blocking EU registry sync, and emits `dpp.passport.published`.
    ///
    /// # Errors
    ///
    /// Returns `DppError::InvalidTransition` if the passport is not in a publishable
    /// state, or `DppError::Signing` if the identity service fails.
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    pub async fn publish(&self, id: PassportId, auth: &AuthContext) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport
            .status
            .can_transition_to(&PassportStatus::Published)
        {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Published.to_string(),
            });
        }

        // Publish-time validation (domain Gap 7 / vault V3): never sign sector
        // data that fails its JSON Schema + cross-field rules.
        //
        // NOTE: this validates sector data *when present*. Hard-requiring its
        // presence at publish (a published EU DPP should always carry sector
        // data) is the stricter completeness policy — deferred until the
        // integration fixtures that publish minimal passports are updated and a
        // Docker run confirms them (roadmap 1.3).
        if let Some(sector_data) = passport.sector_data.as_ref() {
            dpp_domain::validate_sector_data(sector_data).map_err(DppError::Validation)?;

            // JSON Schema gate (fail-closed): enum sets, string patterns, and
            // numeric ranges that the Rust types don't enforce. Runs after typed
            // validation so field-level messages are the primary signal.
            let schema_key = sector_data.sector().catalog_key();
            if let Some(schema_version) = catalog().resolve_schema_version(schema_key, None) {
                let mut sd_json = serde_json::to_value(sector_data)
                    .map_err(|e| DppError::Serialisation(e.to_string()))?;
                // SectorData is internally tagged; schemas validate the inner object.
                if let Some(obj) = sd_json.as_object_mut() {
                    obj.remove("sector");
                }
                schema_registry()
                    .validate_strict(schema_key, &schema_version, &sd_json)
                    .map_err(DppError::from)?;
            } else {
                // No versioned JSON Schema registered for this sector — typed
                // validation (above) is the only structural gate. Observable so
                // operators don't publish schema-free passports silently.
                tracing::warn!(
                    passport_id = %id,
                    sector = %schema_key,
                    "publishing passport with no registered JSON Schema — \
                     only typed validation ran; add a schema to enforce enum/pattern/range constraints"
                );
            }

            // Compliance gate: a sector whose DPP obligation is in force must not
            // be signed/published while it carries *binding* violations. Advisory
            // warnings (e.g. recycled-content thresholds not yet in force) never
            // block — they are surfaced on the persisted determination instead.
            if catalog().is_in_force(sector_data.sector().catalog_key())
                && let Ok(determination) =
                    self.compliance.compute(sector_data.sector(), sector_data)
                && determination.has_violations()
            {
                let summary = determination
                    .violations
                    .iter()
                    .map(|v| {
                        if v.field.is_empty() {
                            v.message.clone()
                        } else {
                            format!("{} ({})", v.message, v.field)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                tracing::warn!(
                    passport_id = %id,
                    violations = %summary,
                    "publish blocked by binding compliance violations"
                );
                return Err(DppError::Validation(
                    format!("cannot publish: binding compliance violations — {summary}").into(),
                ));
            }
        }

        let mut payload =
            serde_json::to_value(&passport).map_err(|e| DppError::Serialisation(e.to_string()))?;
        // Signed-status channel (roadmap 1.2): include the post-publish status in
        // the signed payload so the resolver can bind the status to the JWS and
        // reject reversals (Published → Draft) as tampering.
        payload["status"] = serde_json::json!("active");

        let jws = self
            .identity
            .sign_passport(passport.id, &payload)
            .await
            .map(|c| c.jws)
            .map_err(|e| {
                metrics::counter!("signing_failures_total").increment(1);
                tracing::error!(
                    code = event_codes::JWS_UNSIGNED_PUBLISH_BLOCKED,
                    error = %e,
                    "publish aborted — signing failed; passport remains draft"
                );
                DppError::Signing(e.to_string())
            })?;

        let mut passport = passport;
        passport.status = PassportStatus::Published;
        // publishedAt is set once, on first publish, and preserved across
        // suspend → re-publish cycles (dpp-core invariant).
        if passport.published_at.is_none() {
            let now = Utc::now();
            passport.published_at = Some(now);
            // Compute and seal retention_until once at first publish.
            // Uses the sector's statutory minimum; a stricter delegated-act
            // period can be set by the engine operator before publishing.
            if passport.retention_until.is_none() {
                let years = passport.sector.minimum_retention_years() as i64;
                passport.retention_until = Some(now + chrono::Duration::days(365 * years));
            }
        }
        passport.updated_at = Utc::now();
        passport.jws_signature = Some(jws);
        passport.qr_code_url = Some(build_gs1_or_fallback_url(&passport));
        passport.retention_locked = true;

        // Public verifiability: also sign the *public (redacted) view* — the exact
        // payload the unauthenticated `/public/dpp/{id}` route serves — so anyone
        // can verify the public passport against the operator DID without trusting
        // the resolver. `public_jws_signature` is `None` here, so it is never
        // signed over itself; the full-payload `jws_signature` above stays
        // Confidential for authenticated full-passport verification.
        let public_view = crate::public_view::public_view(
            &serde_json::to_value(&passport).map_err(|e| DppError::Serialisation(e.to_string()))?,
            passport.sector.catalog_key(),
        );
        let public_jws = self
            .identity
            .sign_passport(passport.id, &public_view)
            .await
            .map(|c| c.jws)
            .map_err(|e| {
                metrics::counter!("signing_failures_total").increment(1);
                tracing::error!(
                    code = event_codes::JWS_UNSIGNED_PUBLISH_BLOCKED,
                    error = %e,
                    "publish aborted — public-view signing failed; passport remains draft"
                );
                DppError::Signing(e.to_string())
            })?;
        passport.public_jws_signature = Some(public_jws);

        let updated = match self.repo.update(passport).await {
            Ok(p) => {
                metrics::counter!("passport_publish_total", "outcome" => "success").increment(1);
                p
            }
            Err(e) => {
                metrics::counter!("passport_publish_total", "outcome" => "error").increment(1);
                return Err(e);
            }
        };

        let entry = AuditEntry::new(
            &updated.id.to_string(),
            "published",
            auth,
            None,
            Some(&PassportStatus::Published.to_string()),
        );
        self.audit.append(entry).await?;

        // EU registry sync (ESPR Art. 13) — fire-after-commit, non-blocking.
        // Failures are logged but never propagated; the DB write is the source of truth.
        // Pre-go-live: GhostRegistrySync returns Pending without a network call.
        let reg_req =
            RegistrationRequest::from_published_passport(&updated, &self.operator_country);
        if let Err(e) = self.registry_sync.register(reg_req).await {
            tracing::warn!(
                code = event_codes::REGISTRY_SYNC_FAILED,
                passport_id = %updated.id,
                error = %e,
                "EU registry sync failed (non-fatal)"
            );
        }

        // ESPR Art. 13 third-party archive — fire-after-commit, non-blocking.
        // Failures are logged but never propagated; the DB write is the source of truth.
        let retention_years = updated.sector.minimum_retention_years();
        if let Err(e) = self.archive.archive(&updated, retention_years).await {
            tracing::warn!(
                passport_id = %updated.id,
                error = %e,
                "ESPR archive failed (non-fatal)"
            );
        }

        self.emit(
            event::subjects::PASSPORT_PUBLISHED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "active",
                "qrCodeUrl": updated.qr_code_url,
            }),
        )
        .await;

        Ok(updated)
    }

    /// Suspend a published passport.
    ///
    /// Reversible — a suspended passport can be re-published. Appends an audit
    /// entry with the optional `reason` and emits `dpp.passport.suspended`.
    #[tracing::instrument(skip(self, reason), fields(passport_id = %id))]
    pub async fn suspend(
        &self,
        id: PassportId,
        auth: &AuthContext,
        reason: Option<String>,
    ) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport
            .status
            .can_transition_to(&PassportStatus::Suspended)
        {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Suspended.to_string(),
            });
        }

        let updated = self
            .repo
            .update_status(id, PassportStatus::Suspended)
            .await?;

        let mut entry = AuditEntry::new(
            &updated.id.to_string(),
            "suspended",
            auth,
            Some(&PassportStatus::Published.to_string()),
            Some(&PassportStatus::Suspended.to_string()),
        );
        if let Some(r) = reason {
            entry = entry.with_metadata(serde_json::json!({"reason": r}));
        }
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_SUSPENDED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "suspended",
            }),
        )
        .await;

        Ok(updated)
    }

    /// Permanently archive a passport after retention expiry.
    ///
    /// Blocked by the ESPR retention guard: if `retention_locked` is set and the
    /// sector's minimum retention period has not yet elapsed from `published_at`,
    /// returns `DppError::Validation`. Emits `dpp.passport.archived`.
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    pub async fn archive(&self, id: PassportId, auth: &AuthContext) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport.status.can_transition_to(&PassportStatus::Archived) {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Archived.to_string(),
            });
        }

        // ── Retention guard ─────────────────────────────────────────────
        // EU ESPR requires that published DPPs remain accessible for the
        // period defined in the applicable delegated act.  Archiving before
        // the retention period expires is blocked.
        if passport.retention_locked
            && let Some(published_at) = passport.published_at
        {
            let retention_years = passport
                .sector_data
                .as_ref()
                .map(|sd| sd.sector().minimum_retention_years())
                .unwrap_or(10) as i64;
            let retention_end = published_at + chrono::Duration::days(365 * retention_years);
            if Utc::now() < retention_end {
                tracing::warn!(
                    code = event_codes::RETENTION_BLOCKED,
                    passport_id = %id,
                    retention_end = %retention_end.format("%Y-%m-%d"),
                    "archive blocked by retention policy"
                );
                return Err(DppError::Validation(
                    format!(
                        "retention policy forbids archiving before {}",
                        retention_end.format("%Y-%m-%d")
                    )
                    .into(),
                ));
            }
        }

        let prev_status = passport.status.to_string();
        let updated = self
            .repo
            .update_status(id, PassportStatus::Archived)
            .await?;

        let entry = AuditEntry::new(
            &updated.id.to_string(),
            "archived",
            auth,
            Some(&prev_status),
            Some(&PassportStatus::Archived.to_string()),
        );
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_ARCHIVED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "archived",
                "previousStatus": prev_status,
            }),
        )
        .await;

        Ok(updated)
    }

    /// Return the append-only audit trail for a passport.
    ///
    /// Verifies the passport exists first so an unknown id returns
    /// `DppError::NotFound` rather than an empty list.
    pub async fn history(&self, id: PassportId) -> Result<Vec<AuditEntry>, DppError> {
        // Verify the passport exists so an unknown id returns 404 (consistent
        // with GET /dpp/{id}); otherwise the handler's NotFound branch is dead
        // and a nonexistent passport would return `200 []`.
        self.find_by_id(id).await?;
        self.audit.list_by_passport(&id.to_string()).await
    }

    // ── Event helper ─────────────────────────────────────────────────────────

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

fn apply_compliance(passport: &mut Passport, registry: &dyn ComplianceRegistry) {
    let sector_data = match passport.sector_data.clone() {
        Some(sd) => sd,
        None => return,
    };
    let sector = sector_data.sector();
    if let Ok(mut result) = registry.compute(sector, &sector_data) {
        // Backfill the two display metrics only when the caller didn't supply them.
        if passport.co2e_per_unit.is_none() {
            passport.co2e_per_unit = result.co2e_score.map(CarbonFootprint::from_kg);
        }
        if passport.repairability_score.is_none() {
            passport.repairability_score = result
                .repairability_index
                .map(RepairabilityScore::from_scalar);
        }
        // Persist the full determination (status, metrics, findings, receipt) on
        // the passport so it is part of the signed payload and queryable. Stamp
        // the assessment time if the registry didn't.
        if result.assessed_at.is_none() {
            result.assessed_at = Some(Utc::now());
        }
        passport.compliance_result = Some(result);
    }
}

/// If the passport carries Battery sector data with a GTIN, produce a
/// GS1 Digital Link URL (`/01/{gtin}/21/{id}`).  Otherwise fall back to
/// the legacy resolver path.
fn build_gs1_or_fallback_url(passport: &Passport) -> String {
    const RESOLVER_BASE: &str = "https://id.odal-node.io";
    const LEGACY_BASE: &str = "https://p.odal-node.io";

    match passport.sector_data {
        Some(SectorData::Battery(ref bd)) => build_qr_url(
            RESOLVER_BASE,
            bd.gtin.as_str(),
            &passport.id.to_string(),
            passport.batch_id.as_deref(),
        ),
        _ => format!("{LEGACY_BASE}/{}", passport.id),
    }
}

fn apply_patch(passport: &mut Passport, patch: &serde_json::Value) -> Result<(), DppError> {
    let obj = match patch.as_object() {
        Some(o) => o,
        None => {
            return Err(DppError::Validation(
                "patch body must be a JSON object".into(),
            ));
        }
    };

    if let Some(v) = obj.get("productName").and_then(|v| v.as_str()) {
        passport.product_name = v.to_owned();
    }
    if let Some(v) = obj.get("co2ePerUnit").and_then(|v| v.as_f64()) {
        passport.co2e_per_unit = Some(CarbonFootprint::from_kg(v));
    }
    if let Some(v) = obj.get("repairabilityScore").and_then(|v| v.as_f64()) {
        passport.repairability_score = Some(RepairabilityScore::from_scalar(v));
    }
    if let Some(v) = obj.get("sectorData") {
        let sector_data: SectorData = serde_json::from_value(v.clone())
            .map_err(|e| DppError::Validation(format!("invalid sectorData: {e}").into()))?;
        dpp_domain::validate_sector_data(&sector_data).map_err(DppError::Validation)?;
        passport.sector_data = Some(sector_data);
    }

    Ok(())
}

fn catalog() -> &'static dpp_domain::SectorCatalog {
    static CATALOG: std::sync::OnceLock<dpp_domain::SectorCatalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(dpp_domain::SectorCatalog::new)
}

fn schema_registry() -> &'static dpp_domain::schemas::VersionedSchemaRegistry {
    static REGISTRY: std::sync::OnceLock<dpp_domain::schemas::VersionedSchemaRegistry> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(dpp_domain::schemas::VersionedSchemaRegistry::new)
}

#[cfg(test)]
mod tests {
    use super::{apply_compliance, apply_patch, build_gs1_or_fallback_url};
    use chrono::Utc;
    use dpp_domain::{
        domain::{
            error::DppError,
            passport::{ManufacturerInfo, Passport, PassportId},
            sector::{Sector, SectorData},
            status::PassportStatus,
        },
        ports::compliance::{
            ComplianceError, ComplianceErrorKind, ComplianceRegistry, ComplianceResult,
        },
    };

    fn stub() -> Passport {
        Passport {
            id: PassportId::new(),
            batch_id: None,
            product_name: "Test".into(),
            sector: Sector::Battery,
            product_category: None,
            manufacturer: ManufacturerInfo {
                name: "ACME".into(),
                address: "1 Street".into(),
                did_web_url: None,
            },
            materials: vec![],
            co2e_per_unit: None,
            repairability_score: None,
            compliance_result: None,
            sector_data: None,
            status: PassportStatus::Draft,
            qr_code_url: None,
            jws_signature: None,
            public_jws_signature: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            published_at: None,
            schema_version: "1.0.0".into(),
            retention_locked: false,
            version: 1,
            supersedes_id: None,
            retention_until: None,
            product_id: None,
            operator_identifier: None,
            facility_id: None,
        }
    }

    struct NoopRegistry;

    impl ComplianceRegistry for NoopRegistry {
        fn compute(&self, _: Sector, _: &SectorData) -> Result<ComplianceResult, ComplianceError> {
            Err(ComplianceError {
                kind: ComplianceErrorKind::UnknownSector,
                message: "noop".into(),
            })
        }
    }

    // ── apply_patch ──────────────────────────────────────────────────────────

    #[test]
    fn patch_non_object_returns_validation_error() {
        let mut p = stub();
        let err = apply_patch(&mut p, &serde_json::json!("not-an-object")).unwrap_err();
        assert!(matches!(err, DppError::Validation(_)));
    }

    #[test]
    fn patch_updates_product_name() {
        let mut p = stub();
        apply_patch(&mut p, &serde_json::json!({"productName": "Updated"})).unwrap();
        assert_eq!(p.product_name, "Updated");
    }

    #[test]
    fn patch_updates_co2e_per_unit() {
        let mut p = stub();
        apply_patch(&mut p, &serde_json::json!({"co2ePerUnit": 42.5})).unwrap();
        assert_eq!(p.co2e_per_unit.as_ref().map(|cf| cf.value_kg), Some(42.5));
    }

    #[test]
    fn patch_updates_repairability_score() {
        let mut p = stub();
        apply_patch(&mut p, &serde_json::json!({"repairabilityScore": 7.5})).unwrap();
        assert_eq!(
            p.repairability_score.as_ref().map(|rs| rs.overall),
            Some(7.5)
        );
    }

    #[test]
    fn patch_invalid_sector_data_returns_validation_error() {
        let mut p = stub();
        let err = apply_patch(
            &mut p,
            &serde_json::json!({"sectorData": {"type": "unknown", "garbage": true}}),
        )
        .unwrap_err();
        assert!(matches!(err, DppError::Validation(_)));
    }

    #[test]
    fn patch_empty_object_is_noop() {
        let mut p = stub();
        p.product_name = "Before".into();
        apply_patch(&mut p, &serde_json::json!({})).unwrap();
        assert_eq!(p.product_name, "Before");
    }

    // ── build_gs1_or_fallback_url ────────────────────────────────────────────

    #[test]
    fn no_sector_data_uses_fallback_url() {
        let p = stub(); // sector_data is None
        let url = build_gs1_or_fallback_url(&p);
        assert!(url.starts_with("https://p.odal-node.io/"));
        assert!(url.contains(&p.id.to_string()));
    }

    // ── apply_compliance ─────────────────────────────────────────────────────

    #[test]
    fn no_sector_data_is_noop() {
        let mut p = stub(); // sector_data is None → early return
        apply_compliance(&mut p, &NoopRegistry);
        assert!(p.co2e_per_unit.is_none());
        assert!(p.repairability_score.is_none());
    }
}
