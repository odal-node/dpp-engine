//! `publish` — sign and publish a draft passport, plus its private helpers
//! `validate_schema_for_publish` (fail-closed JSON Schema gate) and
//! `build_carrier_url` (GS1 Digital Link URL for the QR code).

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_digital_link::{build_qr_url, short_serial};
use dpp_domain::{
    domain::{
        error::DppError,
        passport::{Passport, PassportId},
        sector::SectorData,
        status::PassportStatus,
    },
    ports::registry_sync::RegistrationRequest,
};
use dpp_types::{STANDALONE_OPERATOR_ID, audit::AuditEntry, auth::AuthContext};

use super::PassportService;
use super::{catalog, schema_registry};

impl PassportService {
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
        let mut passport = self.find_by_id(id).await?;

        if !passport
            .status
            .can_transition_to(&PassportStatus::Published)
        {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Published.to_string(),
            });
        }

        // Annex III completeness (ESPR): a published DPP for an in-force sector must
        // carry the unique facility identifier (Annex III point (i)) and the
        // responsible-operator identifier (point (k)). Backfill from the current
        // registry defaults first — so a draft created before the default facility /
        // primary identifier was configured still publishes cleanly — then require
        // their presence. Never sign a passport that is missing them.
        if let Some(reader) = &self.registry_reader {
            if passport.facility.is_none() {
                passport.facility = reader
                    .default_facility(STANDALONE_OPERATOR_ID)
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
        if catalog().is_in_force(passport.sector.catalog_key()) {
            let mut missing = Vec::new();
            if passport.facility.is_none() {
                missing.push("facility (Annex III unique facility identifier)");
            }
            if passport.operator_identifier.is_none() {
                missing.push("operatorIdentifier (Annex III responsible-operator identifier)");
            }
            if !missing.is_empty() {
                tracing::warn!(
                    passport_id = %id,
                    missing = %missing.join("; "),
                    "publish blocked — passport is missing required Annex III registry identity"
                );
                return Err(DppError::Validation(
                    format!(
                        "cannot publish: missing required registry identity — {}. \
                         Configure a default facility (`odal facility`) and a primary \
                         operator identifier (`odal operator-id`) before publishing.",
                        missing.join("; ")
                    )
                    .into(),
                ));
            }
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
            validate_schema_for_publish(sector_data)?;

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

        // Every publish-time field is set before the single serialize below,
        // so it captures everything both signatures need — avoiding the
        // second full struct→JSON walk this used to require just to pick up
        // 4-6 fields that changed after an earlier serialize. `jws_signature`
        // is set only after signing (a payload can't sign over its own
        // signature); `public_jws_signature` stays `None` throughout.
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
        passport.qr_code_url = Some(build_carrier_url(&passport, &self.resolver_base_url));
        passport.retention_locked = true;

        // `status` serialises to the API wire string ("active") via
        // `PassportStatus`'s own `Serialize` impl — already reflects the
        // mutation above, no manual patch needed.
        let payload =
            serde_json::to_value(&passport).map_err(|e| DppError::Serialisation(e.to_string()))?;

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
        passport.jws_signature = Some(jws);

        // Public verifiability: also sign the *public (redacted) view* — the exact
        // payload the unauthenticated `/public/dpp/{id}` route serves — so anyone
        // can verify the public passport against the operator DID without trusting
        // the resolver. Derived from the same `payload` above rather than a
        // second full serialize: `public_view` strips `jwsSignature`
        // unconditionally, so `payload` still carrying the pre-signing value
        // here is immaterial. `public_jws_signature` is `None` here, so it is
        // never signed over itself; the full-payload `jws_signature` above
        // stays Confidential for authenticated full-passport verification.
        let public_view = crate::public_view::public_view(&payload, passport.sector.catalog_key());
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

        // Persist the published passport. With the transactional outbox present,
        // the passport write and the EU-registry registration enqueue commit
        // atomically (ESPR Art. 13) — a Published passport can never exist
        // without a queued registration, and the node's drain task performs the
        // actual registration with backoff. Without an outbox (in-memory test
        // doubles), fall back to a plain update.
        let updated = match &self.registry_outbox {
            Some(outbox) => {
                let reg_req =
                    RegistrationRequest::from_published_passport(&passport, &self.operator_country);
                let payload = serde_json::to_value(&reg_req)
                    .map_err(|e| DppError::Serialisation(e.to_string()))?;
                match outbox.commit_publish(&passport, payload).await {
                    Ok(()) => {
                        metrics::counter!("passport_publish_total", "outcome" => "success")
                            .increment(1);
                        passport
                    }
                    Err(e) => {
                        metrics::counter!("passport_publish_total", "outcome" => "error")
                            .increment(1);
                        return Err(e);
                    }
                }
            }
            None => match self.repo.update(passport).await {
                Ok(p) => {
                    metrics::counter!("passport_publish_total", "outcome" => "success")
                        .increment(1);
                    p
                }
                Err(e) => {
                    metrics::counter!("passport_publish_total", "outcome" => "error").increment(1);
                    return Err(e);
                }
            },
        };

        // Stamp the exact payloads that were signed (not the current row) as
        // metadata on this publish's audit entry. `jws_signature` and
        // `public_jws_signature` are frozen at this moment and never re-signed
        // by later lifecycle transitions (suspend/archive/eol only touch
        // `status`), so evidence dossier generation must recover *this*
        // snapshot rather than reconstruct one from the passport's current —
        // by then possibly mutated — row. A re-publish (Suspend -> Published)
        // runs this same path again and appends a new "published" entry with
        // a fresh snapshot; generation always uses the most recent one.
        let entry = AuditEntry::new(
            &updated.id.to_string(),
            "published",
            &auth.user_id,
            None,
            Some(&PassportStatus::Published.to_string()),
        )
        .with_metadata(serde_json::json!({
            "fullViewPayload": payload,
            "publicViewPayload": public_view,
        }));
        self.audit.append(entry).await?;

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

        // Mirror the freshly-signed public view to the continuity tier so it
        // stays reachable if the node goes down (non-blocking, non-fatal).
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }
}

/// Validate `sector_data` against its sector's current JSON Schema before it
/// can be published. Fails closed: a published, signed DPP must pass a real
/// schema check whenever it carries sector data — unlike `create`, where a
/// draft may stay lenient. `Ok` covers a resolved-and-valid schema; `Err`
/// covers both a resolved-but-invalid schema and no schema resolved at all.
fn validate_schema_for_publish(sector_data: &SectorData) -> Result<(), DppError> {
    let schema_key = sector_data.sector().catalog_key();
    let Some(schema_version) = catalog().resolve_schema_version(schema_key, None) else {
        // Every built-in sector has a catalog entry (CI-enforced parity guard),
        // so this is unreachable via `SectorData`'s named variants today; the
        // only value that resolves here is `SectorData::Other`, which is itself
        // already blocked by `validate_sector_data` above (no "other" validator
        // is registered by default). Kept fail-closed as defence in depth for
        // when the open sector model gains a real per-sector validator.
        metrics::counter!("publish_schema_unresolved_total", "sector" => schema_key).increment(1);
        tracing::warn!(
            sector = %schema_key,
            "publish blocked — no registered JSON Schema for this sector"
        );
        return Err(DppError::Validation(
            format!(
                "cannot publish: no registered JSON Schema for sector '{schema_key}' — \
                 publish requires a resolvable schema when sector data is present"
            )
            .into(),
        ));
    };
    let mut sd_json =
        serde_json::to_value(sector_data).map_err(|e| DppError::Serialisation(e.to_string()))?;
    // SectorData is internally tagged; schemas validate the inner object.
    if let Some(obj) = sd_json.as_object_mut() {
        obj.remove("sector");
    }
    schema_registry()
        .validate_strict(schema_key, &schema_version, &sd_json)
        .map_err(DppError::from)
}

/// Build the carrier (QR / Data Matrix) URL a passport should encode, on the
/// node's configured resolver base.
///
/// When the sector data carries a GTIN — every trade-item sector — produces a
/// GS1 Digital Link (`{base}/01/{gtin}[/10/{batch}]/21/{serial}`) with a
/// GS1-conformant 20-char serial derived from the passport id. When it does not
/// (an unsold-goods report or untyped record, which identify no trade item),
/// points at the passport's own resolver page on the same configured base —
/// never a hardcoded host.
fn build_carrier_url(passport: &Passport, resolver_base: &str) -> String {
    let base = resolver_base.trim_end_matches('/');
    match passport.sector_data.as_ref().and_then(SectorData::gtin) {
        Some(gtin) => build_qr_url(
            base,
            gtin,
            &short_serial(passport.id.0.as_bytes()),
            passport.batch_id.as_deref(),
        ),
        None => format!("{base}/dpp/{}", passport.id),
    }
}

#[cfg(test)]
mod tests {
    use super::{build_carrier_url, validate_schema_for_publish};
    use chrono::Utc;
    use dpp_domain::domain::{
        error::DppError,
        passport::{ManufacturerInfo, Passport, PassportId},
        sector::{Sector, SectorData},
        status::PassportStatus,
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
            lint_result: None,
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
            parent_passport_ref: None,
            component_refs: Vec::new(),
            retention_until: None,
            product_id: None,
            operator_identifier: None,
            facility: None,
            seal: None,
        }
    }

    // ── build_carrier_url ────────────────────────────────────────────────────

    #[test]
    fn no_gtin_points_at_resolver_dpp_page() {
        // An unsold-goods report / untyped record carries no trade-item GTIN, so
        // the carrier points at the passport's own page on the configured base —
        // never the old hardcoded `p.odal-node.io` host.
        let p = stub(); // sector_data is None → no GTIN
        let url = build_carrier_url(&p, "https://id.example.com/");
        assert_eq!(url, format!("https://id.example.com/dpp/{}", p.id));
        assert!(!url.contains("p.odal-node.io"));
    }

    #[test]
    fn gtin_sector_builds_gs1_dl_with_conformant_serial() {
        use dpp_domain::domain::sector::ConstructionData;
        let mut p = stub();
        p.sector_data = Some(SectorData::Construction(ConstructionData {
            gtin: "09506000134352".into(),
            product_family: "cement".into(),
            country_of_manufacture: "DE".into(),
            co2e_per_functional_unit_kg: 100.0,
            functional_unit: "per tonne".into(),
            recycled_content_pct: None,
            epd_url: None,
            ce_marking: None,
        }));
        let url = build_carrier_url(&p, "https://id.example.com");
        // Must be a parseable GS1 Digital Link — parse enforces the AI 21 cap, so
        // a >20-char serial would make this fail.
        let parsed = dpp_digital_link::DigitalLink::parse(&url)
            .expect("carrier URL must be a parseable GS1 Digital Link");
        let serial = parsed.serial.expect("serial present");
        assert!(
            serial.chars().count() <= 20,
            "AI 21 serial must be ≤20 chars"
        );
        assert!(url.starts_with("https://id.example.com/01/09506000134352/21/"));
        assert!(!url.contains("p.odal-node.io"));
    }

    // ── validate_schema_for_publish (Q-2) ────────────────────────────────────

    #[test]
    fn unresolvable_sector_schema_fails_closed() {
        // `SectorData::Other`'s catalog key ("other") has no embedded schema —
        // the only value that can reach this branch, since every named sector
        // has a catalog entry (CI-enforced parity guard). Publish must refuse
        // it outright, not warn-and-pass.
        let sd = SectorData::Other(serde_json::json!({"anything": "goes"}));
        let err = validate_schema_for_publish(&sd).unwrap_err();
        assert!(matches!(err, DppError::Validation(_)));
    }
}
