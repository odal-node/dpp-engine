//! `publish` — sign and publish a draft passport, plus its private helpers
//! `validate_schema_for_publish` (fail-closed JSON Schema gate) and
//! `build_carrier_url` (GS1 Digital Link URL for the QR code).

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_digital_link::{build_qr_url, short_serial};
use dpp_domain::{
    error::DppError,
    passport::{Passport, PassportId},
    ports::registry_sync::{RegisteringOperator, RegistrationGranularity, RegistrationRequest},
    product_group::ProductGroupData,
    status::PassportStatus,
};
use dpp_types::{STANDALONE_OPERATOR_ID, audit::AuditEntry, auth::AuthContext};

use super::{PassportService, retention_years_for};
use super::{catalog, schema_registry};

/// Why a publish was refused. One value per `return Err` in [`PassportService::publish`].
///
/// Static strings rather than a formatted message: this is a metric label, so
/// its cardinality has to be bounded by the code rather than by the data.
mod reason {
    pub const INVALID_TRANSITION: &str = "invalid_transition";
    pub const MISSING_REGISTRY_IDENTITY: &str = "missing_registry_identity";
    pub const SECTOR_DATA_INVALID: &str = "product_group_data_invalid";
    pub const SCHEMA_INVALID: &str = "schema_invalid";
    pub const COMPLIANCE_VIOLATIONS: &str = "compliance_violations";
    pub const SIGNING_FAILED: &str = "signing_failed";
    /// The battery's category requires content the passport does not carry.
    ///
    /// Distinct from `product_group_data_invalid`, which is data that is present and
    /// wrong. This is data that is absent, and it is the one rejection a caller
    /// cannot diagnose from their own request: the requirement lives in
    /// `dpp-domain`'s category table, not in anything they sent.
    pub const MANDATORY_CONTENT: &str = "mandatory_content";
}

use reason::{
    COMPLIANCE_VIOLATIONS as REASON_COMPLIANCE_VIOLATIONS,
    INVALID_TRANSITION as REASON_INVALID_TRANSITION, MANDATORY_CONTENT as REASON_MANDATORY_CONTENT,
    MISSING_REGISTRY_IDENTITY as REASON_MISSING_REGISTRY_IDENTITY,
    SCHEMA_INVALID as REASON_SCHEMA_INVALID, SECTOR_DATA_INVALID as REASON_SECTOR_DATA_INVALID,
    SIGNING_FAILED as REASON_SIGNING_FAILED,
};

/// Count a publish rejection, then return its error unchanged.
///
/// # Why this exists
///
/// `passport_publish_total` was incremented in exactly two places, both in the
/// persistence half of `publish` — below every validation gate. So the six
/// business-logic rejections above them moved **no metric at all**: a node whose
/// publishes had all started failing because the default facility was retired
/// showed a flat counter, identical to a node publishing nothing. The operator's
/// signal was a 422 in a client they may not own and one `warn!` line per
/// attempt.
///
/// A separate counter rather than a `rejected` outcome on the existing one, for
/// two reasons: `passport_publish_total` keeps its current meaning for anything
/// already reading it, and a `reason` label on some series of a counter but not
/// others is the kind of label-set mismatch that confuses scrapers.
///
/// The alert this makes possible:
/// `rate(passport_publish_rejected_total[5m]) > 0`, broken down by `reason`.
fn reject(reason: &'static str, e: DppError) -> DppError {
    metrics::counter!("passport_publish_rejected_total", "reason" => reason).increment(1);
    tracing::warn!(reason, error = %e, "publish rejected");
    e
}

impl PassportService {
    /// Sign and publish a draft passport with Ed25519 / JWS.
    ///
    /// Validates product group data, calls the identity service to sign, atomically
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
            return Err(reject(
                REASON_INVALID_TRANSITION,
                DppError::InvalidTransition {
                    current: passport.status.to_string(),
                    required: PassportStatus::Published.to_string(),
                },
            ));
        }

        // Annex III completeness (ESPR): a published DPP for an in-force product group must
        // carry the unique facility identifier (Annex III point (i)) and the
        // responsible-operator identifier (point (k)). Backfill from the current
        // registry defaults first — so a draft created before the default facility /
        // primary identifier was configured still publishes cleanly — then require
        // their presence. Never sign a passport that is missing them.
        // Read the primary identifier as a (scheme, value) pair. The scheme is
        // needed for the registration even when the passport was already
        // stamped at create, so this is read unconditionally rather than only
        // when backfilling.
        let mut primary_identifier = None;
        if let Some(reader) = &self.registry_reader {
            primary_identifier = reader
                .primary_operator_identifier(STANDALONE_OPERATOR_ID)
                .await
                .unwrap_or(None);
            if passport.facility.is_none() {
                passport.facility = reader
                    .default_facility(STANDALONE_OPERATOR_ID)
                    .await
                    .unwrap_or(None);
            }
            if passport.operator_identifier.is_none() {
                passport.operator_identifier =
                    primary_identifier.as_ref().map(|(_, value)| value.clone());
            }
        }
        if super::passport_obligation_live(passport.product_group.catalog_key()) {
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
                return Err(reject(
                    REASON_MISSING_REGISTRY_IDENTITY,
                    DppError::Validation(
                        format!(
                            "cannot publish: missing required registry identity — {}. \
                             Configure a default facility (`odal facility`) and a primary \
                             operator identifier (`odal operator-id`) before publishing.",
                            missing.join("; ")
                        )
                        .into(),
                    ),
                ));
            }
        }

        // Publish-time validation (domain Gap 7 / vault V3): never sign product group
        // data that fails its JSON Schema + cross-field rules.
        //
        // NOTE: this validates product group data *when present*. Hard-requiring its
        // presence at publish (a published EU DPP should always carry product group
        // data) is the stricter completeness policy — deferred until the
        // integration fixtures that publish minimal passports are updated and a
        // Docker run confirms them (roadmap 1.3).
        if let Some(product_group_data) = passport.product_group_data.as_ref() {
            dpp_domain::validate_product_group_data(product_group_data)
                .map_err(|e| reject(REASON_SECTOR_DATA_INVALID, DppError::Validation(e)))?;

            // JSON Schema gate (fail-closed): enum sets, string patterns, and
            // numeric ranges that the Rust types don't enforce. Runs after typed
            // validation so field-level messages are the primary signal.
            validate_schema_for_publish(product_group_data)
                .map_err(|e| reject(REASON_SCHEMA_INVALID, e))?;

            // Compliance gate: a product group whose DPP obligation is in force must not
            // be signed/published while it carries *binding* violations. Advisory
            // warnings (e.g. recycled-content thresholds not yet in force) never
            // block — they are surfaced on the persisted determination instead.
            if super::passport_obligation_live(product_group_data.product_group().catalog_key())
                && let Ok(determination) = self.compliance.compute(
                    product_group_data.product_group().catalog_key(),
                    product_group_data,
                    passport.placed_on_market_date,
                )
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
                return Err(reject(
                    REASON_COMPLIANCE_VIOLATIONS,
                    DppError::Validation(
                        format!("cannot publish: binding compliance violations — {summary}").into(),
                    ),
                ));
            }
        }

        // Every publish-time field is set before the single serialize below,
        // so it captures everything both signatures need — avoiding the
        // second full struct→JSON walk this used to require just to pick up
        // 4-6 fields that changed after an earlier serialize. `jws_signature`
        // is set only after signing (a payload can't sign over its own
        // signature); `public_jws_signature` stays `None` throughout.
        // The transition is core's to perform, not ours to imitate.
        //
        // `transition_to` sets `status`, `published_at` (first publish only) and
        // `retention_locked`, and — the reason it must be called rather than
        // reproduced — runs the mandatory-content gate that refuses a first
        // publish omitting content the product's category requires. That gate is
        // private to `dpp-domain` and reachable no other way, deliberately: a
        // check a consumer can decline to call is a check the next consumer will
        // not call. Setting these three fields by hand, as this did, declined it.
        let first_publish = passport.published_at.is_none();
        passport
            .transition_to(PassportStatus::Published)
            .map_err(|e| reject(REASON_MANDATORY_CONTENT, e))?;

        // Engine-side obligations, which core has no view of: the retention
        // horizon comes from this deployment's product group catalog, and the carrier
        // URL from its resolver. Both are derived from the timestamp core just
        // set, so all three agree on when the publish happened.
        if first_publish && passport.retention_until.is_none() {
            // Compute and seal retention_until once at first publish, from the
            // catalog — the single source of the obligation, held beside the
            // act that imposes it. A stricter delegated-act period can be set
            // by the operator before publishing.
            let published_at = passport.published_at.unwrap_or_else(Utc::now);
            let years = retention_years_for(&passport.product_group);
            passport.retention_until =
                Some(published_at + chrono::Duration::days(365 * i64::from(years)));
        }
        passport.qr_code_url = Some(build_carrier_url(&passport, &self.resolver_base_url));

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
                metrics::counter!("passport_publish_rejected_total", "reason" => REASON_SIGNING_FAILED).increment(1);
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
        let public_view = crate::public_view::public_view(
            &payload,
            passport.product_group.catalog_key(),
            &passport.schema_version,
        );
        let public_jws = self
            .identity
            .sign_passport(passport.id, &public_view)
            .await
            .map(|c| c.jws)
            .map_err(|e| {
                metrics::counter!("signing_failures_total").increment(1);
                metrics::counter!("passport_publish_rejected_total", "reason" => REASON_SIGNING_FAILED).increment(1);
                tracing::error!(
                    code = event_codes::JWS_UNSIGNED_PUBLISH_BLOCKED,
                    error = %e,
                    "publish aborted — public-view signing failed; passport remains draft"
                );
                DppError::Signing(e.to_string())
            })?;
        passport.public_jws_signature = Some(public_jws);

        // Each non-public disclosure set gets its own proof over its own view.
        // Without this an authority or a legitimate-interest holder receives a
        // filtered body and no signature that covers it — and the audiences most
        // likely to be making a safety or resale decision on the data are
        // exactly the ones who cannot check it. Frozen here with its two
        // siblings so all three describe the same moment, and keyed by
        // disclosure set so the artefact names the data it covers rather than
        // the actor vocabulary of one regulation.
        passport.disclosure_signatures = crate::public_view::sign_disclosure_views(
            self.identity.as_ref(),
            passport.id,
            &payload,
            passport.product_group.catalog_key(),
            &passport.schema_version,
        )
        .await
        .map_err(|e| {
            metrics::counter!("signing_failures_total").increment(1);
            metrics::counter!("passport_publish_rejected_total", "reason" => REASON_SIGNING_FAILED)
                .increment(1);
            tracing::error!(
                code = event_codes::JWS_UNSIGNED_PUBLISH_BLOCKED,
                error = %e,
                "publish aborted — disclosure-view signing failed; passport remains draft"
            );
            DppError::Signing(e.to_string())
        })?;

        // Persist the published passport. With the transactional outbox present,
        // the passport write and the EU-registry registration enqueue commit
        // atomically (ESPR Art. 13) — a Published passport can never exist
        // without a queued registration, and the node's drain task performs the
        // actual registration with backoff. Without an outbox (in-memory test
        // doubles), fall back to a plain update.
        let updated = match &self.registry_outbox {
            Some(outbox) => {
                // The scheme is only assertable for the value the passport
                // actually carries. If that value did not come from the current
                // primary identifier — the primary was changed after the draft
                // was stamped — we cannot say what scheme it is in, so the
                // scheme is left empty and the registration fails validation
                // rather than claiming a scheme that may be wrong.
                let identifier_scheme = primary_identifier
                    .as_ref()
                    .filter(|(_, value)| Some(value) == passport.operator_identifier.as_ref())
                    .map(|(scheme, _)| scheme.as_str())
                    .unwrap_or_default();
                // Declare the back-up only where this deployment actually
                // publishes one. The snapshot tier writing to object storage is
                // not enough — the registry has to be able to fetch it.
                let backup_url = self
                    .snapshot_public_base_url
                    .as_ref()
                    .map(|base| format!("{base}/{}.json", passport.id));
                let mut reg_req = RegistrationRequest::from_published_passport(
                    &passport,
                    RegisteringOperator {
                        legal_name: &self.operator.legal_name,
                        country: &self.operator.country,
                        identifier_scheme,
                    },
                    // Item level: the granularity the battery product group is
                    // defined at, and the only one the registry accepts today.
                    // Set per product group once further delegated acts land.
                    RegistrationGranularity::Item,
                );
                reg_req.backup_url = backup_url;
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
        // Same resolver as the seal above, so the archived copy and the sealed
        // deadline cannot disagree.
        let retention_years = retention_years_for(&updated.product_group);
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

        // Queue the eIDAS qualified seal over the signature just produced. Also
        // non-blocking: a QTSP that is down must not stop an operator meeting a
        // publication obligation (see `dpp_types::seal`).
        self.enqueue_seal(&updated).await;

        Ok(updated)
    }
}

impl PassportService {
    /// Whether this product group data would clear the publish-time gates, without
    /// publishing anything.
    ///
    /// Runs the same two checks `publish` runs, in the same order, so a
    /// dry-run verdict cannot drift from the real one. Deliberately excludes
    /// the compliance gate below them: that needs a `placed_on_market_date`
    /// and a persisted passport, and reporting "compliant" against a date the
    /// caller has not supplied would be a fabricated answer.
    pub fn publish_readiness(&self, product_group_data: &ProductGroupData) -> Result<(), DppError> {
        dpp_domain::validate_product_group_data(product_group_data)
            .map_err(DppError::Validation)?;
        validate_schema_for_publish(product_group_data)
    }
}

/// Validate `product_group_data` against its product group's current JSON Schema before it
/// can be published. Fails closed: a published, signed DPP must pass a real
/// schema check whenever it carries product group data — unlike `create`, where a
/// draft may stay lenient. `Ok` covers a resolved-and-valid schema; `Err`
/// covers both a resolved-but-invalid schema and no schema resolved at all.
fn validate_schema_for_publish(product_group_data: &ProductGroupData) -> Result<(), DppError> {
    let schema_key = product_group_data.product_group().catalog_key().to_owned();
    let Some(schema_version) = catalog().resolve_schema_version(&schema_key, None) else {
        // Every built-in product group has a catalog entry (CI-enforced parity guard),
        // so this is unreachable via `ProductGroupData`'s named variants today; the
        // only value that resolves here is `ProductGroupData::Other`, which is itself
        // already blocked by `validate_product_group_data` above (no "other" validator
        // is registered by default). Kept fail-closed as defence in depth for
        // when the open product group model gains a real per-product group validator.
        metrics::counter!("publish_schema_unresolved_total", "productGroup" => schema_key.clone())
            .increment(1);
        tracing::warn!(
            product_group = %schema_key,
            "publish blocked — no registered JSON Schema for this product_group"
        );
        return Err(DppError::Validation(
            format!(
                "cannot publish: no registered JSON Schema for product_group '{schema_key}' — \
                 publish requires a resolvable schema when product_group data is present"
            )
            .into(),
        ));
    };
    let mut sd_json = serde_json::to_value(product_group_data)
        .map_err(|e| DppError::Serialisation(e.to_string()))?;
    // ProductGroupData is internally tagged; schemas validate the inner object.
    if let Some(obj) = sd_json.as_object_mut() {
        obj.remove("productGroup");
    }
    schema_registry()
        .validate_strict(&schema_key, &schema_version, &sd_json)
        .map_err(DppError::from)
}

/// Build the carrier (QR / Data Matrix) URL a passport should encode, on the
/// node's configured resolver base.
///
/// When the product group data carries a GTIN — every trade-item product group — produces a
/// GS1 Digital Link (`{base}/01/{gtin}[/10/{batch}]/21/{serial}`) with a
/// GS1-conformant 20-char serial derived from the passport id. When it does not
/// (an unsold-goods report or untyped record, which identify no trade item),
/// points at the passport's own resolver page on the same configured base —
/// never a hardcoded host.
fn build_carrier_url(passport: &Passport, resolver_base: &str) -> String {
    let base = resolver_base.trim_end_matches('/');
    match passport
        .product_group_data
        .as_ref()
        .and_then(ProductGroupData::gtin)
    {
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
mod rejection_reasons {
    //! The reason label is the whole value of the counter — an alert that fires
    //! without saying *why* publishing stopped is barely better than the flat
    //! line it replaced. These pin the properties a label set has to have.

    use super::reason;

    /// Every `return Err` in `publish` has its own reason. Duplicates would
    /// merge two distinct operator problems into one alert, which is the failure
    /// this counter exists to avoid.
    #[test]
    fn every_reason_is_distinct() {
        let all = [
            reason::INVALID_TRANSITION,
            reason::MISSING_REGISTRY_IDENTITY,
            reason::SECTOR_DATA_INVALID,
            reason::SCHEMA_INVALID,
            reason::COMPLIANCE_VIOLATIONS,
            reason::SIGNING_FAILED,
            reason::MANDATORY_CONTENT,
        ];
        let mut sorted = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "reason labels must be distinct");
    }

    /// Metric label values are `snake_case` and drawn from a fixed set, so
    /// cardinality is bounded by the code rather than by passport data. A label
    /// built from an error message would make every distinct failure a new
    /// series.
    #[test]
    fn reasons_are_bounded_snake_case_labels() {
        for r in [
            reason::INVALID_TRANSITION,
            reason::MISSING_REGISTRY_IDENTITY,
            reason::SECTOR_DATA_INVALID,
            reason::SCHEMA_INVALID,
            reason::COMPLIANCE_VIOLATIONS,
            reason::SIGNING_FAILED,
            reason::MANDATORY_CONTENT,
        ] {
            assert!(
                !r.is_empty() && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{r} is not a bounded snake_case label"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_carrier_url, validate_schema_for_publish};
    use chrono::Utc;
    use dpp_domain::{
        error::DppError,
        passport::{ManufacturerInfo, Passport, PassportId},
        product_group::{ProductGroup, ProductGroupData},
        status::PassportStatus,
    };

    fn stub() -> Passport {
        Passport {
            id: PassportId::new(),
            batch_id: None,
            product_name: "Test".into(),
            product_group: ProductGroup::Battery,
            applicable_instruments: Vec::new(),
            granularity: None,
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
            product_group_data: None,
            status: PassportStatus::Draft,
            qr_code_url: None,
            jws_signature: None,
            public_jws_signature: None,
            disclosure_signatures: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            published_at: None,
            placed_on_market_date: None,
            schema_version: "1.0.0".into(),
            retention_locked: false,
            version: 1,
            supersedes_id: None,
            parent_passport_ref: None,
            component_refs: Vec::new(),
            retention_until: None,
            product_id: None,
            commodity_code: None,
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
        let p = stub(); // product_group_data is None → no GTIN
        let url = build_carrier_url(&p, "https://id.example.com/");
        assert_eq!(url, format!("https://id.example.com/dpp/{}", p.id));
        assert!(!url.contains("p.odal-node.io"));
    }

    #[test]
    fn gtin_product_group_builds_gs1_dl_with_conformant_serial() {
        use dpp_domain::product_group::ConstructionData;
        let mut p = stub();
        p.product_group_data = Some(ProductGroupData::Construction(ConstructionData {
            gtin: dpp_domain::Gtin::parse("09506000134352").unwrap(),
            product_family: "cement".into(),
            country_of_origin: "DE".into(),
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
    fn unresolvable_product_group_schema_fails_closed() {
        // `ProductGroupData::Other`'s catalog key ("other") has no embedded schema —
        // the only value that can reach this branch, since every named product group
        // has a catalog entry (CI-enforced parity guard). Publish must refuse
        // it outright, not warn-and-pass.
        let sd = ProductGroupData::other(serde_json::json!({"anything": "goes"}))
            .expect("an untagged payload has no typed variant");
        let err = validate_schema_for_publish(&sd).unwrap_err();
        assert!(matches!(err, DppError::Validation(_)));
    }
}
