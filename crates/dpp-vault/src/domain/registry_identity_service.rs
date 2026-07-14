//! `RegistryIdentityService` — manage the operator's facilities (ESPR Annex III)
//! and economic-operator identifiers (ESPR Art. 13).
//!
//! Validation reuses the `dpp-registry` structural/checksum validators (the same
//! ones that gate an EU registry payload), so a malformed GLN/LEI/VAT is rejected
//! at entry rather than at sync time.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use dpp_domain::domain::error::DppError;
use dpp_types::operator::STANDALONE_OPERATOR_ID;
use dpp_types::registry_identity::{
    CreateFacilityRequest, CreateOperatorIdentifierRequest, Facility, OperatorIdentifier,
    RegistryIdentityAudit, RegistryIdentityRepository,
};

/// `entity_type` discriminators for registry-identity audit records.
const ENTITY_FACILITY: &str = "facility";
const ENTITY_OPERATOR_IDENTIFIER: &str = "operator_identifier";

/// Application service for facility / operator-identifier management.
///
/// Single-tenant: every call is scoped to `STANDALONE_OPERATOR_ID`.
pub struct RegistryIdentityService {
    pub repo: Arc<dyn RegistryIdentityRepository>,
}

impl RegistryIdentityService {
    pub fn new(repo: Arc<dyn RegistryIdentityRepository>) -> Self {
        Self { repo }
    }

    // ── Facilities ───────────────────────────────────────────────────────────

    pub async fn list_facilities(&self) -> Result<Vec<Facility>, DppError> {
        self.repo.list_facilities(STANDALONE_OPERATOR_ID).await
    }

    pub async fn add_facility(
        &self,
        req: CreateFacilityRequest,
        actor: &str,
    ) -> Result<Facility, DppError> {
        validate_facility(&req)?;
        let facility = Facility {
            id: Uuid::now_v7(),
            name: req.name.trim().to_owned(),
            identifier_scheme: req.identifier_scheme.trim().to_owned(),
            identifier_value: req.identifier_value.trim().to_owned(),
            country: req.country.trim().to_uppercase(),
            address: req
                .address
                .map(|a| a.trim().to_owned())
                .filter(|a| !a.is_empty()),
            is_default: req.is_default,
            created_at: Utc::now(),
        };
        let created = self
            .repo
            .add_facility(STANDALONE_OPERATOR_ID, facility)
            .await?;
        self.audit(
            ENTITY_FACILITY,
            created.id,
            "added",
            actor,
            snapshot(&created),
        )
        .await?;
        Ok(created)
    }

    pub async fn set_default_facility(&self, id: Uuid, actor: &str) -> Result<(), DppError> {
        if self
            .repo
            .set_default_facility(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            self.audit(ENTITY_FACILITY, id, "set_default", actor, None)
                .await?;
            Ok(())
        } else {
            Err(DppError::NotFound(id.to_string()))
        }
    }

    /// Retire a facility (soft-delete). The row is preserved as Annex III
    /// provenance for passports that stamped its identifier; only the audit-
    /// bearing `retired_at`/default flags change. Returns `NotFound` when no live
    /// facility with `id` exists (including one already retired).
    ///
    /// Guarded: retiring the **default** facility while other live facilities
    /// exist is refused (it would silently leave new passports with no facility);
    /// the operator must set a different default first. Retiring the *only*
    /// facility is allowed — there is nothing to promote.
    pub async fn retire_facility(&self, id: Uuid, actor: &str) -> Result<(), DppError> {
        let live = self.repo.list_facilities(STANDALONE_OPERATOR_ID).await?;
        match live.iter().find(|f| f.id == id) {
            None => return Err(DppError::NotFound(id.to_string())),
            Some(f) if f.is_default && live.len() > 1 => {
                return Err(DppError::Validation(
                    "cannot retire the default facility while other facilities exist; \
                     set a different facility as default first"
                        .into(),
                ));
            }
            Some(_) => {}
        }
        match self
            .repo
            .retire_facility(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            Some(retired) => {
                self.audit(ENTITY_FACILITY, id, "retired", actor, snapshot(&retired))
                    .await?;
                Ok(())
            }
            None => Err(DppError::NotFound(id.to_string())),
        }
    }

    /// Append an append-only audit record for a registry-identity mutation. The
    /// mutation is applied first; an audit-write failure is propagated (surfaced
    /// as 500) rather than swallowed, so an un-recorded change is never reported
    /// as clean success. (Full write+audit atomicity would need a shared
    /// transaction — a later hardening; the append is a single trivial INSERT
    /// that does not fail in practice.)
    async fn audit(
        &self,
        entity_type: &str,
        entity_id: Uuid,
        action: &str,
        actor: &str,
        snapshot: Option<serde_json::Value>,
    ) -> Result<(), DppError> {
        self.repo
            .append_audit(RegistryIdentityAudit::new(
                STANDALONE_OPERATOR_ID,
                entity_type,
                entity_id,
                action,
                actor,
                snapshot,
            ))
            .await
    }

    // ── Operator identifiers ─────────────────────────────────────────────────

    pub async fn list_operator_identifiers(&self) -> Result<Vec<OperatorIdentifier>, DppError> {
        self.repo
            .list_operator_identifiers(STANDALONE_OPERATOR_ID)
            .await
    }

    pub async fn add_operator_identifier(
        &self,
        req: CreateOperatorIdentifierRequest,
        operator_country: &str,
        actor: &str,
    ) -> Result<OperatorIdentifier, DppError> {
        validate_operator_identifier(&req, operator_country)?;
        let identifier = OperatorIdentifier {
            id: Uuid::now_v7(),
            scheme: req.scheme.trim().to_lowercase(),
            value: req.value.trim().to_owned(),
            label: req
                .label
                .map(|l| l.trim().to_owned())
                .filter(|l| !l.is_empty()),
            is_primary: req.is_primary,
            created_at: Utc::now(),
        };
        let created = self
            .repo
            .add_operator_identifier(STANDALONE_OPERATOR_ID, identifier)
            .await?;
        self.audit(
            ENTITY_OPERATOR_IDENTIFIER,
            created.id,
            "added",
            actor,
            snapshot(&created),
        )
        .await?;
        Ok(created)
    }

    pub async fn set_primary_operator_identifier(
        &self,
        id: Uuid,
        actor: &str,
    ) -> Result<(), DppError> {
        if self
            .repo
            .set_primary_operator_identifier(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            self.audit(ENTITY_OPERATOR_IDENTIFIER, id, "set_primary", actor, None)
                .await?;
            Ok(())
        } else {
            Err(DppError::NotFound(id.to_string()))
        }
    }

    /// Retire an operator identifier (soft-delete). Like a facility, its value is
    /// stamped by value onto immutable passports (ESPR Art. 13), so the row is
    /// preserved as provenance; only `retired_at`/primary flags change. Returns
    /// `NotFound` when no live identifier with `id` exists.
    ///
    /// Guarded like [`Self::retire_facility`]: retiring the **primary** identifier
    /// while other live identifiers exist is refused; set a different primary first.
    pub async fn retire_operator_identifier(&self, id: Uuid, actor: &str) -> Result<(), DppError> {
        let live = self
            .repo
            .list_operator_identifiers(STANDALONE_OPERATOR_ID)
            .await?;
        match live.iter().find(|o| o.id == id) {
            None => return Err(DppError::NotFound(id.to_string())),
            Some(o) if o.is_primary && live.len() > 1 => {
                return Err(DppError::Validation(
                    "cannot retire the primary operator identifier while others exist; \
                     set a different primary first"
                        .into(),
                ));
            }
            Some(_) => {}
        }
        match self
            .repo
            .retire_operator_identifier(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            Some(retired) => {
                self.audit(
                    ENTITY_OPERATOR_IDENTIFIER,
                    id,
                    "retired",
                    actor,
                    snapshot(&retired),
                )
                .await?;
                Ok(())
            }
            None => Err(DppError::NotFound(id.to_string())),
        }
    }

    // ── Audit trail ──────────────────────────────────────────────────────────

    /// Append-only mutation history for one facility (oldest first).
    pub async fn facility_audit(&self, id: Uuid) -> Result<Vec<RegistryIdentityAudit>, DppError> {
        self.repo.list_registry_audit(ENTITY_FACILITY, id).await
    }

    /// Append-only mutation history for one operator identifier (oldest first).
    pub async fn operator_identifier_audit(
        &self,
        id: Uuid,
    ) -> Result<Vec<RegistryIdentityAudit>, DppError> {
        self.repo
            .list_registry_audit(ENTITY_OPERATOR_IDENTIFIER, id)
            .await
    }
}

/// Serialise a record to a JSON audit snapshot; `None` if it can't be encoded
/// (never expected — these are plain data) so auditing degrades to a
/// snapshot-less record rather than failing the mutation.
fn snapshot<T: serde::Serialize>(record: &T) -> Option<serde_json::Value> {
    serde_json::to_value(record).ok()
}

/// Validate a facility via the `dpp-registry` structural/checksum check (country
/// code + GLN checksum when `scheme == "gln"`), plus non-empty required fields.
fn validate_facility(req: &CreateFacilityRequest) -> Result<(), DppError> {
    if req.name.trim().is_empty() {
        return Err(DppError::Validation("facility name is required".into()));
    }
    if req.identifier_scheme.trim().is_empty() || req.identifier_value.trim().is_empty() {
        return Err(DppError::Validation(
            "identifierScheme and identifierValue are required".into(),
        ));
    }
    let fid = dpp_registry::FacilityIdentifier {
        scheme: req.identifier_scheme.trim().to_owned(),
        value: req.identifier_value.trim().to_owned(),
        name: Some(req.name.trim().to_owned()),
        country: req.country.trim().to_uppercase(),
        address: req.address.clone(),
    };
    fid.validate()
        .map_err(|e| DppError::Validation(e.to_string().into()))
}

/// Validate an operator identifier via the `dpp-registry` scheme check
/// (LEI ISO 7064, DUNS length, EORI/VAT prefix), plus non-empty fields.
///
/// `operator_country` is the operator's own registered country (`OperatorConfig`):
/// an Art. 13 identifier belongs to the operator, not a location, so it has no
/// per-entry country of its own — the operator's country is reused for the
/// `dpp-registry` validation, which requires a non-empty ISO code.
fn validate_operator_identifier(
    req: &CreateOperatorIdentifierRequest,
    operator_country: &str,
) -> Result<(), DppError> {
    if req.scheme.trim().is_empty() || req.value.trim().is_empty() {
        return Err(DppError::Validation("scheme and value are required".into()));
    }
    let oid = dpp_registry::OperatorIdentifier {
        scheme: req.scheme.trim().to_lowercase(),
        value: req.value.trim().to_owned(),
        name: req
            .label
            .clone()
            .unwrap_or_else(|| req.value.trim().to_owned()),
        country: operator_country.trim().to_uppercase(),
        did: None,
    };
    oid.validate()
        .map_err(|e| DppError::Validation(e.to_string().into()))
}
