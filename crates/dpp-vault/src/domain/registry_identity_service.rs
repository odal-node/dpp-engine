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
    RegistryIdentityRepository,
};

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

    pub async fn add_facility(&self, req: CreateFacilityRequest) -> Result<Facility, DppError> {
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
        self.repo
            .add_facility(STANDALONE_OPERATOR_ID, facility)
            .await
    }

    pub async fn set_default_facility(&self, id: Uuid) -> Result<(), DppError> {
        if self
            .repo
            .set_default_facility(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            Ok(())
        } else {
            Err(DppError::NotFound(id.to_string()))
        }
    }

    pub async fn delete_facility(&self, id: Uuid) -> Result<(), DppError> {
        if self
            .repo
            .delete_facility(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            Ok(())
        } else {
            Err(DppError::NotFound(id.to_string()))
        }
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
    ) -> Result<OperatorIdentifier, DppError> {
        validate_operator_identifier(&req)?;
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
        self.repo
            .add_operator_identifier(STANDALONE_OPERATOR_ID, identifier)
            .await
    }

    pub async fn set_primary_operator_identifier(&self, id: Uuid) -> Result<(), DppError> {
        if self
            .repo
            .set_primary_operator_identifier(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            Ok(())
        } else {
            Err(DppError::NotFound(id.to_string()))
        }
    }

    pub async fn delete_operator_identifier(&self, id: Uuid) -> Result<(), DppError> {
        if self
            .repo
            .delete_operator_identifier(STANDALONE_OPERATOR_ID, id)
            .await?
        {
            Ok(())
        } else {
            Err(DppError::NotFound(id.to_string()))
        }
    }
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
fn validate_operator_identifier(req: &CreateOperatorIdentifierRequest) -> Result<(), DppError> {
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
        // Per-identifier country is not modelled; empty skips the country check,
        // leaving the scheme/value structural validation (the part that matters here).
        country: String::new(),
        did: None,
    };
    oid.validate()
        .map_err(|e| DppError::Validation(e.to_string().into()))
}
