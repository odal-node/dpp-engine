//! Registry-identity types and repository port: the operator's **facilities**
//! (ESPR Annex III) and **economic-operator identifiers** (ESPR Art. 13).
//!
//! These are the records stamped onto new passports (see the vault's create
//! path) and sent in EU registry payloads. They are managed through the API/CLI
//! control plane — never seeded by hand — so this module is the single source
//! of their shape.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::DppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A manufacturing/processing facility (ESPR Annex III). Exactly one per
/// operator may be `is_default`; that one is stamped onto new passports.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Facility {
    pub id: Uuid,
    /// Human-readable facility name.
    pub name: String,
    /// Identifier scheme (e.g. `"gln"`, `"national"`).
    pub identifier_scheme: String,
    /// Identifier value (e.g. the 13-digit GLN).
    pub identifier_value: String,
    /// ISO 3166-1 alpha-2 country code of the facility.
    pub country: String,
    /// Optional street address / location description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Whether this facility is the operator's default (stamped on new passports).
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

/// Request body for `POST /api/v1/facilities`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFacilityRequest {
    pub name: String,
    pub identifier_scheme: String,
    pub identifier_value: String,
    pub country: String,
    #[serde(default)]
    pub address: Option<String>,
    /// Make this the default facility on creation (unsets any previous default).
    #[serde(default)]
    pub is_default: bool,
}

/// An economic-operator identifier (ESPR Art. 13 — EORI/VAT/LEI/DUNS/…).
/// Exactly one per operator may be `is_primary`; that one is stamped on new
/// passports.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorIdentifier {
    pub id: Uuid,
    /// Identifier scheme (e.g. `"vat"`, `"lei"`, `"eori"`, `"duns"`).
    pub scheme: String,
    /// The identifier value (e.g. the VAT or LEI string).
    pub value: String,
    /// Optional human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Whether this identifier is the operator's primary (stamped on new passports).
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
}

/// Request body for `POST /api/v1/operator-identifiers`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOperatorIdentifierRequest {
    pub scheme: String,
    pub value: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Make this the primary identifier on creation (unsets any previous primary).
    #[serde(default)]
    pub is_primary: bool,
}

/// Port trait for managing the operator's facilities and economic-operator
/// identifiers. All methods are scoped by `operator_id` (the node's constant
/// `STANDALONE_OPERATOR_ID` — single-tenant, not a tenant discriminator).
#[async_trait]
pub trait RegistryIdentityRepository: Send + Sync {
    // ── Facilities (Annex III) ───────────────────────────────────────────────
    async fn list_facilities(&self, operator_id: &str) -> Result<Vec<Facility>, DppError>;
    async fn add_facility(
        &self,
        operator_id: &str,
        facility: Facility,
    ) -> Result<Facility, DppError>;
    /// Make the facility `id` the sole default for this operator. `false` if no
    /// such facility exists.
    async fn set_default_facility(&self, operator_id: &str, id: Uuid) -> Result<bool, DppError>;
    /// Delete a facility by id. `false` if no such facility exists.
    async fn delete_facility(&self, operator_id: &str, id: Uuid) -> Result<bool, DppError>;

    // ── Operator identifiers (Art. 13) ───────────────────────────────────────
    async fn list_operator_identifiers(
        &self,
        operator_id: &str,
    ) -> Result<Vec<OperatorIdentifier>, DppError>;
    async fn add_operator_identifier(
        &self,
        operator_id: &str,
        identifier: OperatorIdentifier,
    ) -> Result<OperatorIdentifier, DppError>;
    /// Make the identifier `id` the sole primary for this operator. `false` if
    /// no such identifier exists.
    async fn set_primary_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<bool, DppError>;
    /// Delete an operator identifier by id. `false` if no such identifier exists.
    async fn delete_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<bool, DppError>;
}
