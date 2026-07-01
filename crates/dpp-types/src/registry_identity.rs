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

/// An immutable audit record for a registry-identity mutation (a facility per
/// Annex III or an operator identifier per Art. 13).
///
/// Because a facility's identifier is stamped by value onto immutable passports,
/// its lifecycle is compliance-relevant provenance. These records let the
/// operator reconstruct what their facility / identifier set was at any time,
/// including who retired a facility and when. Append-only: the DB trigger raises
/// on any UPDATE or DELETE (mirrors `passport_audit`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryIdentityAudit {
    pub id: Uuid,
    /// Provenance identity of the node operator (`STANDALONE_OPERATOR_ID`).
    pub operator_id: String,
    /// `"facility"` or `"operator_identifier"`.
    pub entity_type: String,
    /// Id of the facility / identifier the action was applied to.
    pub entity_id: Uuid,
    /// `"added"`, `"retired"`, `"set_default"`, or `"set_primary"`.
    pub action: String,
    /// `user_id` of the actor who performed the change, from `AuthContext`.
    pub actor: String,
    /// The full record at the time of the action, for reconstruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<serde_json::Value>,
    pub ts: DateTime<Utc>,
}

impl RegistryIdentityAudit {
    /// Construct an append-only audit record with a fresh time-ordered id.
    pub fn new(
        operator_id: &str,
        entity_type: &str,
        entity_id: Uuid,
        action: &str,
        actor: &str,
        snapshot: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            operator_id: operator_id.to_owned(),
            entity_type: entity_type.to_owned(),
            entity_id,
            action: action.to_owned(),
            actor: actor.to_owned(),
            snapshot,
            ts: Utc::now(),
        }
    }
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
    /// such **live** facility exists.
    async fn set_default_facility(&self, operator_id: &str, id: Uuid) -> Result<bool, DppError>;
    /// Retire a facility (soft-delete): mark it `retired_at` and clear its
    /// default flag, keeping the row as Annex III provenance for passports that
    /// already stamped its identifier. Never hard-deletes. Returns the retired
    /// facility, or `None` if no **live** facility with that id exists.
    async fn retire_facility(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<Option<Facility>, DppError>;

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
    /// no such **live** identifier exists.
    async fn set_primary_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<bool, DppError>;
    /// Retire an operator identifier (soft-delete): mark it `retired_at` and clear
    /// its primary flag, keeping the row as Art. 13 provenance for passports that
    /// stamped its value. Never hard-deletes. Returns the retired identifier, or
    /// `None` if no **live** identifier with that id exists.
    async fn retire_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<Option<OperatorIdentifier>, DppError>;

    // ── Registry-identity audit (append-only) ────────────────────────────────
    /// Append an immutable audit record for a registry-identity mutation.
    async fn append_audit(&self, entry: RegistryIdentityAudit) -> Result<(), DppError>;
    /// List the append-only audit trail for one entity, oldest first.
    async fn list_registry_audit(
        &self,
        entity_type: &str,
        entity_id: Uuid,
    ) -> Result<Vec<RegistryIdentityAudit>, DppError>;
}
