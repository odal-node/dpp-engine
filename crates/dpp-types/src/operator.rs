//! Operator configuration and repository port for the single-tenant node.
//!
//! `STANDALONE_OPERATOR_ID` is the constant identity of the single operator
//! this node serves — it is used as a provenance tag in audit records and
//! registry submissions, never as an in-process isolation scope.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::{DppError, FacilitySnapshot};
use serde::{Deserialize, Serialize};

/// Constant identity of the single operator this node serves.
///
/// Used as a provenance tag in database records and EU registry submissions.
/// This is NOT a tenant-isolation key — there is exactly one operator per node
/// (DECISION-0002). Do not add operator-scoping queries around this value.
pub const STANDALONE_OPERATOR_ID: &str = "self_hosted";

/// Operator configuration as stored in the `operator_config` table.
///
/// Fields are optional where an operator may not have completed onboarding.
/// `operator_id` is always `STANDALONE_OPERATOR_ID` for a self-hosted node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorConfig {
    /// The constant node operator identity (`STANDALONE_OPERATOR_ID`).
    pub operator_id: String,
    /// Legal name of the economic operator (e.g. company legal name).
    pub legal_name: String,
    /// Commercial/trade name if different from the legal name.
    pub trade_name: Option<String>,
    /// Registered address of the economic operator.
    pub address: String,
    /// ISO 3166-1 alpha-2 country code of the operator's registered address.
    pub country: String,
    /// Contact email for data-access requests and compliance queries.
    pub contact_email: String,
    /// `did:web` URL for the operator's DID document (used for JWS verification).
    pub did_web_url: Option<String>,
    /// Product categories this operator handles (informational; not a dispatch key).
    pub product_categories: Option<Vec<String>>,
    /// Primary brand colour hex code (e.g. `"#1A73E8"`).
    pub brand_primary: Option<String>,
    /// Secondary brand colour hex code.
    pub brand_secondary: Option<String>,
    /// URL of the operator's brand logo image.
    pub brand_logo_url: Option<String>,
    /// Custom domain for the public resolver (e.g. `"passports.acme.example.com"`).
    pub custom_domain: Option<String>,
    /// Data residency region (default `"EU"`). Informational only.
    #[serde(default = "default_data_residency")]
    pub data_residency: String,
    /// Minimum data retention in days for draft passports (default 3650 = ~10 years).
    #[serde(default = "default_retention_days")]
    pub retention_policy_days: i64,
    /// Feature flags as an opaque JSON object; resolved at boot by the node.
    pub feature_flags: Option<serde_json::Value>,
    /// Row creation timestamp.
    pub created_at: Option<DateTime<Utc>>,
    /// Last-update timestamp.
    pub updated_at: Option<DateTime<Utc>>,
}

fn default_data_residency() -> String {
    "EU".to_owned()
}

fn default_retention_days() -> i64 {
    3650
}

impl OperatorConfig {
    /// Construct an empty `OperatorConfig` for bootstrapping a fresh node.
    ///
    /// All optional fields are `None`; required fields are empty strings. The
    /// caller is expected to PATCH the config before going live.
    pub fn empty(operator_id: &str) -> Self {
        Self {
            operator_id: operator_id.to_owned(),
            legal_name: String::new(),
            trade_name: None,
            address: String::new(),
            country: String::new(),
            contact_email: String::new(),
            did_web_url: None,
            product_categories: None,
            brand_primary: None,
            brand_secondary: None,
            brand_logo_url: None,
            custom_domain: None,
            data_residency: default_data_residency(),
            retention_policy_days: default_retention_days(),
            feature_flags: None,
            created_at: None,
            updated_at: None,
        }
    }

    /// True when the responsible-economic-operator identity is complete enough
    /// to publish passports. The EU DPP requires the operator's legal name,
    /// registered address, country, and a contact for data-access requests.
    pub fn is_complete(&self) -> bool {
        self.missing_fields().is_empty()
    }

    /// The camelCase names of the required identity fields still missing.
    /// Empty when the operator profile is complete.
    pub fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.legal_name.trim().is_empty() {
            missing.push("legalName");
        }
        if self.address.trim().is_empty() {
            missing.push("address");
        }
        if self.country.trim().is_empty() {
            missing.push("country");
        }
        if self.contact_email.trim().is_empty() {
            missing.push("contactEmail");
        }
        missing
    }
}

/// Partial-update payload for `PATCH /api/v1/operator`.
///
/// Only `Some` fields are applied; `None` fields leave the existing value unchanged.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOperatorConfig {
    pub legal_name: Option<String>,
    pub trade_name: Option<String>,
    pub address: Option<String>,
    pub country: Option<String>,
    pub contact_email: Option<String>,
    pub did_web_url: Option<String>,
    pub product_categories: Option<Vec<String>>,
    pub brand_primary: Option<String>,
    pub brand_secondary: Option<String>,
    pub brand_logo_url: Option<String>,
    pub custom_domain: Option<String>,
    pub data_residency: Option<String>,
    pub retention_policy_days: Option<i64>,
    pub feature_flags: Option<serde_json::Value>,
}

impl UpdateOperatorConfig {
    /// Apply all `Some` fields from `self` onto `cfg` in-place.
    pub fn apply(&self, cfg: &mut OperatorConfig) {
        if let Some(ref v) = self.legal_name {
            cfg.legal_name = v.clone();
        }
        if let Some(ref v) = self.trade_name {
            cfg.trade_name = Some(v.clone());
        }
        if let Some(ref v) = self.address {
            cfg.address = v.clone();
        }
        if let Some(ref v) = self.country {
            cfg.country = v.clone();
        }
        if let Some(ref v) = self.contact_email {
            cfg.contact_email = v.clone();
        }
        if let Some(ref v) = self.did_web_url {
            cfg.did_web_url = Some(v.clone());
        }
        if let Some(ref v) = self.product_categories {
            cfg.product_categories = Some(v.clone());
        }
        if let Some(ref v) = self.brand_primary {
            cfg.brand_primary = Some(v.clone());
        }
        if let Some(ref v) = self.brand_secondary {
            cfg.brand_secondary = Some(v.clone());
        }
        if let Some(ref v) = self.brand_logo_url {
            cfg.brand_logo_url = Some(v.clone());
        }
        if let Some(ref v) = self.custom_domain {
            cfg.custom_domain = Some(v.clone());
        }
        if let Some(ref v) = self.data_residency {
            cfg.data_residency = v.clone();
        }
        if let Some(v) = self.retention_policy_days {
            cfg.retention_policy_days = v;
        }
        if let Some(ref v) = self.feature_flags {
            cfg.feature_flags = Some(v.clone());
        }
    }
}

/// Port trait for operator configuration persistence.
#[async_trait]
pub trait OperatorConfigRepository: Send + Sync {
    /// Fetch the operator config by id. Returns `None` if not yet bootstrapped.
    async fn get(&self, operator_id: &str) -> Result<Option<OperatorConfig>, DppError>;
    /// Create or update the operator config (upsert by `operator_id`).
    async fn upsert(&self, config: OperatorConfig) -> Result<OperatorConfig, DppError>;

    /// Snapshot of the operator's **default** facility (ESPR Annex III), or `None`
    /// if none is configured. Read live on create and copied by value onto the
    /// new passport so the signed record carries the full facility descriptor,
    /// independent of the operator's mutable facility registry.
    ///
    /// Default impl returns `None` so non-persistent test doubles need not implement it.
    async fn default_facility(
        &self,
        _operator_id: &str,
    ) -> Result<Option<FacilitySnapshot>, DppError> {
        Ok(None)
    }

    /// Value of the operator's **primary** economic-operator identifier
    /// (ESPR Art. 13 — e.g. EORI/VAT/LEI), or `None` if none is configured.
    ///
    /// Default impl returns `None` so non-persistent test doubles need not implement it.
    async fn primary_operator_identifier(
        &self,
        _operator_id: &str,
    ) -> Result<Option<String>, DppError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_operator_is_incomplete_with_all_fields_missing() {
        let cfg = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
        assert!(!cfg.is_complete());
        assert_eq!(
            cfg.missing_fields(),
            vec!["legalName", "address", "country", "contactEmail"]
        );
    }

    #[test]
    fn operator_with_required_identity_is_complete() {
        let mut cfg = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
        cfg.legal_name = "Acme GmbH".into();
        cfg.address = "1 Allee, Berlin".into();
        cfg.country = "DE".into();
        cfg.contact_email = "ops@acme.example".into();
        assert!(cfg.is_complete());
        assert!(cfg.missing_fields().is_empty());
    }

    #[test]
    fn whitespace_only_fields_count_as_missing() {
        let mut cfg = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
        cfg.legal_name = "Acme GmbH".into();
        cfg.address = "   ".into();
        cfg.country = "DE".into();
        cfg.contact_email = "ops@acme.example".into();
        assert!(!cfg.is_complete());
        assert_eq!(cfg.missing_fields(), vec!["address"]);
    }
}
