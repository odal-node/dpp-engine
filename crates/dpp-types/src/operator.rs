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
    /// When this operator completed EU registry identity verification.
    ///
    /// `None` means never verified — the right state for a deployment that has
    /// not onboarded, and distinct from "verified, date unknown". See
    /// [`OperatorConfig::registry_verification_expires_at`] for what it implies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_verified_at: Option<DateTime<Utc>>,
    /// Row creation timestamp.
    pub created_at: Option<DateTime<Utc>>,
    /// Last-update timestamp.
    pub updated_at: Option<DateTime<Utc>>,
}

/// The regulation's hard cap on how long verified-operator status lasts,
/// regardless of the electronic identification means used.
pub const REGISTRY_VERIFICATION_MAX_YEARS: i64 = 3;

impl OperatorConfig {
    /// When this operator's verified-registry status lapses, or `None` if it
    /// was never verified.
    ///
    /// This is the **three-year cap** measured from the verification date. The
    /// eID means used may expire sooner, in which case status ends then — that
    /// earlier date is not modelled here because nothing in this system knows
    /// it. So this is an upper bound: verification never lasts longer than this,
    /// and may end before it.
    #[must_use]
    pub fn registry_verification_expires_at(&self) -> Option<DateTime<Utc>> {
        self.registry_verified_at
            .map(|at| at + chrono::Duration::days(365 * REGISTRY_VERIFICATION_MAX_YEARS))
    }

    /// Whether this operator may currently register passports with the EU
    /// registry.
    ///
    /// `false` both when never verified and when verification has lapsed — the
    /// registry refuses either way, so they are one answer here even though
    /// they are different situations to an operator reading a status page.
    #[must_use]
    pub fn registry_verification_is_current(&self, now: DateTime<Utc>) -> bool {
        self.registry_verification_expires_at()
            .is_some_and(|expiry| now < expiry)
    }
}

fn default_data_residency() -> String {
    "EU".to_owned()
}

/// Minimum data-retention floor (days, 10 years). A configured retention
/// shorter than this would violate the minimum-retention guarantee.
///
/// **Not an ESPR figure.** ESPR (EU) 2024/1781 Art. 9(2)(i) sets no number — it
/// requires availability for "at least the expected lifetime of a specific
/// product". The 10 years is read off the regimes that do state a figure:
/// Reg. (EU) 2025/2509 (toys) and Reg. (EU) 2026/405 (detergents) both require
/// the passport to be available for 10 years after placing on the market,
/// "including in cases of insolvency, liquidation or cessation of activity",
/// and Reg. (EU) 2024/3110 (CPR) imposes the same 10 years on the economic
/// operator.
///
/// This is a **floor**, not the answer: the per-product group figure lives in the
/// catalog as `ProductGroupDescriptor::retention_years`, and a product group whose act
/// demands more must carry it there. Two cases this constant deliberately does
/// not express — CPR additionally requires the *construction DPP system* to
/// stay accessible for **25 years**, which binds a passport service provider
/// rather than a node; and the ESPR product groups' figure is tied to expected product
/// lifetime, so their catalog value is an assumption rather than a citation.
pub const MIN_RETENTION_DAYS: i64 = 3650;

fn default_retention_days() -> i64 {
    MIN_RETENTION_DAYS
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
            registry_verified_at: None,
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// When this operator completed EU registry identity verification.
    ///
    /// Recorded by the operator after enrolling with the registry — nothing in
    /// this node can observe it, and until it is set the node holds every
    /// registration rather than submitting as an unverified operator.
    ///
    /// Set-only: passing `None` leaves any existing date untouched, in keeping
    /// with the rest of this patch type. Correcting a wrong date means passing
    /// the right one.
    pub registry_verified_at: Option<DateTime<Utc>>,
}

impl UpdateOperatorConfig {
    /// Validate the patch's invariants before it is applied.
    ///
    /// # Errors
    /// Returns a message if `retention_policy_days` is present and below
    /// [`MIN_RETENTION_DAYS`] (the ESPR minimum-retention floor) — the config
    /// must never silently drop below the documented minimum-retention guarantee.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(days) = self.retention_policy_days
            && days < MIN_RETENTION_DAYS
        {
            return Err(format!(
                "retentionPolicyDays must be at least {MIN_RETENTION_DAYS} \
                 (ESPR minimum retention); got {days}"
            ));
        }
        // Verification is an event that has already happened. A future date
        // would silently extend the three-year window derived from it, which is
        // the one thing an operator must not be able to grant themselves.
        if let Some(at) = self.registry_verified_at
            && at > Utc::now()
        {
            return Err(format!(
                "registryVerifiedAt cannot be in the future; got {at}"
            ));
        }
        Ok(())
    }

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
        if let Some(v) = self.registry_verified_at {
            cfg.registry_verified_at = Some(v);
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

    /// The operator's **primary** economic-operator identifier (ESPR Art. 13)
    /// as a `(scheme, value)` pair — e.g. `("vat", "DE811234567")` — or `None`
    /// if none is configured.
    ///
    /// The scheme travels with the value because the value alone does not say
    /// what it is, and the EU registry requires the scheme to be stated. A
    /// caller holding only the value has to guess, and a wrong guess is a false
    /// statement the registry cannot detect.
    ///
    /// Default impl returns `None` so non-persistent test doubles need not implement it.
    async fn primary_operator_identifier(
        &self,
        _operator_id: &str,
    ) -> Result<Option<(String, String)>, DppError> {
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

    fn patch_with_retention(days: Option<i64>) -> UpdateOperatorConfig {
        UpdateOperatorConfig {
            legal_name: None,
            trade_name: None,
            address: None,
            country: None,
            contact_email: None,
            did_web_url: None,
            product_categories: None,
            brand_primary: None,
            brand_secondary: None,
            brand_logo_url: None,
            custom_domain: None,
            data_residency: None,
            retention_policy_days: days,
            feature_flags: None,
            registry_verified_at: None,
        }
    }

    #[test]
    fn validate_rejects_retention_below_minimum() {
        assert!(patch_with_retention(Some(-1)).validate().is_err());
        assert!(patch_with_retention(Some(0)).validate().is_err());
        assert!(
            patch_with_retention(Some(MIN_RETENTION_DAYS - 1))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_accepts_retention_at_or_above_minimum_and_absent() {
        assert!(
            patch_with_retention(Some(MIN_RETENTION_DAYS))
                .validate()
                .is_ok()
        );
        assert!(patch_with_retention(Some(5475)).validate().is_ok()); // ~15y
        assert!(patch_with_retention(None).validate().is_ok());
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;

    fn config_verified(at: Option<DateTime<Utc>>) -> OperatorConfig {
        OperatorConfig {
            registry_verified_at: at,
            ..OperatorConfig::empty("op")
        }
    }

    /// Never verified is not "verified long ago" — there is no expiry to report,
    /// and the operator cannot register.
    #[test]
    fn a_never_verified_operator_has_no_expiry_and_cannot_register() {
        let cfg = config_verified(None);
        assert!(cfg.registry_verification_expires_at().is_none());
        assert!(!cfg.registry_verification_is_current(Utc::now()));
    }

    /// The regulation caps verified status at three years from verification.
    #[test]
    fn verification_expires_three_years_after_it_was_granted() {
        let verified_at = Utc::now() - chrono::Duration::days(365);
        let cfg = config_verified(Some(verified_at));
        let expiry = cfg.registry_verification_expires_at().expect("has expiry");
        assert_eq!(expiry, verified_at + chrono::Duration::days(365 * 3));
        assert!(cfg.registry_verification_is_current(Utc::now()));
    }

    /// A day past the cap and registration is closed until re-verification.
    #[test]
    fn verification_lapses_once_the_cap_passes() {
        let cfg = config_verified(Some(Utc::now() - chrono::Duration::days(365 * 3 + 1)));
        assert!(!cfg.registry_verification_is_current(Utc::now()));
    }

    /// The boundary belongs to the expired side: at the instant of expiry the
    /// status is no longer current.
    #[test]
    fn the_expiry_instant_is_not_current() {
        let verified_at = Utc::now() - chrono::Duration::days(365 * 3);
        let cfg = config_verified(Some(verified_at));
        let expiry = cfg.registry_verification_expires_at().unwrap();
        assert!(!cfg.registry_verification_is_current(expiry));
        assert!(cfg.registry_verification_is_current(expiry - chrono::Duration::seconds(1)));
    }
}

#[cfg(test)]
mod registry_verification_patch_tests {
    use super::*;

    fn patch_verified_at(at: Option<DateTime<Utc>>) -> UpdateOperatorConfig {
        UpdateOperatorConfig {
            registry_verified_at: at,
            ..patch_none()
        }
    }

    fn patch_none() -> UpdateOperatorConfig {
        UpdateOperatorConfig {
            legal_name: None,
            trade_name: None,
            address: None,
            country: None,
            contact_email: None,
            did_web_url: None,
            product_categories: None,
            brand_primary: None,
            brand_secondary: None,
            brand_logo_url: None,
            custom_domain: None,
            data_residency: None,
            retention_policy_days: None,
            feature_flags: None,
            registry_verified_at: None,
        }
    }

    /// Recording the verification date is what lets a node start registering:
    /// without it the drain holds every submission.
    #[test]
    fn setting_the_verification_date_makes_the_operator_current() {
        let mut cfg = OperatorConfig::empty("op");
        assert!(
            !cfg.registry_verification_is_current(Utc::now()),
            "a fresh node is not verified"
        );

        patch_verified_at(Some(Utc::now() - chrono::Duration::days(1))).apply(&mut cfg);

        assert!(
            cfg.registry_verification_is_current(Utc::now()),
            "recording the date must unblock registration"
        );
    }

    /// Verification is an event that already happened. A future date would
    /// silently extend the three-year window derived from it — the one thing an
    /// operator must not be able to grant themselves.
    #[test]
    fn a_future_verification_date_is_refused() {
        let err = patch_verified_at(Some(Utc::now() + chrono::Duration::days(1)))
            .validate()
            .expect_err("a future date must be refused");
        assert!(err.contains("registryVerifiedAt"), "got: {err}");
    }

    /// Set-only, like every other field on this patch: omitting it must not
    /// erase a recorded date and silently stop registration.
    #[test]
    fn omitting_the_date_leaves_an_existing_one_untouched() {
        let verified = Utc::now() - chrono::Duration::days(10);
        let mut cfg = OperatorConfig {
            registry_verified_at: Some(verified),
            ..OperatorConfig::empty("op")
        };

        // A patch that changes something else entirely.
        UpdateOperatorConfig {
            brand_primary: Some("#000000".into()),
            ..patch_none()
        }
        .apply(&mut cfg);

        assert_eq!(cfg.registry_verified_at, Some(verified));
    }
}
