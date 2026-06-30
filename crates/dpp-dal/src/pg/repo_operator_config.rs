//! `OperatorConfigRepository` on PostgreSQL — explicit column mapping
//! (operator_config is fully relational; no doc column).

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::operator::{OperatorConfig, OperatorConfigRepository};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`OperatorConfigRepository`].
///
/// The `operator_config` table is fully relational (no doc column); each
/// field maps to an explicit column. Single-tenant: `operator_id` is the
/// node's constant provenance identity (`STANDALONE_OPERATOR_ID`), not a
/// scoping key.
pub struct PgOperatorConfigRepo {
    dal: PgDal,
}

impl PgOperatorConfigRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn from_row(r: &sqlx::postgres::PgRow) -> OperatorConfig {
        let cats: Option<serde_json::Value> = r.get("product_categories");
        OperatorConfig {
            operator_id: r.get("operator_id"),
            legal_name: r.get("legal_name"),
            trade_name: r.get("trade_name"),
            address: r.get("address"),
            country: r.get::<String, _>("country"),
            contact_email: r.get("contact_email"),
            did_web_url: r.get("did_web_url"),
            product_categories: cats.and_then(|v| serde_json::from_value(v).ok()),
            brand_primary: r.get("brand_primary"),
            brand_secondary: r.get("brand_secondary"),
            brand_logo_url: r.get("brand_logo_url"),
            custom_domain: r.get("custom_domain"),
            data_residency: r.get("data_residency"),
            retention_policy_days: r.get::<i32, _>("retention_policy_days").into(),
            feature_flags: r.get("feature_flags"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }
    }
}

#[async_trait]
impl OperatorConfigRepository for PgOperatorConfigRepo {
    /// Load the operator config row for `operator_id`.
    ///
    /// In a single-tenant node this is always called with `STANDALONE_OPERATOR_ID`.
    async fn get(&self, operator_id: &str) -> Result<Option<OperatorConfig>, DppError> {
        let row = sqlx::query("SELECT * FROM odal.operator_config WHERE operator_id = $1")
            .bind(operator_id)
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(row.as_ref().map(Self::from_row))
    }

    /// Identifier value of the operator's default facility (ESPR Annex III).
    ///
    /// Returns the `identifier_value` of the `is_default` facility, or `None`
    /// when the operator has not configured a default facility.
    async fn default_facility_identifier(
        &self,
        operator_id: &str,
    ) -> Result<Option<String>, DppError> {
        let row = sqlx::query(
            "SELECT identifier_value FROM odal.facility \
             WHERE operator_id = $1 AND is_default = true LIMIT 1",
        )
        .bind(operator_id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| r.get::<String, _>("identifier_value")))
    }

    /// Value of the operator's primary economic-operator identifier (ESPR Art. 13).
    ///
    /// Returns the `value` of the `is_primary` operator identifier, or `None`
    /// when none is marked primary.
    async fn primary_operator_identifier(
        &self,
        operator_id: &str,
    ) -> Result<Option<String>, DppError> {
        let row = sqlx::query(
            "SELECT value FROM odal.operator_identifier \
             WHERE operator_id = $1 AND is_primary = true LIMIT 1",
        )
        .bind(operator_id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| r.get::<String, _>("value")))
    }

    /// Insert or update the operator config (upsert on `operator_id`).
    ///
    /// `created_at` is set on first insert; `updated_at` is refreshed on
    /// every upsert. Returns the final persisted row.
    async fn upsert(&self, config: OperatorConfig) -> Result<OperatorConfig, DppError> {
        let cats = config
            .product_categories
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null));
        let row = sqlx::query(
            r#"INSERT INTO odal.operator_config
                 (operator_id, legal_name, trade_name, address, country, contact_email,
                  did_web_url, product_categories, brand_primary, brand_secondary,
                  brand_logo_url, custom_domain, data_residency, retention_policy_days,
                  feature_flags, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now(),now())
               ON CONFLICT (operator_id) DO UPDATE SET
                 legal_name = EXCLUDED.legal_name,
                 trade_name = EXCLUDED.trade_name,
                 address = EXCLUDED.address,
                 country = EXCLUDED.country,
                 contact_email = EXCLUDED.contact_email,
                 did_web_url = EXCLUDED.did_web_url,
                 product_categories = EXCLUDED.product_categories,
                 brand_primary = EXCLUDED.brand_primary,
                 brand_secondary = EXCLUDED.brand_secondary,
                 brand_logo_url = EXCLUDED.brand_logo_url,
                 custom_domain = EXCLUDED.custom_domain,
                 data_residency = EXCLUDED.data_residency,
                 retention_policy_days = EXCLUDED.retention_policy_days,
                 feature_flags = EXCLUDED.feature_flags,
                 updated_at = now()
               RETURNING *"#,
        )
        .bind(&config.operator_id)
        .bind(&config.legal_name)
        .bind(&config.trade_name)
        .bind(&config.address)
        .bind(&config.country)
        .bind(&config.contact_email)
        .bind(&config.did_web_url)
        .bind(cats)
        .bind(&config.brand_primary)
        .bind(&config.brand_secondary)
        .bind(&config.brand_logo_url)
        .bind(&config.custom_domain)
        .bind(&config.data_residency)
        .bind(config.retention_policy_days as i32)
        .bind(&config.feature_flags)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(Self::from_row(&row))
    }
}
