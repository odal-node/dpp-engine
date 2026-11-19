//! `OperatorConfigRepository` on PostgreSQL — explicit column mapping
//! (operator_config is fully relational; no doc column).

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::{DppError, FacilitySnapshot};
use dpp_types::operator::{OperatorConfig, OperatorConfigRepository, UpdateOperatorConfig};

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
            registry_verified_at: r.get("registry_verified_at"),
            // The column's CHECK admits only the four wire names, so a value
            // that does not read is not one a write could have stored.
            enterprise_size: r
                .get::<Option<String>, _>("enterprise_size")
                .and_then(|size| serde_json::from_value(serde_json::Value::String(size)).ok()),
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

    /// Snapshot of the operator's default facility (ESPR Annex III).
    ///
    /// Returns the full descriptor (scheme, value, name, country, address) of the
    /// live `is_default` facility, or `None` when none is configured. Copied by
    /// value onto new passports so the signed record stays self-contained.
    async fn default_facility(
        &self,
        operator_id: &str,
    ) -> Result<Option<FacilitySnapshot>, DppError> {
        let row = sqlx::query(
            "SELECT identifier_scheme, identifier_value, name, country, address \
             FROM odal.facility \
             WHERE operator_id = $1 AND is_default = true AND retired_at IS NULL LIMIT 1",
        )
        .bind(operator_id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| FacilitySnapshot {
            scheme: r.get("identifier_scheme"),
            value: r.get("identifier_value"),
            name: r.get("name"),
            country: r.get::<String, _>("country"),
            address: r.get("address"),
            // Not typed here: `actor_identifier()` reads the scheme and value
            // above when this is unset, and leaving it unset keeps the snapshot's
            // bytes as they were.
            identifier: None,
        }))
    }

    /// Value of the operator's primary economic-operator identifier (ESPR Art. 13).
    ///
    /// Returns the `value` of the `is_primary` operator identifier, or `None`
    /// when none is marked primary.
    async fn primary_operator_identifier(
        &self,
        operator_id: &str,
    ) -> Result<Option<(String, String)>, DppError> {
        // Both columns. The scheme is what says whether the value is a VAT
        // number, an LEI or a DID — selecting the value alone left every caller
        // to guess, and the registry mapping guessed `did` for all of them.
        let row = sqlx::query(
            "SELECT scheme, value FROM odal.operator_identifier \
             WHERE operator_id = $1 AND is_primary = true AND retired_at IS NULL LIMIT 1",
        )
        .bind(operator_id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| (r.get::<String, _>("scheme"), r.get::<String, _>("value"))))
    }

    /// Insert or update the operator config (upsert on `operator_id`).
    ///
    /// `created_at` is set on first insert; `updated_at` is refreshed on
    /// every upsert. Returns the final persisted row.
    ///
    /// A whole-row write that takes no lock before it: it overwrites a change
    /// committed after `config` was read. For seeding; use
    /// [`update`](Self::update) to change an existing config.
    async fn upsert(&self, config: OperatorConfig) -> Result<OperatorConfig, DppError> {
        let row = bind_row(UPSERT_SQL, &config)?
            .fetch_one(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(Self::from_row(&row))
    }

    /// Patch the stored config in one transaction that holds its row.
    ///
    /// 1. `INSERT … ON CONFLICT DO NOTHING` of [`OperatorConfig::empty`]. A
    ///    lock needs a row: with none, `FOR UPDATE` locks nothing and two first
    ///    updates would both read "absent". The insert makes the row exist, and
    ///    a second first update waits on the first one's uncommitted insert.
    /// 2. `SELECT … FOR UPDATE` reads the row and holds it, so a concurrent
    ///    update waits here until this one commits, then reads what it wrote.
    /// 3. [`UpdateOperatorConfig::apply`] patches the row read.
    /// 4. The write is [`upsert`](Self::upsert)'s statement, so the `COALESCE`
    ///    on `registry_verified_at` and `enterprise_size` and the refusal of a
    ///    `retention_policy_days` beyond `i32` apply here as they do there.
    ///
    /// Any error drops the transaction, which rolls back the row step 1 made.
    async fn update(
        &self,
        operator_id: &str,
        patch: &UpdateOperatorConfig,
    ) -> Result<OperatorConfig, DppError> {
        let mut tx = self.dal.pool().begin().await.map_err(db_err)?;
        bind_row(INSERT_IF_ABSENT_SQL, &OperatorConfig::empty(operator_id))?
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        let held =
            sqlx::query("SELECT * FROM odal.operator_config WHERE operator_id = $1 FOR UPDATE")
                .bind(operator_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
        let mut config = Self::from_row(&held);
        patch.apply(&mut config);
        let written = bind_row(UPSERT_SQL, &config)?
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(Self::from_row(&written))
    }
}

/// The `INSERT` every write of a whole config row starts with. A macro, not a
/// `const`, so `concat!` can join it to each statement's `ON CONFLICT` clause:
/// the column list and its placeholders are written once.
macro_rules! insert_row {
    () => {
        r#"INSERT INTO odal.operator_config
             (operator_id, legal_name, trade_name, address, country, contact_email,
              did_web_url, product_categories, brand_primary, brand_secondary,
              brand_logo_url, custom_domain, data_residency, retention_policy_days,
              feature_flags, registry_verified_at, enterprise_size, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now(),now())"#
    };
}

/// Write the whole row, replacing what a conflicting row holds.
const UPSERT_SQL: &str = concat!(
    insert_row!(),
    r#"
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
                 -- COALESCE, not overwrite: a config update that does not carry
                 -- a verification date must not silently erase one. Clearing it
                 -- is a deliberate act, not a side effect of editing branding.
                 registry_verified_at =
                   COALESCE(EXCLUDED.registry_verified_at, odal.operator_config.registry_verified_at),
                 -- COALESCE for the same reason: the size decides whether the
                 -- destruction ban reaches this operator, and an edit that does
                 -- not carry one must not reset it to "not stated".
                 enterprise_size =
                   COALESCE(EXCLUDED.enterprise_size, odal.operator_config.enterprise_size),
                 updated_at = now()
               RETURNING *"#
);

/// Create the row when none exists and leave an existing one untouched.
const INSERT_IF_ABSENT_SQL: &str = concat!(insert_row!(), " ON CONFLICT (operator_id) DO NOTHING");

/// Bind every column of `config` to `sql`, one of the statements above.
///
/// The one place a config becomes a row, so the statements cannot disagree on
/// what a column holds or what is refused.
fn bind_row<'q>(
    sql: &'static str,
    config: &OperatorConfig,
) -> Result<sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>, DppError> {
    let cats = config
        .product_categories
        .as_ref()
        .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null));
    // The column is INTEGER. A value outside its range would wrap to a number
    // that can be below the retention floor the API enforced, so it is refused
    // here rather than narrowed.
    let retention_days = i32::try_from(config.retention_policy_days).map_err(|_| {
        DppError::Validation(
            format!(
                "retention_policy_days {} is outside the storable range",
                config.retention_policy_days
            )
            .into(),
        )
    })?;
    Ok(sqlx::query(sql)
        .bind(config.operator_id.clone())
        .bind(config.legal_name.clone())
        .bind(config.trade_name.clone())
        .bind(config.address.clone())
        .bind(config.country.clone())
        .bind(config.contact_email.clone())
        .bind(config.did_web_url.clone())
        .bind(cats)
        .bind(config.brand_primary.clone())
        .bind(config.brand_secondary.clone())
        .bind(config.brand_logo_url.clone())
        .bind(config.custom_domain.clone())
        .bind(config.data_residency.clone())
        .bind(retention_days)
        .bind(config.feature_flags.clone())
        .bind(config.registry_verified_at)
        .bind(
            config
                .enterprise_size
                .and_then(|size| serde_json::to_value(size).ok())
                .and_then(|wire| wire.as_str().map(str::to_owned)),
        ))
}
