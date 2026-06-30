//! `RegistryIdentityRepository` on PostgreSQL — operator facilities
//! (`odal.facility`) and economic-operator identifiers (`odal.operator_identifier`).
//!
//! Single-tenant: every method is scoped by `operator_id`, the node's constant
//! provenance identity (`STANDALONE_OPERATOR_ID`), not a tenant key.

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_types::registry_identity::{Facility, OperatorIdentifier, RegistryIdentityRepository};

use super::{PgDal, db_err};

/// Map a Postgres unique-violation (SQLSTATE 23505) to a clean validation error
/// (so a duplicate facility/identifier returns 422, not an opaque 500), falling
/// back to the generic mapping for any other database error.
fn dup_or_db_err(e: sqlx::Error, message: &str) -> DppError {
    if matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")) {
        DppError::Validation(message.into())
    } else {
        db_err(e)
    }
}

/// PostgreSQL implementation of [`RegistryIdentityRepository`].
pub struct PgRegistryIdentityRepo {
    dal: PgDal,
}

impl PgRegistryIdentityRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn facility_from_row(r: &sqlx::postgres::PgRow) -> Facility {
        Facility {
            id: r.get("id"),
            name: r.get("name"),
            identifier_scheme: r.get("identifier_scheme"),
            identifier_value: r.get("identifier_value"),
            country: r.get::<String, _>("country"),
            address: r.get("address"),
            is_default: r.get("is_default"),
            created_at: r.get("created_at"),
        }
    }

    fn operator_id_from_row(r: &sqlx::postgres::PgRow) -> OperatorIdentifier {
        OperatorIdentifier {
            id: r.get("id"),
            scheme: r.get("scheme"),
            value: r.get("value"),
            label: r.get("label"),
            is_primary: r.get("is_primary"),
            created_at: r.get("created_at"),
        }
    }
}

#[async_trait]
impl RegistryIdentityRepository for PgRegistryIdentityRepo {
    // ── Facilities ───────────────────────────────────────────────────────────

    async fn list_facilities(&self, operator_id: &str) -> Result<Vec<Facility>, DppError> {
        let rows = sqlx::query(
            "SELECT id, name, identifier_scheme, identifier_value, country, address, \
                    is_default, created_at \
             FROM odal.facility WHERE operator_id = $1 \
             ORDER BY is_default DESC, created_at DESC",
        )
        .bind(operator_id)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::facility_from_row).collect())
    }

    async fn add_facility(
        &self,
        operator_id: &str,
        facility: Facility,
    ) -> Result<Facility, DppError> {
        let row = sqlx::query(
            "INSERT INTO odal.facility \
               (id, operator_id, name, identifier_scheme, identifier_value, country, address, \
                is_default, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             RETURNING id, name, identifier_scheme, identifier_value, country, address, \
                       is_default, created_at",
        )
        .bind(facility.id)
        .bind(operator_id)
        .bind(&facility.name)
        .bind(&facility.identifier_scheme)
        .bind(&facility.identifier_value)
        .bind(&facility.country)
        .bind(&facility.address)
        // Always insert non-default; a requested default is applied below via the
        // single atomic UPDATE, so there is never a window with two defaults.
        .bind(false)
        .bind(facility.created_at)
        .fetch_one(self.dal.pool())
        .await
        .map_err(|e| {
            dup_or_db_err(
                e,
                "a facility with this identifier scheme + value already exists",
            )
        })?;

        let mut created = Self::facility_from_row(&row);
        if facility.is_default {
            self.set_default_facility(operator_id, facility.id).await?;
            created.is_default = true;
        }
        Ok(created)
    }

    async fn set_default_facility(&self, operator_id: &str, id: Uuid) -> Result<bool, DppError> {
        // One statement flips the chosen row to default and all others off.
        let res = sqlx::query(
            "UPDATE odal.facility SET is_default = (id = $2), updated_at = now() \
             WHERE operator_id = $1",
        )
        .bind(operator_id)
        .bind(id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        // rows_affected counts every facility; confirm the target actually exists.
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        let exists = sqlx::query("SELECT 1 FROM odal.facility WHERE operator_id = $1 AND id = $2")
            .bind(operator_id)
            .bind(id)
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(exists.is_some())
    }

    async fn delete_facility(&self, operator_id: &str, id: Uuid) -> Result<bool, DppError> {
        let res = sqlx::query("DELETE FROM odal.facility WHERE operator_id = $1 AND id = $2")
            .bind(operator_id)
            .bind(id)
            .execute(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── Operator identifiers ─────────────────────────────────────────────────

    async fn list_operator_identifiers(
        &self,
        operator_id: &str,
    ) -> Result<Vec<OperatorIdentifier>, DppError> {
        let rows = sqlx::query(
            "SELECT id, scheme, value, label, is_primary, created_at \
             FROM odal.operator_identifier WHERE operator_id = $1 \
             ORDER BY is_primary DESC, created_at DESC",
        )
        .bind(operator_id)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::operator_id_from_row).collect())
    }

    async fn add_operator_identifier(
        &self,
        operator_id: &str,
        identifier: OperatorIdentifier,
    ) -> Result<OperatorIdentifier, DppError> {
        let row = sqlx::query(
            "INSERT INTO odal.operator_identifier \
               (id, operator_id, scheme, value, label, is_primary, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) \
             RETURNING id, scheme, value, label, is_primary, created_at",
        )
        .bind(identifier.id)
        .bind(operator_id)
        .bind(&identifier.scheme)
        .bind(&identifier.value)
        .bind(&identifier.label)
        // Always insert non-primary; a requested primary is applied below via the
        // single atomic UPDATE, so there is never a window with two primaries.
        .bind(false)
        .bind(identifier.created_at)
        .fetch_one(self.dal.pool())
        .await
        .map_err(|e| {
            dup_or_db_err(
                e,
                "an operator identifier with this scheme + value already exists",
            )
        })?;

        let mut created = Self::operator_id_from_row(&row);
        if identifier.is_primary {
            self.set_primary_operator_identifier(operator_id, identifier.id)
                .await?;
            created.is_primary = true;
        }
        Ok(created)
    }

    async fn set_primary_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<bool, DppError> {
        let res = sqlx::query(
            "UPDATE odal.operator_identifier SET is_primary = (id = $2) WHERE operator_id = $1",
        )
        .bind(operator_id)
        .bind(id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        let exists = sqlx::query(
            "SELECT 1 FROM odal.operator_identifier WHERE operator_id = $1 AND id = $2",
        )
        .bind(operator_id)
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(exists.is_some())
    }

    async fn delete_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<bool, DppError> {
        let res =
            sqlx::query("DELETE FROM odal.operator_identifier WHERE operator_id = $1 AND id = $2")
                .bind(operator_id)
                .bind(id)
                .execute(self.dal.pool())
                .await
                .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }
}
