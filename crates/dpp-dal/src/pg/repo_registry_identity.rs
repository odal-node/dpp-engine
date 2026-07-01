//! `RegistryIdentityRepository` on PostgreSQL — operator facilities
//! (`odal.facility`) and economic-operator identifiers (`odal.operator_identifier`).
//!
//! Single-tenant: every method is scoped by `operator_id`, the node's constant
//! provenance identity (`STANDALONE_OPERATOR_ID`), not a tenant key.

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_types::registry_identity::{
    Facility, OperatorIdentifier, RegistryIdentityAudit, RegistryIdentityRepository,
};

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

    fn registry_audit_from_row(r: &sqlx::postgres::PgRow) -> RegistryIdentityAudit {
        RegistryIdentityAudit {
            id: r.get("id"),
            operator_id: r.get("operator_id"),
            entity_type: r.get("entity_type"),
            entity_id: r.get("entity_id"),
            action: r.get("action"),
            actor: r.get("actor"),
            snapshot: r.get("snapshot"),
            ts: r.get("ts"),
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
             FROM odal.facility WHERE operator_id = $1 AND retired_at IS NULL \
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
        // One statement flips the chosen row to default and all other live rows
        // off. Retired facilities are excluded so a retired row can never carry
        // the default flag and can never be re-defaulted.
        let res = sqlx::query(
            "UPDATE odal.facility SET is_default = (id = $2), updated_at = now() \
             WHERE operator_id = $1 AND retired_at IS NULL",
        )
        .bind(operator_id)
        .bind(id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        // rows_affected counts every live facility; confirm the target is live.
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        let exists = sqlx::query(
            "SELECT 1 FROM odal.facility \
             WHERE operator_id = $1 AND id = $2 AND retired_at IS NULL",
        )
        .bind(operator_id)
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(exists.is_some())
    }

    async fn retire_facility(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<Option<Facility>, DppError> {
        // Soft-delete: the row is Annex III provenance referenced by value from
        // immutable passports, so it is never removed — only marked retired and
        // stripped of its default flag. A DB DELETE would fail anyway (grant
        // revoked in 0013); this UPDATE is the sole retirement path.
        let row = sqlx::query(
            "UPDATE odal.facility \
             SET retired_at = now(), is_default = false, updated_at = now() \
             WHERE operator_id = $1 AND id = $2 AND retired_at IS NULL \
             RETURNING id, name, identifier_scheme, identifier_value, country, address, \
                       is_default, created_at",
        )
        .bind(operator_id)
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(Self::facility_from_row))
    }

    // ── Operator identifiers ─────────────────────────────────────────────────

    async fn list_operator_identifiers(
        &self,
        operator_id: &str,
    ) -> Result<Vec<OperatorIdentifier>, DppError> {
        let rows = sqlx::query(
            "SELECT id, scheme, value, label, is_primary, created_at \
             FROM odal.operator_identifier WHERE operator_id = $1 AND retired_at IS NULL \
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
        // Flip the chosen live row to primary and all other live rows off; retired
        // rows are excluded so a retired identifier can never carry the primary flag.
        let res = sqlx::query(
            "UPDATE odal.operator_identifier SET is_primary = (id = $2) \
             WHERE operator_id = $1 AND retired_at IS NULL",
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
            "SELECT 1 FROM odal.operator_identifier \
             WHERE operator_id = $1 AND id = $2 AND retired_at IS NULL",
        )
        .bind(operator_id)
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(exists.is_some())
    }

    async fn retire_operator_identifier(
        &self,
        operator_id: &str,
        id: Uuid,
    ) -> Result<Option<OperatorIdentifier>, DppError> {
        // Soft-delete: the value is stamped by value onto immutable passports
        // (Art. 13), so the row is preserved as provenance — only marked retired
        // and stripped of its primary flag. A DB DELETE would fail anyway (grant
        // revoked in 0014); this UPDATE is the sole retirement path.
        let row = sqlx::query(
            "UPDATE odal.operator_identifier SET retired_at = now(), is_primary = false \
             WHERE operator_id = $1 AND id = $2 AND retired_at IS NULL \
             RETURNING id, scheme, value, label, is_primary, created_at",
        )
        .bind(operator_id)
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(Self::operator_id_from_row))
    }

    // ── Registry-identity audit (append-only) ────────────────────────────────

    async fn append_audit(&self, entry: RegistryIdentityAudit) -> Result<(), DppError> {
        sqlx::query(
            "INSERT INTO odal.registry_identity_audit \
               (id, operator_id, entity_type, entity_id, action, actor, snapshot, ts) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(entry.id)
        .bind(&entry.operator_id)
        .bind(&entry.entity_type)
        .bind(entry.entity_id)
        .bind(&entry.action)
        .bind(&entry.actor)
        .bind(&entry.snapshot)
        .bind(entry.ts)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn list_registry_audit(
        &self,
        entity_type: &str,
        entity_id: Uuid,
    ) -> Result<Vec<RegistryIdentityAudit>, DppError> {
        let rows = sqlx::query(
            "SELECT id, operator_id, entity_type, entity_id, action, actor, snapshot, ts \
             FROM odal.registry_identity_audit \
             WHERE entity_type = $1 AND entity_id = $2 \
             ORDER BY ts ASC",
        )
        .bind(entity_type)
        .bind(entity_id)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::registry_audit_from_row).collect())
    }
}
