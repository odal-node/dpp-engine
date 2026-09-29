//! `PassportRepository` on PostgreSQL — document-style.
//!
//! Single-tenant: one operator per node, no operator-isolation boundary and no
//! `operator_id` column on the passport.
//!
//! Design notes:
//! - `patch_fields` is a row-locked read-merge-write inside one transaction —
//!   real concurrent-write safety (no string-built SQL, no lowercasing quirks).

use async_trait::async_trait;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use dpp_domain::{
    ProductGroupData,
    catalog::ProductGroupCatalog,
    error::DppError,
    identifier::ProductIdentifier,
    passport::{CarrierQualifier, Passport, PassportId},
    ports::passport_repo::PassportRepository,
    product::ProductIdentity,
    schemas::lens::LensRegistry,
    status::PassportStatus,
};

use super::{PgDal, db_err};

/// A passport's product identifier as one string — the SQL twin of
/// `ProductIdentifier::as_str`.
///
/// Whichever of the three EN 18219 value keys is present, and the pre-identifier
/// `productGroupData.gtin` of a document stored before the identifier existed:
/// a signed record is never rewritten, so SQL has to read both shapes where Rust
/// reads the old one through the lens chain. No scheme is needed beside it — a
/// GTIN is digits, a link an absolute `http(s)` URL, a DID starts `did:`.
///
/// 🚨 Verbatim the expression `0042_passport_identifier_index.sql` indexes.
/// Postgres uses an expression index only for a query that repeats it, so a
/// query that paraphrases this falls back to a sequential scan, silently.
/// `the_identifier_expression_is_the_one_the_index_covers` holds the two equal.
///
/// A macro rather than a `const` because sqlx takes only a literal statement,
/// and `concat!` splices a macro into one where it cannot splice a `const` —
/// the same arrangement as `repo_unsold_goods`'s column list.
macro_rules! identifier_sql {
    () => {
        "(COALESCE(doc->'productGroupData'->'productIdentifier'->>'gtin', \
         doc->'productGroupData'->'productIdentifier'->>'url', \
         doc->'productGroupData'->'productIdentifier'->>'did', \
         doc->'productGroupData'->>'gtin'))"
    };
}

/// A passport's effective carrier serial — the SQL twin of
/// `Passport::effective_carrier_serial`: the attributed `carrierSerial`, or else
/// `PassportId::default_carrier_serial`, the last twenty hex digits of the id's
/// lowercase canonical text. Verbatim what `idx_passport_carrier_serial`
/// indexes, for the same reason as [`identifier_sql`].
macro_rules! carrier_serial_sql {
    () => {
        "(COALESCE(doc->>'carrierSerial', right(replace(id::text, '-', ''), 20)))"
    };
}

/// Whether `passport`'s product group data carries `identifier` — the port's
/// own test, applied to the rows the SQL narrowed to.
fn carries(passport: &Passport, identifier: &ProductIdentifier) -> bool {
    passport
        .product_group_data
        .as_ref()
        .and_then(ProductGroupData::product_identifier)
        .is_some_and(|id| id == identifier)
}

/// Apply a passport update (scalar columns + `doc`) inside a caller-supplied
/// transaction. Shared by [`PgPassportRepo::update`] and the transactional
/// outbox's `commit_publish`, so the publish-write and the outbox insert commit
/// atomically without duplicating this SQL. Errors `NotFound` if no row matched.
///
/// # Why `doc || $2` rather than `doc = $2`
///
/// Writing the serialised struct over the whole column erases every stored key
/// the struct does not model. That is not a stale value in memory — it is gone
/// from the database. `update_status` is a read-modify-write (`find_by_id`,
/// mutate, `update`), and publish takes the same path, so the erasure happens on
/// the one write that matters most: the retention guard tests
/// `OLD.retention_locked`, which is still false while the row is a draft, so the
/// guard does not fire, the lossy write lands, and `retention_locked` becomes
/// true in that same statement. Every later write is guarded, so it can never be
/// repaired in place.
///
/// `||` is a shallow merge at the top level: the struct wins on every key it
/// models, and keys it does not model survive. That is exactly the
/// envelope/`productGroupData` split — `productGroupData` is fully modelled and versioned
/// through the lens chain, so replacing it wholesale is correct; the envelope is
/// the axis with no such mechanism.
///
/// **Constraint this carries:** the `Passport` fields are
/// `skip_serializing_if = "Option::is_none"`, so a field going `Some` -> `None`
/// is absent from `$2` and will no longer clear the stored key. No production
/// path does that today (checked: every envelope-field assignment to `None` is
/// inside a test). A field that genuinely needs clearing must write an explicit
/// JSON `null` rather than rely on omission.
pub(crate) async fn update_passport_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    passport: &Passport,
) -> Result<(), DppError> {
    let doc = serde_json::to_value(passport)
        .map_err(|e| DppError::Internal(format!("serialize: {e}")))?;
    let res = sqlx::query(
        // The scalar columns re-projected from `$2`, each `COALESCE`d onto its
        // stored value for the reason the doc comment above gives: an omitted
        // key is absent, not null, so a column must keep what it has rather
        // than be cleared by a partial document.
        //
        // `retention_until` is the one that matters most here — it is sealed at
        // publish, so it is never present at create and would stay NULL forever
        // if only the insert wrote it. `assessed_at` and `ruleset_version`
        // change whenever the compliance determination is re-run.
        r#"UPDATE odal.passport SET
             product_group           = $2->>'productGroup',
             status           = COALESCE($2->>'status', status),
             retention_locked = COALESCE(($2->>'retentionLocked')::boolean, retention_locked),
             schema_version   = COALESCE($2->>'schemaVersion', schema_version),
             granularity      = COALESCE($2->>'granularity', granularity),
             retention_until  = COALESCE(NULLIF($2->>'retentionUntil','')::timestamptz, retention_until),
             product_id       = COALESCE(NULLIF($2->>'productId','')::uuid, product_id),
             assessed_at      = COALESCE(NULLIF($2->'complianceResult'->>'assessedAt','')::timestamptz, assessed_at),
             ruleset_version  = COALESCE($2->'complianceResult'->>'rulesetVersion', ruleset_version),
             published_at     = COALESCE(NULLIF($2->>'publishedAt','')::timestamptz, published_at),
             doc              = doc || $2
           WHERE id = $1"#,
    )
    .bind(passport.id.0)
    .bind(&doc)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    if res.rows_affected() == 0 {
        return Err(DppError::NotFound("record not found after update".into()));
    }
    Ok(())
}

/// PostgreSQL implementation of [`PassportRepository`].
///
/// Each method serialises to/from the `doc JSONB` column. Scalar columns
/// (`product_group`, `status`, `retention_locked`, …) are extracted from the JSON
/// and stored redundantly as real columns to support indexed queries.
pub struct PgPassportRepo {
    dal: PgDal,
    lenses: LensRegistry,
    catalog: ProductGroupCatalog,
}

impl PgPassportRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self {
            dal,
            lenses: LensRegistry::new(),
            catalog: ProductGroupCatalog::new(),
        }
    }

    fn to_doc(passport: &Passport) -> Result<serde_json::Value, DppError> {
        serde_json::to_value(passport).map_err(|e| DppError::Internal(format!("serialize: {e}")))
    }

    /// Deserialize a stored document, upcasting `productGroupData` through the
    /// registered lens chain first if it predates the product group's current
    /// schema version — see `Passport::from_stored` in dpp-domain. Every
    /// passport read goes through this, not raw `serde_json::from_value`, so
    /// a non-additive dpp-domain change to a persisted product group-data shape
    /// fails a specific document instead of every one at once.
    fn read_doc(&self, doc: serde_json::Value) -> Result<Passport, DppError> {
        Passport::from_stored(doc, &self.lenses, &self.catalog)
    }

    /// [`read_doc`](Self::read_doc) over every row's `doc`.
    fn read_docs(&self, rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<Passport>, DppError> {
        rows.into_iter()
            .map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .collect()
    }

    fn uuid_of(id: PassportId) -> Uuid {
        id.0
    }
}

#[async_trait]
impl PassportRepository for PgPassportRepo {
    /// Persist a new passport; scalar columns are populated from the JSON doc.
    async fn create(&self, passport: Passport) -> Result<Passport, DppError> {
        let doc = Self::to_doc(&passport)?;
        let mut tx = self.dal.begin().await?;
        sqlx::query(
            // Every scalar column here is a **projection of `doc`**, never a
            // second source of truth: the document is authoritative and these
            // exist so a value can be filtered, indexed or reported on without
            // reaching into JSONB. `passport_column_coverage.rs` fails the build
            // if a column on this table is left out of both this statement and
            // the update, which is how ten of them came to sit permanently NULL
            // while reading as authoritative.
            //
            // `version` and `supersedes_id` carry the version chain —
            // `idx_passport_supersedes` indexes the second, and "is this record
            // still the head" is a predicate, not a document read.
            //
            // `assessed_at` and `ruleset_version` live one level down, inside
            // `complianceResult`, because that is where the determination that
            // produced them lives. A missing `complianceResult` yields SQL NULL
            // through both arrows rather than an error.
            r#"INSERT INTO odal.passport
                 (id, product_group, status, retention_locked, schema_version,
                  version, supersedes_id,
                  granularity, retention_until, product_id,
                  assessed_at, ruleset_version,
                  created_at, updated_at, published_at, doc)
               VALUES ($1,
                       $2->>'productGroup',
                       COALESCE($2->>'status','draft'),
                       COALESCE(($2->>'retentionLocked')::boolean, false),
                       COALESCE($2->>'schemaVersion','1.0.0'),
                       COALESCE(($2->>'version')::integer, 1),
                       NULLIF($2->>'supersedesId','')::uuid,
                       $2->>'granularity',
                       NULLIF($2->>'retentionUntil','')::timestamptz,
                       NULLIF($2->>'productId','')::uuid,
                       NULLIF($2->'complianceResult'->>'assessedAt','')::timestamptz,
                       $2->'complianceResult'->>'rulesetVersion',
                       now(), now(),
                       NULLIF($2->>'publishedAt','')::timestamptz,
                       $2)"#,
        )
        .bind(Self::uuid_of(passport.id))
        .bind(&doc)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(passport)
    }

    /// Fetch by id regardless of status — for authenticated internal reads.
    async fn find_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        let mut tx = self.dal.begin().await?;
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1")
            .bind(Self::uuid_of(id))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Fetch only `active` (published) passports — public resolver path.
    async fn find_published_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        // Public resolver path: only active (published) passports are served.
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1 AND status = 'active'")
            .bind(Self::uuid_of(id))
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)?;
        row.map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Every passport carrying `identifier`, at the level `batch_id` and
    /// `serial_number` name — the port's contract, answered from
    /// `idx_passport_identifier` rather than the default `list()` scan.
    ///
    /// The SQL narrows to candidates; the port's own rule then decides. So the
    /// answer is the default implementation's exactly, including for a stored
    /// identifier the SQL expression reads but the typed payload refuses — an
    /// untyped group whose `productIdentifier` does not parse carries none.
    async fn find_by_identifier(
        &self,
        identifier: &ProductIdentifier,
        batch_id: Option<&str>,
        serial_number: Option<&str>,
    ) -> Result<Vec<Passport>, DppError> {
        let rows = sqlx::query(concat!(
            "SELECT doc FROM odal.passport WHERE ",
            identifier_sql!(),
            " = $1 \
               AND CASE WHEN $3::text IS NOT NULL THEN doc->>'serialNumber' = $3 \
                        ELSE doc->>'batchId' IS NOT DISTINCT FROM $2 \
                         AND doc->>'serialNumber' IS NULL END \
             ORDER BY created_at"
        ))
        .bind(identifier.as_str())
        .bind(batch_id)
        .bind(serial_number)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(self
            .read_docs(rows)?
            .into_iter()
            .filter(|p| {
                carries(p, identifier)
                    && match serial_number {
                        Some(serial) => p.serial_number.as_deref() == Some(serial),
                        None => p.batch_id.as_deref() == batch_id && p.serial_number.is_none(),
                    }
            })
            .collect())
    }

    /// Every passport a printed carrier names — the port's contract, answered
    /// from `idx_passport_carrier_serial` for a serial and from the identifier
    /// index otherwise.
    ///
    /// Filtered afterwards by the port's own rule, for the reason
    /// [`find_by_identifier`](Self::find_by_identifier) gives.
    async fn find_by_carrier(
        &self,
        identifier: &ProductIdentifier,
        qualifier: &CarrierQualifier<'_>,
    ) -> Result<Vec<Passport>, DppError> {
        let rows = match qualifier {
            CarrierQualifier::Serial(serial) => {
                sqlx::query(concat!(
                    "SELECT doc FROM odal.passport WHERE ",
                    identifier_sql!(),
                    " = $1 AND ",
                    carrier_serial_sql!(),
                    " = $2 ORDER BY created_at"
                ))
                .bind(identifier.as_str())
                .bind(serial.as_ref())
                .fetch_all(self.dal.pool())
                .await
            }
            CarrierQualifier::Batch(batch) => {
                sqlx::query(concat!(
                    "SELECT doc FROM odal.passport WHERE ",
                    identifier_sql!(),
                    " = $1 AND doc->>'granularity' = 'batch' AND doc->>'batchId' = $2 \
                     ORDER BY created_at"
                ))
                .bind(identifier.as_str())
                .bind(batch.as_ref())
                .fetch_all(self.dal.pool())
                .await
            }
            CarrierQualifier::Model => {
                sqlx::query(concat!(
                    "SELECT doc FROM odal.passport WHERE ",
                    identifier_sql!(),
                    " = $1 AND doc->>'granularity' = 'model' ORDER BY created_at"
                ))
                .bind(identifier.as_str())
                .fetch_all(self.dal.pool())
                .await
            }
            // A level added to core after this build: every record carrying the
            // identifier, left to the port's own rule below to decide.
            _ => {
                sqlx::query(concat!(
                    "SELECT doc FROM odal.passport WHERE ",
                    identifier_sql!(),
                    " = $1 ORDER BY created_at"
                ))
                .bind(identifier.as_str())
                .fetch_all(self.dal.pool())
                .await
            }
        }
        .map_err(db_err)?;
        Ok(self
            .read_docs(rows)?
            .into_iter()
            .filter(|p| {
                carries(p, identifier)
                    && match qualifier {
                        CarrierQualifier::Serial(serial) => p.effective_carrier_serial() == *serial,
                        level => p.carrier_qualifier().as_ref() == Some(level),
                    }
            })
            .collect())
    }

    /// Find a passport by exact compound identity (product group, identifier,
    /// batch, serial), across `Draft` and `Published` — backs the import
    /// delta-matcher. Indexed by `0042_passport_identifier_index.sql`.
    ///
    /// `UnsoldGoods` carries no identifier, so a row for it never matches here:
    /// a discard-event report identifies no single product, not a query bug.
    async fn find_by_identity(
        &self,
        identity: &ProductIdentity,
    ) -> Result<Option<Passport>, DppError> {
        let product_group_str = serde_json::to_value(&identity.product_group)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| DppError::Internal("failed to serialise product_group".into()))?;
        let rows = sqlx::query(concat!(
            "SELECT doc FROM odal.passport \
             WHERE status IN ('draft','active') \
               AND product_group = $1 \
               AND ",
            identifier_sql!(),
            " = $2 \
               AND doc->>'batchId' IS NOT DISTINCT FROM $3 \
               AND doc->>'serialNumber' IS NOT DISTINCT FROM $4 \
             ORDER BY created_at"
        ))
        .bind(&product_group_str)
        .bind(&identity.identifier)
        .bind(identity.batch_id.as_deref())
        .bind(identity.serial_number.as_deref())
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(self
            .read_docs(rows)?
            .into_iter()
            .find(|p| ProductIdentity::from_passport(p).as_ref() == Some(identity)))
    }

    /// The record that supersedes `id`, from the indexed `supersedes_id` column
    /// rather than the port's default `list()` scan.
    ///
    /// Two rows are fetched so a second claimant is seen: more than one record
    /// naming `id` as its predecessor is refused, as the port requires, rather
    /// than one being picked.
    async fn find_superseding(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        let rows = sqlx::query("SELECT doc FROM odal.passport WHERE supersedes_id = $1 LIMIT 2")
            .bind(Self::uuid_of(id))
            .fetch_all(self.dal.pool())
            .await
            .map_err(db_err)?;
        let mut claimants = self.read_docs(rows)?;
        match claimants.len() {
            0 | 1 => Ok(claimants.pop()),
            _ => Err(DppError::SuccessionUnresolvable {
                id: id.to_string(),
                reason: "more than one record claims it as their predecessor".into(),
            }),
        }
    }

    /// Fetch by id without a status filter; equivalent to `find_by_id`.
    async fn find_by_id_any_status(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        let mut tx = self.dal.begin().await?;
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1")
            .bind(Self::uuid_of(id))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Replace the stored doc; errors if no row with the given id exists.
    async fn update(&self, passport: Passport) -> Result<Passport, DppError> {
        let mut tx = self.dal.begin().await?;
        update_passport_in_tx(&mut tx, &passport).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(passport)
    }

    /// Merge a partial JSON delta into the stored doc under a row-level lock.
    ///
    /// Concurrent callers serialise on `FOR UPDATE` — no last-write-wins
    /// clobbering. Null values in `delta` remove the corresponding key.
    async fn patch_fields(
        &self,
        id: PassportId,
        delta: serde_json::Value,
    ) -> Result<Passport, DppError> {
        // Reject protected/state-machine fields up front: they are set only via
        // the publish pipeline / update_status and back scalar columns this path
        // does not rewrite, so patching them would bypass the state machine and
        // desync the doc from its enforcing column. The rule itself lives in
        // `crate::protected_fields` so the in-memory backend answers with it too.
        crate::protected_fields::refuse_protected(&delta)?;

        let mut tx = self.dal.begin().await?;
        // Row lock makes concurrent patches serialise instead of clobbering.
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1 FOR UPDATE")
            .bind(Self::uuid_of(id))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let Some(row) = row else {
            return Err(DppError::NotFound(id.to_string()));
        };
        let mut doc: serde_json::Value = row.get("doc");
        if let (serde_json::Value::Object(dm), serde_json::Value::Object(pm)) = (&delta, &mut doc) {
            for (k, v) in dm {
                if v.is_null() {
                    pm.remove(k);
                } else {
                    pm.insert(k.clone(), v.clone());
                }
            }
        }
        let passport = self.read_doc(doc.clone())?;
        // Doc-only write: the scalar columns are all protected fields (rejected
        // above), so they can never drift from the doc via this path.
        sqlx::query("UPDATE odal.passport SET doc = $2 WHERE id = $1")
            .bind(Self::uuid_of(id))
            .bind(&doc)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(passport)
    }

    /// Convenience wrapper: load, set status and `updated_at`, then call `update`.
    async fn update_status(
        &self,
        id: PassportId,
        status: PassportStatus,
    ) -> Result<Passport, DppError> {
        let Some(mut passport) = self.find_by_id(id).await? else {
            return Err(DppError::NotFound(id.to_string()));
        };
        passport.status = status;
        passport.updated_at = chrono::Utc::now();
        self.update(passport).await
    }

    /// List passports with optional status filter, full-text ILIKE search, and
    /// exact `facilityId` match (facility is a grouping/filter dimension,
    /// never an isolation boundary).
    async fn list(
        &self,
        status: Option<PassportStatus>,
        q: Option<&str>,
        facility_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        let needle = q.map(str::trim).filter(|s| !s.is_empty());
        let mut tx = self.dal.begin().await?;
        let rows = sqlx::query(
            r#"SELECT doc FROM odal.passport
               WHERE ($1::text IS NULL OR status = $1)
                 AND ($2::text IS NULL
                      OR doc->>'productName'           ILIKE '%' || $2 || '%'
                      OR doc->>'batchId'               ILIKE '%' || $2 || '%'
                      OR doc->'manufacturer'->>'name'  ILIKE '%' || $2 || '%')
                 AND ($3::text IS NULL OR doc->'facility'->>'value' = $3)
               ORDER BY created_at DESC
               LIMIT $4 OFFSET $5"#,
        )
        .bind(status.map(|s| s.to_string()))
        .bind(needle)
        .bind(facility_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        rows.into_iter()
            .map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .collect()
    }

    /// Count passports with optional status and `facilityId` filters (the
    /// latter giving per-facility counts without a new endpoint).
    async fn count(
        &self,
        status: Option<PassportStatus>,
        facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        let mut tx = self.dal.begin().await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM odal.passport
               WHERE ($1::text IS NULL OR status = $1)
                 AND ($2::text IS NULL OR doc->'facility'->>'value' = $2)"#,
        )
        .bind(status.map(|s| s.to_string()))
        .bind(facility_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(total.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    /// Whitespace-insensitive, since Postgres compares parsed expressions and
    /// the migration is laid out for reading.
    fn squash(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The expressions the queries use are the ones the indexes cover.
    ///
    /// Postgres uses an expression index only for a query that repeats the
    /// expression. A query that paraphrases it — reorders the `COALESCE`, adds
    /// a cast — still returns the right rows, through a sequential scan, and
    /// nothing reports the difference until the table is large.
    #[test]
    fn the_identifier_expression_is_the_one_the_index_covers() {
        let migration = squash(include_str!(
            "../../../../ops/pg/0042_passport_identifier_index.sql"
        ));
        for (name, expr) in [
            ("identifier", identifier_sql!()),
            ("carrier serial", carrier_serial_sql!()),
        ] {
            // The index wraps the expression in one more pair of parentheses,
            // which is how `CREATE INDEX` takes an expression.
            let indexed = format!("({})", squash(expr));
            assert!(
                migration.contains(&indexed),
                "the {name} expression the queries use is not the one 0042 indexes:\n{indexed}"
            );
        }
    }
}
