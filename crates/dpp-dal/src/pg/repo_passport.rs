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
    catalog::ProductGroupCatalog,
    error::DppError,
    passport::{Passport, PassportId},
    ports::passport_repo::PassportRepository,
    product::ProductIdentity,
    schemas::lens::LensRegistry,
    status::PassportStatus,
};

use super::{PgDal, db_err};

/// Fields `patch_fields` refuses to modify: passport identity, lifecycle state,
/// retention lock, signatures, seal, registry identity, and upward lineage. Each
/// is governed by the publish pipeline / `update_status` / a dedicated transition
/// method, and several back a scalar column that this JSONB-merge path does not
/// rewrite — allowing them here would both bypass the state machine and desync
/// the doc from its enforcing column (e.g. flipping `retentionLocked` in the doc
/// while the `retention_locked` column stays `false`). Serialized (camelCase)
/// names.
///
/// # Derived from core, never restated
///
/// This backend overrides `patch_fields`, so it does not inherit core's default
/// guard — but it still owes callers that guard's contract. It therefore reads
/// `dpp_domain::PROTECTED_PATCH_FIELDS` and applies exactly the two divergences
/// declared below, rather than keeping a second list.
///
/// It used to keep one, and that list fell **three entries short** of core's:
/// `operatorIdentifier`, `facility` and `parentPassportRef` were protected by
/// core and not here, which on PostgreSQL — the only backend that ships — made
/// them writable through `PUT /dpp/{id}` and carried them into the signed
/// publish payload. A second list is a second thing to keep right, and nothing
/// was keeping it right: the one test covering this path asserted two keys, both
/// of which were in both lists the whole time.
///
/// The two divergences, and why each is deliberate:
///
/// - **`product_group` is added here.** It backs a real scalar column that this JSONB
///   merge does not rewrite, so patching it in the doc would desync the two.
///   Core has no column to protect.
/// - **`componentRefs` is removed here.** Core protects the lineage edges
///   because patching them on a *published* passport would leave the served body
///   no longer verifying against its own signature. This path accepts drafts
///   only (`update` refuses any non-`Draft` status), and a draft has no
///   signature to break — a bill of materials is editable while it is still
///   being assembled, which is the point of a draft. Its *upward* sibling
///   `parentPassportRef` stays protected, because nothing applies it: it is
///   stamped at create and read at verify.
///
/// `protected_patch_derivation_tests` holds both halves honest — the guard must
/// equal core's value plus/minus these entries, and an entry that no longer
/// diverges from core must be deleted rather than left as a stale exception.
const ADDED_HERE: [&str; 1] = ["productGroup"];
const REMOVED_HERE: [&str; 1] = ["componentRefs"];

fn is_protected_patch_field(key: &str) -> bool {
    if REMOVED_HERE.contains(&key) {
        return false;
    }
    ADDED_HERE.contains(&key) || dpp_domain::PROTECTED_PATCH_FIELDS.contains(&key)
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
        r#"UPDATE odal.passport SET
             product_group           = $2->>'product_group',
             status           = COALESCE($2->>'status', status),
             retention_locked = COALESCE(($2->>'retentionLocked')::boolean, retention_locked),
             schema_version   = COALESCE($2->>'schemaVersion', schema_version),
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
            r#"INSERT INTO odal.passport
                 (id, product_group, status, retention_locked, schema_version,
                  created_at, updated_at, published_at, doc)
               VALUES ($1,
                       $2->>'product_group',
                       COALESCE($2->>'status','draft'),
                       COALESCE(($2->>'retentionLocked')::boolean, false),
                       COALESCE($2->>'schemaVersion','1.0.0'),
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

    /// Find an active passport by GTIN via LIKE scan on `qrCodeUrl`.
    ///
    /// O(n) over active passports — acceptable for single-tenant MVP scale.
    async fn find_published_by_gtin(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        // A GTIN is purely numeric. Reject anything else so LIKE metacharacters
        // (`%`/`_`) in an untrusted value can't widen the pattern to match — and
        // return — an arbitrary passport. A non-numeric value can never match a
        // real GS1 Digital Link URL anyway.
        if gtin.is_empty() || !gtin.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        // Battery GS1 DL URL: https://id.odal-node.io/01/{gtin}/21/{serialId}
        let row = sqlx::query(
            "SELECT doc FROM odal.passport \
             WHERE status = 'active' \
               AND doc->>'qrCodeUrl' LIKE '%/01/' || $1 || '/%' \
             LIMIT 1",
        )
        .bind(gtin)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Find a passport by the GTIN in its `qrCodeUrl`, regardless of status.
    ///
    /// The by-GTIN counterpart of `find_by_id_any_status`, and it exists for the
    /// same reason: a public route must be able to tell "no such GTIN" from
    /// "that GTIN resolves to a suspended passport", because only the second is
    /// a recall and only the second warrants `410 Gone`. Returning the passport
    /// and leaving the lifecycle decision to the caller is what makes that
    /// possible — storage says what is stored, not what is publicly visible.
    ///
    /// Same numeric-only guard as `find_published_by_gtin`: a `%` or `_` in an
    /// untrusted value would otherwise widen the LIKE pattern and match an
    /// arbitrary passport.
    async fn find_by_gtin_any_status(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        if gtin.is_empty() || !gtin.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT doc FROM odal.passport \
             WHERE doc->>'qrCodeUrl' LIKE '%/01/' || $1 || '/%' \
             LIMIT 1",
        )
        .bind(gtin)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Find a passport by exact compound identity (product group, GTIN, batch),
    /// across `Draft` and `Published` — backs the import delta-matcher.
    /// Indexed by `0019_passport_identity_index.sql`. GTIN is read from
    /// `doc->'productGroupData'->>'gtin'`: present for every product group except
    /// `UnsoldGoods`/`Other`, which carry no GTIN field and so never match
    /// here — a discard-event report and an untyped catch-all, not a query bug.
    async fn find_by_identity(
        &self,
        identity: &ProductIdentity,
    ) -> Result<Option<Passport>, DppError> {
        let product_group_str = serde_json::to_value(&identity.product_group)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| DppError::Internal("failed to serialise product_group".into()))?;
        let row = sqlx::query(
            "SELECT doc FROM odal.passport \
             WHERE status IN ('draft','active') \
               AND product_group = $1 \
               AND doc->'productGroupData'->>'gtin' = $2 \
               AND doc->>'batchId' IS NOT DISTINCT FROM $3 \
             LIMIT 1",
        )
        .bind(&product_group_str)
        .bind(&identity.gtin)
        .bind(identity.batch_id.as_deref())
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| self.read_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
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
        // desync the doc from its enforcing column.
        if let Some(obj) = delta.as_object() {
            let mut forbidden: Vec<&str> = obj
                .keys()
                .map(String::as_str)
                .filter(|k| is_protected_patch_field(k))
                .collect();
            if !forbidden.is_empty() {
                forbidden.sort_unstable();
                return Err(DppError::Validation(
                    format!(
                        "patch_fields cannot modify protected field(s): {}",
                        forbidden.join(", ")
                    )
                    .into(),
                ));
            }
        }

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
mod protected_patch_derivation_tests {
    use super::{ADDED_HERE, REMOVED_HERE, is_protected_patch_field};

    /// The backend's guard must equal core's, plus/minus exactly the declared
    /// divergences — and it is checked against core's live value, not a copy.
    ///
    /// This is the test the hand-typed list never had. Its predecessor asserted
    /// two keys (`retentionLocked`, `status`), both of which were present in
    /// both lists the whole time, so the three entries that actually drifted
    /// were covered by nothing.
    #[test]
    fn guard_equals_core_plus_declared_divergences() {
        for key in dpp_domain::PROTECTED_PATCH_FIELDS {
            let expected = !REMOVED_HERE.contains(key);
            assert_eq!(
                is_protected_patch_field(key),
                expected,
                "core protects `{key}`; this backend must too unless it is in REMOVED_HERE"
            );
        }
        for key in ADDED_HERE {
            assert!(
                is_protected_patch_field(key),
                "`{key}` is declared as added here but is not protected"
            );
        }
    }

    /// A divergence that no longer diverges is a stale exception — it reads as a
    /// deliberate difference while being none, and hides the next real one.
    #[test]
    fn declared_divergences_are_real() {
        for key in ADDED_HERE {
            assert!(
                !dpp_domain::PROTECTED_PATCH_FIELDS.contains(&key),
                "`{key}` is in ADDED_HERE but core already protects it — drop the entry"
            );
        }
        for key in REMOVED_HERE {
            assert!(
                dpp_domain::PROTECTED_PATCH_FIELDS.contains(&key),
                "`{key}` is in REMOVED_HERE but core does not protect it — drop the entry"
            );
        }
    }
}
