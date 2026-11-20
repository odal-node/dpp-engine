//! `EvidenceDossierRepository` on PostgreSQL — append-only by trigger, not
//! convention (`ops/pg/0021`).

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::{DppError, passport::PassportId};
use dpp_types::evidence::{
    DossierV1, EvidenceDossierRecord, EvidenceDossierRepository, EvidenceDossierSummary,
};
use dpp_types::transfer::{ChainError, RefusedChain};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`EvidenceDossierRepository`].
///
/// The DB enforces append-only via a trigger; any UPDATE/DELETE raises
/// `ODAL_EVIDENCE` which `db_err` maps to `DppError::Internal`.
pub struct PgEvidenceDossierRepo {
    dal: PgDal,
}

impl PgEvidenceDossierRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl EvidenceDossierRepository for PgEvidenceDossierRepo {
    async fn insert(&self, record: &EvidenceDossierRecord) -> Result<(), DppError> {
        let doc = serde_json::to_value(&record.dossier)
            .map_err(|e| DppError::Internal(format!("serialize evidence dossier: {e}")))?;
        sqlx::query(
            r#"INSERT INTO odal.evidence_dossier
                 (id, passport_id, actor, doc_hash, doc, created_at)
               VALUES ($1,$2,$3,$4,$5,$6)"#,
        )
        .bind(record.id)
        .bind(record.passport_id.0)
        .bind(&record.actor)
        .bind(&record.doc_hash)
        .bind(&doc)
        .bind(record.created_at)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn list_by_passport(
        &self,
        passport_id: PassportId,
    ) -> Result<Vec<EvidenceDossierSummary>, DppError> {
        let rows = sqlx::query(
            r#"SELECT id, passport_id, actor, doc_hash, created_at
               FROM odal.evidence_dossier
               WHERE passport_id = $1
               ORDER BY created_at DESC, id DESC"#,
        )
        .bind(passport_id.0)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| EvidenceDossierSummary {
                id: r.get("id"),
                passport_id: PassportId(r.get("passport_id")),
                actor: r.get("actor"),
                created_at: r.get("created_at"),
                doc_hash: r.get("doc_hash"),
            })
            .collect())
    }

    async fn get(&self, id: uuid::Uuid) -> Result<Option<EvidenceDossierRecord>, ChainError> {
        let row = sqlx::query(
            r#"SELECT id, passport_id, actor, doc_hash, doc, created_at
               FROM odal.evidence_dossier
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| {
            let passport_id = PassportId(r.get("passport_id"));
            let doc: serde_json::Value = r.get("doc");
            let dossier = <DossierV1 as serde::Deserialize>::deserialize(&doc).map_err(|e| {
                // A dossier is read member by member and stops at the first
                // fault, so the chain is read on its own: a refused chain is
                // reported as one even when something else fails first.
                match RefusedChain::from_dossier_document(passport_id, &doc) {
                    Some(refused) => ChainError::Refused(refused),
                    None => ChainError::Other(DppError::Internal(format!(
                        "deserialize evidence dossier: {e}"
                    ))),
                }
            })?;
            Ok(EvidenceDossierRecord {
                id: r.get("id"),
                passport_id,
                actor: r.get("actor"),
                created_at: r.get("created_at"),
                doc_hash: r.get("doc_hash"),
                dossier,
            })
        })
        .transpose()
    }

    async fn get_document(&self, id: uuid::Uuid) -> Result<Option<serde_json::Value>, DppError> {
        sqlx::query_scalar("SELECT doc FROM odal.evidence_dossier WHERE id = $1")
            .bind(id)
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)
    }
}
