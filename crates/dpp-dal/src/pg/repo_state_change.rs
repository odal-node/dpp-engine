//! [`StateChangeLog`] on PostgreSQL: one transaction per state change.
//!
//! Every part of a [`StateChange`] is written by a helper the owning repository
//! also uses for its own writes, so there is one statement per table and this
//! file holds no SQL of its own. Passport writes stay in `repo_passport.rs`,
//! which keeps `passport_writers_are_known` meaningful.
//!
//! # The archive is written here, not by the decorator
//!
//! This is a second door onto `odal.passport` beside [`PassportRepository`],
//! so [`ArchivingPassportRepo`](super::ArchivingPassportRepo) does not see it.
//! It archives the same thing the decorator does, the stored passport as it
//! was before the change, re-serialised from its typed form, and it does so in
//! the transaction that makes the change. A write that creates a passport
//! archives nothing, as the decorator's `create` archives nothing.
//!
//! [`PassportRepository`]: dpp_domain::ports::passport_repo::PassportRepository

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Postgres, Transaction};

use dpp_domain::{DppError, passport::Passport, passport::PassportId};
use dpp_types::state_change::{PassportWrite, StateChange, StateChangeLog};

use super::repo_audit::append_in_tx;
use super::repo_passport::{PgPassportRepo, insert_passport_in_tx, update_passport_in_tx};
use super::repo_passport_version::insert_version;
use super::repo_registry_sync::{queue_registration_in_tx, record_status_intent};
use super::repo_registry_transfer::queue_transfer_notice;
use super::repo_transfer::upsert_chain;
use super::repo_webhook::fan_out;
use super::{PgDal, db_err};

/// PostgreSQL implementation of [`StateChangeLog`].
pub struct PgStateChangeLog {
    dal: PgDal,
    passports: PgPassportRepo,
}

impl PgStateChangeLog {
    /// Construct a log sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self {
            passports: PgPassportRepo::new(dal.clone()),
            dal,
        }
    }

    /// The stored passport, locked for the rest of `tx`, and archived as the
    /// version this change supersedes.
    async fn archive_current(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: PassportId,
    ) -> Result<Passport, DppError> {
        let current = self
            .passports
            .current_for_update_in_tx(tx, id)
            .await?
            .ok_or_else(|| DppError::NotFound(id.to_string()))?;
        let doc = serde_json::to_value(&current).map_err(|e| {
            DppError::Serialisation(format!("cannot archive the passport version: {e}"))
        })?;
        insert_version(&mut **tx, id.0, &doc, Utc::now()).await?;
        Ok(current)
    }

    async fn write_passport(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        write: PassportWrite,
    ) -> Result<Passport, DppError> {
        match write {
            PassportWrite::Insert(passport) => {
                insert_passport_in_tx(tx, &passport).await?;
                Ok(passport)
            }
            PassportWrite::Replace(passport) => {
                self.archive_current(tx, passport.id).await?;
                update_passport_in_tx(tx, &passport).await?;
                Ok(passport)
            }
            PassportWrite::Status(id, status) => {
                let mut passport = self.archive_current(tx, id).await?;
                passport.status = status;
                passport.updated_at = Utc::now();
                update_passport_in_tx(tx, &passport).await?;
                Ok(passport)
            }
            PassportWrite::Patch(id, delta) => {
                self.archive_current(tx, id).await?;
                self.passports.patch_in_tx(tx, id, delta).await
            }
        }
    }
}

#[async_trait]
impl StateChangeLog for PgStateChangeLog {
    async fn commit(&self, change: StateChange) -> Result<Option<Passport>, DppError> {
        let StateChange {
            passport,
            transfer_chain,
            registration,
            transfer_notice,
            registry_intent,
            audit,
            webhook,
        } = change;

        let mut tx = self.dal.begin().await?;

        let written = match passport {
            Some(write) => Some(self.write_passport(&mut tx, write).await?),
            None => None,
        };
        if let Some(chain) = &transfer_chain {
            upsert_chain(&mut *tx, chain).await?;
        }
        if let Some(payload) = &registration {
            let passport = written.as_ref().ok_or_else(|| {
                DppError::Internal(
                    "a registration is queued only with the passport it registers".into(),
                )
            })?;
            queue_registration_in_tx(&mut tx, passport.id, payload).await?;
        }
        if let Some((transfer_id, payload)) = &transfer_notice {
            let chain = transfer_chain.as_ref().ok_or_else(|| {
                DppError::Internal(
                    "a transfer notice is queued only with the chain that accepted it".into(),
                )
            })?;
            queue_transfer_notice(&mut *tx, *transfer_id, chain.passport_id, payload).await?;
        }
        if let Some(intent) = registry_intent {
            let passport = written.as_ref().ok_or_else(|| {
                DppError::Internal(
                    "a registry status is recorded only with the passport it describes".into(),
                )
            })?;
            record_status_intent(&mut *tx, passport.id, intent).await?;
        }
        append_in_tx(&mut tx, audit).await?;
        if let Some(event) = &webhook {
            fan_out(&mut *tx, &event.event_type, &event.body).await?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(written)
    }
}
