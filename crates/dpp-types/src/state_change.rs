//! One state change, and everything that must not be lost with it.
//!
//! # Why one transaction
//!
//! A change to a passport used to be several writes in a row: the passport,
//! then its audit entry, then a webhook delivery per subscriber, each committed
//! on its own. The deliveries were enqueued after the commit, best effort, and
//! nothing swept for them, so a node killed between the passport write and the
//! enqueue had changed the passport and told no subscriber. The registry and
//! transfer outboxes had already closed the same gap for their own rows by
//! writing them in the passport's transaction; webhooks had not.
//!
//! [`StateChangeLog::commit`] writes the lot in one transaction: the archived
//! pre-change version, the passport, the transfer chain, the registry rows, the
//! audit entry and the webhook deliveries. Either all of them are there
//! afterwards or none is. Only the event bus publish stays after the commit: it
//! leaves the database, so it cannot be part of the transaction, and a bus
//! subscriber is not owed delivery the way a webhook subscriber is.
//!
//! # Archiving moves inside the transaction
//!
//! `ArchivingPassportRepo` archives the version a write replaces, but the
//! `PassportRepository` port has no transaction, so it archives first and
//! writes second, and a failure in between leaves a redundant version behind.
//! A [`PassportWrite`] that replaces a stored passport archives it in the same
//! transaction instead, so the version and the change commit together. EN 18221
//! clause 4.2 asks that every change be archived; this keeps that true on a path
//! that does not go through the decorator.

use async_trait::async_trait;
use uuid::Uuid;

use dpp_domain::{
    DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
    transfer::TransferChain,
};

use crate::audit::PassportAuditEntry;

/// The write a state change makes to the passport itself.
#[derive(Debug, Clone)]
pub enum PassportWrite {
    /// A new passport. Nothing is archived: archiving starts at the first change.
    Insert(Passport),
    /// The stored passport replaced by this one, as publish does.
    Replace(Passport),
    /// The stored passport's status set, and nothing else.
    Status(PassportId, PassportStatus),
    /// A partial update merged into the stored passport. A `null` removes the
    /// key. Protected fields are refused, as `PassportRepository::patch_fields`
    /// refuses them.
    Patch(PassportId, serde_json::Value),
}

/// An event every matching webhook subscription is sent.
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    /// The subject, matched against each subscription's filter.
    pub event_type: String,
    /// The exact bytes to POST and sign: the serialised event envelope.
    pub body: String,
}

/// One state change: everything written for it commits together.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// The passport write, if the change touches the passport row.
    pub passport: Option<PassportWrite>,
    /// The passport's transfer chain, written whole, if the change touches it.
    pub transfer_chain: Option<TransferChain>,
    /// The EU registry registration a publish owes: the serialised
    /// `RegistrationRequest`. Queued as `registry_sync` rows are by publish.
    pub registration: Option<serde_json::Value>,
    /// The EU registry notification an accepted transfer owes: the transfer id
    /// and the serialised record.
    pub transfer_notice: Option<(Uuid, serde_json::Value)>,
    /// The audit entry recording the change, chained onto the passport's trail.
    pub audit: PassportAuditEntry,
    /// The event webhook subscribers are sent.
    pub webhook: Option<WebhookEvent>,
}

impl StateChange {
    /// A change recorded by `audit`, writing nothing else until the builder
    /// methods add it.
    #[must_use]
    pub fn new(audit: PassportAuditEntry) -> Self {
        Self {
            passport: None,
            transfer_chain: None,
            registration: None,
            transfer_notice: None,
            audit,
            webhook: None,
        }
    }

    /// Write the passport as `write` says.
    #[must_use]
    pub fn with_passport(mut self, write: PassportWrite) -> Self {
        self.passport = Some(write);
        self
    }

    /// Write the passport's transfer chain.
    #[must_use]
    pub fn with_transfer_chain(mut self, chain: TransferChain) -> Self {
        self.transfer_chain = Some(chain);
        self
    }

    /// Queue the registry registration a publish owes.
    #[must_use]
    pub fn with_registration(mut self, payload: serde_json::Value) -> Self {
        self.registration = Some(payload);
        self
    }

    /// Queue the registry notification an accepted transfer owes.
    #[must_use]
    pub fn with_transfer_notice(mut self, transfer_id: Uuid, payload: serde_json::Value) -> Self {
        self.transfer_notice = Some((transfer_id, payload));
        self
    }

    /// Send `event` to every matching webhook subscription.
    #[must_use]
    pub fn with_webhook(mut self, event: WebhookEvent) -> Self {
        self.webhook = Some(event);
        self
    }
}

/// Commits a [`StateChange`] in one transaction.
#[async_trait]
pub trait StateChangeLog: Send + Sync {
    /// Write every part of `change` in one transaction, or none of it.
    ///
    /// Returns the passport as written when the change wrote one.
    ///
    /// # Errors
    /// [`DppError::NotFound`] when a write that replaces, patches or sets the
    /// status of a passport finds none; otherwise whatever the storage reports.
    /// Nothing is written in either case.
    async fn commit(&self, change: StateChange) -> Result<Option<Passport>, DppError>;
}
