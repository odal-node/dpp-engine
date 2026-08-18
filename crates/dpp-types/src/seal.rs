//! Durable queue for eIDAS qualified sealing.
//!
//! # Why publish does not seal inline
//!
//! Sealing is a paid call to a third-party QTSP aggregator. Putting it in the
//! publish path would couple every publish to that provider's availability, so a
//! provider outage would stop an operator from publishing passports at all —
//! trading a *missing seal*, which is visible and repairable, for a *blocked
//! regulatory obligation*, which is neither. Publish therefore commits and
//! enqueues; the node's drain task seals with backoff.
//!
//! A published passport can consequently exist for a short window with
//! `seal: None`. That is honest and observable — absent, not faked — and it is
//! the same posture `RegistrySyncOutbox` already takes for EU registration.
//!
//! # Why this lives here (not in core's `dpp-domain::ports`)
//!
//! `SealPort` — what a seal *is* and who can produce one — is core. *When* a
//! given deployment gets around to calling it, and how it retries, is
//! operational, so the queue stays engine-side beside `RegistrySyncOutbox`,
//! `WebhookOutbox` and `SnapshotOutbox`.
//!
//! # What is queued
//!
//! The digest, not the payload. `payload_hash` is the SHA-256 of the passport's
//! `jwsSignature` compact string — see `dpp_vault`'s seal service for why that is
//! the sealed preimage. Storing it on the row rather than re-deriving it at drain
//! time is what makes the row mean one specific attestation: a re-publish
//! produces a different JWS, hence a different digest, hence a distinct row.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use dpp_domain::{DppError, domain::passport::PassportId, ports::seal::SealedEnvelope};

/// The digest a qualified seal is applied over: hex SHA-256 of a passport's
/// compact JWS.
///
/// **One definition, deliberately.** `dpp-vault` composes this at publish and the
/// DAL re-derives it in the repair sweep; two copies that agree today are two
/// copies that can disagree tomorrow, and a disagreement here buys a seal over a
/// digest nothing else recognises.
///
/// Why the JWS rather than the canonicalized document: the JWS is frozen at
/// publish, whereas `lintResult`, `status` and `qrCodeUrl` stay mutable after it,
/// so a document digest would drift out from under its own seal. It is also
/// reconstructible by anyone holding the passport, with no canonicalization step
/// to agree on.
#[must_use]
pub fn digest_for_jws(jws: &str) -> String {
    hex::encode(Sha256::digest(jws.as_bytes()))
}

/// One drainable sealing row.
#[derive(Debug, Clone)]
pub struct SealRow {
    /// Outbox row id.
    pub id: uuid::Uuid,
    /// The passport this seal will be written onto.
    pub passport_id: PassportId,
    /// Hex SHA-256 of the passport's `jwsSignature` — the digest to seal.
    pub payload_hash: String,
    /// Attempts made so far (pre-increment).
    pub attempts: i32,
}

/// Aggregate counts for boot logs and gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealOutboxCounts {
    /// Rows awaiting a sealing attempt.
    pub pending: i64,
    /// Rows whose seal is on the passport.
    pub sealed: i64,
    /// Rows that gave up — the passport is published and unsealed.
    pub exhausted: i64,
}

/// The sealing outbox — enqueued in the publish transaction, drained by the node.
#[async_trait]
pub trait SealOutbox: Send + Sync {
    /// Queue `payload_hash` to be sealed for `passport_id`.
    ///
    /// Idempotent on `(passport_id, payload_hash)`: enqueueing the same digest
    /// twice is one row, so a retried publish of unchanged content cannot buy two
    /// seals for the same attestation. A *different* digest — a re-publish, which
    /// re-signs and so produces a new JWS — is a new row, because it is a new
    /// statement that needs its own seal.
    ///
    /// One exception, which is the recovery path: an **`exhausted`** row is
    /// re-armed. It has no seal and nothing was delivered to pay for, so
    /// re-queueing it cannot double-bill — and without it, a passport that
    /// exhausted its retries during a provider outage would stay permanently
    /// unsealed, with no way back short of re-publishing and changing the very
    /// signature the seal is supposed to attest to. `sealed` and `pending` rows
    /// are left untouched.
    async fn enqueue(&self, passport_id: PassportId, payload_hash: &str) -> Result<(), DppError>;

    /// Repair sweep: queue seals for published passports that have none, capped
    /// at `limit`. Returns how many rows were queued or re-armed.
    ///
    /// This is what makes the guarantee end-to-end rather than "loss-proof once
    /// enqueued", and it closes two holes that nothing else can:
    ///
    /// - **The lost enqueue.** [`Self::enqueue`] runs after commit, so a crash in
    ///   that window leaves a published passport with no row at all. Nothing
    ///   would ever seal it.
    /// - **The exhausted row.** A passport that burned its retry budget during a
    ///   provider outage is published and unsealed, and the only other path back
    ///   is a re-publish — which changes the signature the seal attests to.
    ///
    /// Targeted, not exhaustive: it queries for passports whose *current*
    /// signature has no seal, so a converged deployment sweeps to zero work and
    /// buys nothing. Because a seal is only ever bought for a digest that has
    /// none, this cannot double-bill.
    ///
    /// `cooldown_secs` holds back rows that failed recently, so a provider that
    /// is simply down does not get hammered by sweep and drain together.
    async fn enqueue_unsealed(&self, limit: i64, cooldown_secs: i64) -> Result<u64, DppError>;

    /// Rows due for an attempt (`pending`, `next_attempt_at <= now`), oldest
    /// first, capped at `limit`.
    async fn due(&self, limit: i64) -> Result<Vec<SealRow>, DppError>;

    /// Terminal success: write `envelope` onto the passport and mark the row
    /// `sealed`, **in one transaction**.
    ///
    /// The atomicity is the point, and it is about money. If the seal write and
    /// the row update could commit separately, a crash in between would leave a
    /// `pending` row for a seal already produced and already billed — and the
    /// next drain pass would buy it again.
    async fn mark_sealed(&self, id: uuid::Uuid, envelope: &SealedEnvelope) -> Result<(), DppError>;

    /// The digest the passport's stored seal was requested over.
    ///
    /// [`SealedEnvelope`] carries no preimage, so without this a node cannot tell
    /// a current seal from one superseded by a later re-publish — it can only
    /// hand both values to an external validator and let that validator extract
    /// the signed message digest. But the row that bought the seal *does* carry
    /// the preimage, and rows are never deleted, so the answer is already held
    /// here and was only ever a query away.
    ///
    /// The latest `sealed` row is the one whose envelope is on the passport:
    /// [`Self::mark_sealed`] writes the envelope and closes the row in the same
    /// transaction, so the two cannot disagree about which seal is current.
    ///
    /// This is the node's own record, not proof — it says what was *asked* for,
    /// not what the CAdES actually covers. Only an independent validator
    /// establishes the latter, and it is the cross-check for this value rather
    /// than a substitute for it.
    ///
    /// `None` when this node holds no sealed row: a seal restored from a backup
    /// or produced elsewhere is one whose preimage this node cannot vouch for,
    /// and saying so beats guessing.
    async fn sealed_digest(&self, passport_id: PassportId) -> Result<Option<String>, DppError>;

    /// Transient failure: increment `attempts`, back `next_attempt_at` off
    /// exponentially, keep the row `pending`.
    async fn mark_attempt_failed(&self, id: uuid::Uuid, message: String) -> Result<(), DppError>;

    /// Terminal failure: mark `exhausted` and store the reason. The row stays for
    /// audit and is never deleted; a re-publish enqueues a fresh row for the new
    /// digest.
    async fn mark_exhausted(&self, id: uuid::Uuid, message: String) -> Result<(), DppError>;

    /// Counts by status, for boot logs and gauges.
    async fn status_counts(&self) -> Result<SealOutboxCounts, DppError>;

    /// How many **published passports carry no seal at all**, right now.
    ///
    /// Not derivable from [`Self::status_counts`], and this is the whole reason
    /// it exists. Those counts describe *rows*, and the failure that matters
    /// most leaves no row: [`Self::enqueue`] runs after commit, so a crash in
    /// that window publishes a passport that nothing will ever seal. An outbox
    /// reporting `pending: 0, exhausted: 0` is consistent with any number of
    /// unsealed passports, so a status view built on rows alone would show all
    /// clear while the obligation went unmet.
    ///
    /// Counts passports, not rows, and takes no `limit`: it answers "is anything
    /// unsealed", which a capped query cannot.
    ///
    /// Read-only. [`Self::enqueue_unsealed`] is the repair for the same
    /// condition and shares this predicate, but adds its own guards for rows the
    /// drain already owns — those belong to the repair, not to the question.
    async fn unsealed_published_count(&self) -> Result<i64, DppError>;
}
