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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use dpp_domain::{DppError, passport::PassportId, seal::SealedEnvelope};

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

// ─── Reading a stored seal ────────────────────────────────────────────────────

/// What a seal's certificate declares about the device holding its private key.
///
/// A **declaration**, never a verification. The certificate says where its key
/// lives; nothing confirms it, and nothing could from bytes alone — that
/// assurance comes from the issuing QTSP's conformity assessment. The name says
/// `Declares` for that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CreationDevice {
    /// The certificate carries the Annex III(j) indication.
    ///
    /// Regulation (EU) No 910/2014 Art. 32(1)(f), reached for seals through
    /// Art. 40, requires that the seal was created by a qualified electronic seal
    /// creation device, and Annex III(j) requires the certificate to say so in a
    /// form suitable for automated processing.
    DeclaresQualifiedDevice,
    /// It carries qualified-certificate statements, but not that one.
    ///
    /// Lawful, and enough for Art. 40a — validation of an *advanced* seal based
    /// on a qualified certificate, which omits the device leg — but not for the
    /// Art. 32/40 pair.
    NoQualifiedDevice,
    /// It carries no qualified-certificate statements at all.
    ///
    /// A different finding from [`Self::NoQualifiedDevice`]: this certificate is
    /// not presenting itself as a qualified certificate in the first place. A
    /// self-signed development certificate lands here.
    NotAQualifiedCertificate,
}

/// What a stored seal's own certificate says about who issued it.
///
/// **Read out of the seal, never from configuration.** A node knows which
/// backend it was *told* to use, which attests the operator's intent rather than
/// the bytes that came back — and a seal restored from a backup, or made before
/// a backend was changed, was not produced by the backend running now.
///
/// Nothing here is a qualification verdict. Establishing that a seal is
/// qualified needs the issuer matched against an EU Trusted List *and* the
/// issuer's signature over this certificate verified; neither is done to produce
/// this. What it does answer, completely and without a network, is whether
/// anybody issued the certificate at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealOrigin {
    /// The certificate's subject distinguished name, RFC 4514.
    pub subject: String,
    /// The certificate's issuer distinguished name, RFC 4514.
    pub issuer: String,
    /// Whether issuer and subject are the same name.
    ///
    /// The structural test for "nobody issued this to us", and the one an
    /// operator asks first. True means the seal attests that a key this node
    /// holds signed a digest, and **nothing else** — it carries no legal weight
    /// and no Trusted List will give it any.
    ///
    /// A property of the certificate, so no environment variable can change it.
    pub self_issued: bool,
    /// What the certificate declares about the creation device (Annex III(j)).
    pub creation_device: CreationDevice,
}

/// Whether a seal's own bytes say it covers a particular signature.
///
/// # Why this exists beside the outbox record
///
/// A node records the digest it *asked* a backend to seal, and that record is
/// genuinely useful: it survives a seal that will not parse, and it spots a
/// re-published passport with a string comparison and no AdES tooling. But it is
/// a statement about this node's own bookkeeping. A seal restored from a backup
/// has no such row; a seal stored against the wrong passport has a row that
/// agrees with itself and nothing else.
///
/// A detached CAdES says what it covers in exactly one place — the
/// `messageDigest` signed attribute, RFC 5652 §11.2 — and that attribute is
/// *inside* the signature. Reading it turns "this seal is for this passport"
/// from a claim resting on our records into a fact checkable against the seal.
///
/// The two answers can disagree, and **the disagreement is the finding**: it
/// means the records and the bytes describe different things, which no single
/// source could have told anyone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "result")]
pub enum SealBinding {
    /// The seal names this exact signature, and its attributes verify under the
    /// certificate it carries.
    ///
    /// The strongest statement this node can make without an external validator:
    /// whatever else is true of the seal's *trust*, it is demonstrably a seal
    /// over this passport's current signature and not over anything else.
    CoversThisSignature,
    /// The seal is intact and names a different digest.
    ///
    /// Ordinary after a re-publish — the passport re-signed, so its current
    /// signature is not the one sealed. It is also what a seal stored against the
    /// wrong passport looks like, and the two are indistinguishable from here;
    /// what distinguishes them is whether an outbox row exists saying this digest
    /// was ever requested for this passport.
    CoversAnotherDigest {
        /// The hex SHA-256 the seal actually covers.
        covered: String,
    },
    /// The signature over the seal's attributes does not verify.
    ///
    /// No digest is reported, deliberately: the attribute naming it is inside a
    /// signature that failed, so its contents are not evidence of anything. A
    /// caller shown a digest here would be shown a number that nothing vouches
    /// for.
    NotIntact,
    /// The bytes could not be read, or carry no digest at all.
    ///
    /// A placeholder seal, an unparsed format, or a signature with no signed
    /// attributes — a seal whose digest is not inside it and cannot be recovered
    /// from the envelope alone. **Never** to be read as a mismatch.
    Unknown,
}

/// Reads a stored seal's certificate.
///
/// # Why this is a port rather than a function
///
/// Parsing CMS and X.509 needs ASN.1 machinery that belongs with the seal
/// adapter, beside the code that produces seals in the first place — one home
/// for certificate handling, so two places cannot disagree about what a seal
/// says. The services that *serve* seals sit above that adapter and must not
/// link it: the crate carrying it also carries an HTTP client and an XML
/// signature verifier, which is a disproportionate dependency for reading a
/// distinguished name.
///
/// So the question is declared here, where every consumer already looks, and
/// answered by whichever adapter the composition root resolved — the same
/// arrangement [`SealOutbox`] uses, and for the same reason.
pub trait SealInspector: Send + Sync {
    /// What the envelope's certificate says, or `None` if it cannot be read.
    ///
    /// `None` for a placeholder envelope, for a format this adapter does not
    /// parse, and for bytes that will not decode. All three mean *not read* —
    /// **never** that the seal was self-issued, which is a finding and must come
    /// from a certificate that was actually examined.
    fn origin(&self, envelope: &SealedEnvelope) -> Option<SealOrigin>;

    /// Whether the envelope's own bytes say it covers `payload_hash`.
    ///
    /// `payload_hash` is the hex SHA-256 the caller wants to test against — for
    /// a passport, [`digest_for_jws`] of its current compact JWS.
    ///
    /// The implementation must check the seal's signature as well as reading the
    /// digest out of it. The attribute naming the digest sits inside that
    /// signature, so a comparison made without it is a comparison against a value
    /// anybody could have written.
    fn binding(&self, envelope: &SealedEnvelope, payload_hash: &str) -> SealBinding;
}
