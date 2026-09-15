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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use dpp_domain::{
    DppError, passport::PassportId, seal::SealConformanceLevel, seal::SealedEnvelope,
};

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

/// What a completed pass over every stored seal found.
///
/// Reported as a whole rather than as a running total, because the useful
/// quantity is "how many broken seals does this node hold" and that is only
/// answerable once the walk has been all the way round. A figure accumulated
/// mid-walk answers "how many in the part seen so far", which reads as a
/// smaller number than the truth and falls to zero every time the walk restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealAuditReport {
    /// When the pass finished.
    ///
    /// The age of this is the age of every number below it. A pass takes as long
    /// as the estate divided by the audit's throughput, so on a large deployment
    /// these are hours old by construction — which is fine for a condition that
    /// does not appear suddenly, and worth stating rather than implying
    /// freshness.
    pub completed_at: DateTime<Utc>,
    /// Seals opened.
    pub checked: u64,
    /// Seals covering their passport's current signature.
    ///
    /// EN 319 102-1 `INDETERMINATE`, not `TOTAL-PASSED` — see
    /// [`SealBinding::validation_status`]. Nothing about these seals has failed;
    /// their certificates have not been validated.
    pub sound: u64,
    /// Seals over a different digest — ordinarily a passport re-published after
    /// sealing, which is not a defect.
    ///
    /// `TOTAL-FAILED` / `HASH_FAILURE` when the question asked is about this
    /// passport's *current* signature, which is the question this walk asks.
    pub superseded: u64,
    /// Seals whose own signature does not verify.
    ///
    /// `TOTAL-FAILED` / `SIG_CRYPTO_FAILURE`, and the standard makes that
    /// verdict stable: no additional validation data can lift it. That is what
    /// makes a replacement worth buying for these and for nothing else here.
    pub broken: u64,
    /// Seals whose signature is sound and whose **certificate** was not, at the
    /// moment they were made.
    ///
    /// `TOTAL-FAILED` with a certificate sub-indication — revoked before
    /// sealing, or outside its validity window, with an attested time to prove
    /// the order. Where nothing attests the moment, the finding is indeterminate
    /// and the seal stays in [`Self::sound`]: a certificate that has expired
    /// since is the ordinary state of an old seal, not a defect in it.
    ///
    /// Apart from `broken` because the two need opposite actions: a broken seal
    /// is worth replacing, and one made under a revoked certificate would only
    /// be replaced by another from the same certificate.
    pub certificate_failed: u64,
    /// Seals this node could not read. Not a finding.
    ///
    /// `INDETERMINATE` with a custom diagnostic — the format is one this node
    /// does not parse, which is a limit of the reader rather than a defect in
    /// the seal.
    pub unreadable: u64,
    /// The passports carrying a broken seal, so an operator can act rather than
    /// grep a log.
    ///
    /// Capped — see [`Self::truncated`]. A node with thousands of broken seals
    /// has one problem, not thousands, and the count above already states its
    /// size; a list long enough to prove that is a list nobody reads.
    pub broken_passports: Vec<PassportId>,
    /// True when [`Self::broken_passports`] was cut short.
    ///
    /// Stated rather than left to be inferred from the length matching the cap,
    /// which is the kind of inference that is right until the cap changes.
    pub truncated: bool,
}

/// The last completed audit pass, shared between the task that runs it and the
/// route that reports it.
///
/// # Why this is held in memory rather than stored
///
/// The findings are **derived**: they can be recomputed from the seals at any
/// time, and the only reason not to recompute them on demand is that opening
/// every CAdES would give a read route unpredictable latency. That makes this a
/// cache, and a cache is a poor candidate for a table — a repaired seal would
/// leave a stale row until the next walk, and the row would need invalidating by
/// something that already knows the answer.
///
/// [`Self::last`] returns an `Option` and the route reports the absence rather
/// than a zero: **"no pass has completed" and "no broken seals" are different**,
/// and serving the second when the first is true is how a monitoring surface
/// reassures an operator about something it has not looked at. EU law draws the
/// same line for validation generally — CIR (EU) 2025/1945, which pins the
/// validation standards for qualified seals, makes *indeterminate* a distinct
/// technical outcome from valid and from invalid, and requires it to be reported
/// as such rather than collapsed into either.
///
/// # This is seeded from storage, not only from the running process
///
/// A restart empties the slot, and used to leave the route blind for the length
/// of a whole walk — hours on a large estate, and indistinguishable from an
/// audit that is not running. Worse, a deployment whose estate takes longer to
/// walk than it goes between restarts would never publish anything at all.
///
/// So a node that keeps a [`SealAuditStore`] loads the last stored report into
/// this at boot and stores each new one. `None` then means what it says: **no
/// pass has ever completed against this database**, not merely none since this
/// process started. Nodes without a store keep the old behaviour, which is the
/// honest degradation — the absence is still the truth about what this process
/// knows.
#[derive(Debug, Default)]
pub struct SealAuditLog(std::sync::RwLock<Option<SealAuditReport>>);

impl SealAuditLog {
    /// Publish the result of a completed pass.
    pub fn record(&self, report: SealAuditReport) {
        // A poisoned lock means a panic while holding it. Recovering is right
        // here: the data is a cache of a derived value, so the worst a poisoned
        // read can serve is a stale report, and refusing to record would leave
        // the route permanently blind for a reason unrelated to seals.
        let mut slot = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(report);
    }

    /// The last completed pass, if there has been one.
    #[must_use]
    pub fn last(&self) -> Option<SealAuditReport> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// A walk that has started and not yet reached the end.
///
/// The audit covers the estate in batches, so between the first batch and the
/// last there is a partial result that is **not** publishable: a count from half
/// the estate reads exactly like a count from all of it, and the difference is
/// the whole value of the number. This is that half-finished state, kept so it
/// can be picked up again rather than thrown away.
///
/// # Why this is stored and the report alone would not be enough
///
/// The failure it exists for is a node whose estate takes longer to walk than
/// the node goes between restarts. Storing only the finished report does not
/// help there, because the finished report is exactly what such a node never
/// produces — it would begin again from the start every time, for ever, and
/// report nothing while doing a great deal of work. Keeping the cursor makes the
/// progress survive, so the walk finishes eventually however often the process
/// is replaced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealAuditProgress {
    /// When this walk began — and the bound it passes to
    /// [`SealOutbox::sealed_passports`], so the pass describes exactly the seals
    /// that existed at that moment.
    pub started_at: DateTime<Utc>,
    /// The last passport the walk has looked at. `None` means it is at the
    /// beginning.
    pub cursor: Option<PassportId>,
    /// Seals opened so far in this walk.
    pub checked: u64,
    /// Sound so far.
    pub sound: u64,
    /// Intact over a superseded signature so far.
    pub superseded: u64,
    /// Broken so far.
    pub broken: u64,
    /// Certificate-failed so far.
    pub certificate_failed: u64,
    /// Unreadable so far.
    pub unreadable: u64,
    /// The broken passports named so far, capped by the caller.
    pub broken_passports: Vec<PassportId>,
}

/// Where a node keeps what its seal audit has found and how far it has got.
///
/// # This is a cache with one job the cache argument does not cover
///
/// The findings are derived and recomputable, which is why they are *also* held
/// in [`SealAuditLog`] in memory and served from there. Storing them buys two
/// things memory cannot:
///
/// - a restart no longer erases the answer, so the route stops saying "no pass
///   has completed" for the length of a whole walk after every deployment —
///   which on a large estate is hours, and is indistinguishable from an audit
///   that is not running;
/// - a walk survives the restart too, so progress accumulates instead of
///   resetting.
///
/// What it deliberately does **not** become is a record of validations. Under
/// Reg. (EU) No 910/2014 Art. 33, reached for seals by Art. 40, a *qualified*
/// validation service is a QTSP service whose result carries the provider's own
/// advanced signature or seal. Nothing here is signed and nothing here is
/// qualified; this is a node's own housekeeping, and a stored row must not be
/// presented as an attestation that a seal was valid at a moment in time.
#[async_trait]
pub trait SealAuditStore: Send + Sync {
    /// Read back the walk in progress and the last completed report.
    ///
    /// Both are independently optional: a node that has never finished a walk
    /// has progress and no report, and a node that finished one and has not
    /// started the next has a report and no progress.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn load(&self) -> Result<(Option<SealAuditProgress>, Option<SealAuditReport>), DppError>;

    /// Save the walk's position after a batch, leaving the last report alone.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn save_progress(&self, progress: &SealAuditProgress) -> Result<(), DppError>;

    /// Publish a completed pass: store `report` and clear the progress, so a
    /// restart starts the next walk cleanly rather than resuming a finished one.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn complete(&self, report: &SealAuditReport) -> Result<(), DppError>;
}

/// One sealed passport, as an audit pass needs to see it.
#[derive(Debug, Clone)]
pub struct SealedPassport {
    /// The passport carrying the seal.
    pub passport_id: PassportId,
    /// The seal stored on it.
    pub seal: SealedEnvelope,
    /// Hex SHA-256 of the passport's **current** compact JWS — what a sound
    /// seal should be covering.
    pub payload_hash: String,
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

    /// Re-arm a **sealed** row so its passport is sealed again.
    ///
    /// # This deliberately crosses the line [`Self::enqueue`] holds
    ///
    /// `enqueue` re-arms only `exhausted` rows, and says why: a `sealed` row
    /// "has an artifact that was paid for, so re-queueing it buys the same
    /// attestation twice". That reasoning is sound wherever the artifact is
    /// worth something. It is exactly wrong where the artifact is a seal that
    /// does not verify — there the row is paid for **and** carries nothing, and
    /// the passport is published and, in substance, unsealed.
    ///
    /// So this is the one path that re-arms a `sealed` row, and it is the
    /// caller's job to have established that the seal is worthless first. The
    /// store cannot check that — whether a seal stands up is cryptographic — so
    /// the guarantee lives at the call site and nowhere else.
    ///
    /// Returns whether a row actually moved. `false` means there was no `sealed`
    /// row for that digest, which is not an error: the passport may have been
    /// re-published, or a repair may already be queued.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn rearm_sealed(
        &self,
        passport_id: PassportId,
        payload_hash: &str,
        reason: &str,
    ) -> Result<bool, DppError>;

    /// Sealed passports, in id order, for an audit pass to read.
    ///
    /// # Why "unsealed" is not the only failure worth finding
    ///
    /// [`Self::enqueue_unsealed`] and [`Self::unsealed_published_count`] both ask
    /// the same question of the database: is the `seal` member absent? **A seal
    /// that is present but worthless satisfies neither clause.** Its passport is
    /// not swept, not counted, and looks healthy in every number this node
    /// reports — while being, in substance, unsealed.
    ///
    /// That question cannot be a SQL clause. Whether a stored seal stands up is
    /// cryptographic: open the CAdES, check the signature, read the digest it
    /// covers and compare. So this hands the rows out and lets a caller that can
    /// read seals decide.
    ///
    /// Paged with `after` as a cursor rather than an offset: passport ids are
    /// UUIDv7 and time-ordered, so a cursor is stable against rows arriving
    /// mid-walk, which an offset is not.
    ///
    /// # `sealed_before` pins what a pass is a statement *about*
    ///
    /// A walk takes minutes to hours, and seals are written while it runs. Which
    /// of those a pass happens to see depends on where its cursor had reached —
    /// so without a bound, "checked 1,204" describes a population nobody can
    /// name, and two consecutive passes disagree for reasons that are not about
    /// the seals.
    ///
    /// Passing the moment the walk started makes the pass a statement about
    /// exactly the seals that existed then. Skipping the newer ones costs
    /// nothing in coverage: the drain checks a seal's binding before it accepts
    /// it, so a seal written during the walk was verified as it landed, and the
    /// next pass covers it anyway.
    ///
    /// `None` walks everything, which is what a caller doing a one-off sweep
    /// wants. A passport whose seal cannot be dated is **included** either way:
    /// not knowing when something was sealed is not a reason to stop looking at
    /// it.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn sealed_passports(
        &self,
        limit: i64,
        after: Option<PassportId>,
        sealed_before: Option<DateTime<Utc>>,
    ) -> Result<Vec<SealedPassport>, DppError>;
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

/// The main status indication of a validation process, as ETSI EN 319 102-1
/// clause 5.1.3 defines it.
///
/// The standard has three. **This enum has two**, and the missing one is the
/// point: `TOTAL-PASSED` requires, among other things, that the constraints
/// applicable to the signer's certificate "have been positively validated". This
/// node checks format and cryptography and does not build or validate a
/// certificate chain — no validity window, no revocation, no trust anchor. A
/// seal can therefore be as sound as this node can establish and still not have
/// passed, and an enum that could express `totalPassed` would eventually be
/// asked to.
///
/// Making that unrepresentable is the honest encoding of what the node does
/// today. Reg. (EU) No 910/2014 Art. 32(1)(b), reached for seals by Art. 40,
/// is the requirement that is missing, and implementing it is what would make a
/// third variant meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationIndication {
    /// The signature is demonstrably not valid, and no further data can change
    /// that.
    ///
    /// The standard is explicit that this is stable: the same inputs always
    /// yield the same answer, and *additional validation data* cannot lift a
    /// `TOTAL-FAILED` to a pass — only additional proofs of existence can change
    /// a result at all. That stability is what makes it safe to spend money on a
    /// replacement seal for one, and it is why the repair route refuses
    /// everything else.
    TotalFailed,
    /// The available information is insufficient to decide.
    ///
    /// Not a weaker "failed". Under CIR (EU) 2025/1945 — the act that pins how a
    /// qualified seal is validated — an indeterminate result is its own
    /// technical outcome, "neither an EU qualified electronic signature, nor an
    /// EU qualified electronic seal", and is to be reported as such rather than
    /// collapsed into either neighbour.
    Indeterminate,
}

/// The sub-indication qualifying a [`ValidationIndication`], from EN 319 102-1
/// table 6.
///
/// Only the two this node can actually justify are modelled. Where none of the
/// table's values fits, the standard's own instruction is to report a custom
/// diagnostic instead — and [`SealBinding`] beside this *is* that diagnostic, in
/// machine-readable form, which is why the field is optional here rather than
/// stretched to a value that nearly fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationSubIndication {
    /// The signature value could not be verified with the public key in the
    /// signing certificate.
    SigCryptoFailure,
    /// A hash of signed data does not match the value in the signature — here,
    /// the passport's current signature against the digest the seal covers.
    HashFailure,
    /// The signing certificate was revoked before the seal was made, and a
    /// timestamp proves the order.
    Revoked,
    /// The signing certificate had expired when the seal was made, and a
    /// timestamp proves it.
    Expired,
    /// The signing certificate was not yet valid when the seal was made, and a
    /// timestamp proves it.
    NotYetValid,
    /// The certificate is revoked, and nothing here proves the seal was made
    /// before that.
    ///
    /// `NO_POE` throughout table 6 means *no proof of existence*: without an
    /// attested time the seal cannot be placed on either side of the revocation,
    /// and a revoked certificate does not retroactively unmake a seal it made
    /// while valid. Reporting this as a failure would condemn every sound seal
    /// from a provider that later rotated a key.
    RevokedNoPoe,
    /// The certificate is outside its validity window, and nothing here proves
    /// the seal was made while it was inside.
    ///
    /// The ordinary state of a long-lived seal: certificates expire, sealed
    /// passports are kept for a decade, and a `B-B` seal carries no time anybody
    /// can trust. It is what an archival timestamp exists to fix.
    OutOfBoundsNoPoe,
    /// Revocation information was not available, so the question could not be
    /// asked.
    ///
    /// Not a defect in the seal. A `B-B` or `B-T` seal is not required to carry
    /// revocation material — ETSI EN 319 122-1 puts it in `SignedData.crls` from
    /// `B-LT` upward — and this node reads only what the seal carries.
    TryLater,
}

/// What this node's reading of a seal amounts to in EN 319 102-1's vocabulary.
///
/// A translation, not a second opinion: every value is derived from
/// [`SealBinding`] and adds no checking. It exists because the audit's findings
/// travel to readers whose tooling speaks that vocabulary, and because the
/// translation makes one thing explicit that our own names let a reader assume —
/// that a sound seal here has **not** passed validation, it has merely not
/// failed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealValidationStatus {
    /// The main indication.
    pub indication: ValidationIndication,
    /// The sub-indication, where one from table 6 applies. `null` means the
    /// standard's custom-diagnostic case, and `binding` carries the diagnostic.
    pub sub_indication: Option<ValidationSubIndication>,
}

impl SealBinding {
    /// This reading, stated in EN 319 102-1's terms.
    ///
    /// The mapping, and why each one:
    ///
    /// | This node | Indication | Sub-indication |
    /// |---|---|---|
    /// | `coversThisSignature` | `indeterminate` | — |
    /// | `coversAnotherDigest` | `totalFailed` | `hashFailure` |
    /// | `notIntact` | `totalFailed` | `sigCryptoFailure` |
    /// | `unknown` | `indeterminate` | — |
    ///
    /// **A sound seal is `indeterminate`, not passed**, for the reason
    /// [`ValidationIndication`] gives: the certificate has not been validated,
    /// so the strongest honest answer is that nothing has failed yet.
    ///
    /// **A superseded seal is `totalFailed`**, which reads oddly until the
    /// question is stated precisely: validating *this passport's current
    /// signature* against that seal fails on the hash, exactly as table 6
    /// describes. The seal itself is intact and is a perfectly good attestation
    /// of the signature it does cover — which is why this node reports it
    /// separately and does not alarm on it, and why a repair is refused.
    ///
    /// Both `indeterminate` cases are the custom-diagnostic case, and they are
    /// not the same diagnostic: one is "the certificate was never checked", the
    /// other "these bytes could not be read". `binding` keeps them apart.
    #[must_use]
    pub fn validation_status(&self) -> SealValidationStatus {
        SealValidationStatus::of(self, None)
    }
}

/// Where a certificate's validity window sits relative to the moment being asked
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WindowStanding {
    /// The moment falls inside `notBefore`..`notAfter`.
    Inside,
    /// It is after `notAfter`.
    Expired,
    /// It is before `notBefore`.
    NotYetValid,
}

/// A certificate's validity window, and where the sealing moment falls in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityWindow {
    /// The certificate's `notBefore`.
    pub not_before: DateTime<Utc>,
    /// The certificate's `notAfter`.
    pub not_after: DateTime<Utc>,
    /// Where the judged moment falls.
    pub standing: WindowStanding,
}

/// The moment a certificate's standing was judged against, and whether anything
/// proves it.
///
/// Reg. (EU) No 910/2014 Art. 32(1)(b), reached for seals by Art. 40, asks
/// whether the certificate was valid **at the time of signing** — so the whole
/// answer turns on which time is used and what that time is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JudgedTime {
    /// The moment used.
    pub at: DateTime<Utc>,
    /// True when it came from a timestamp token inside the seal, checked.
    ///
    /// False means it is this node's clock — the validation time, not the
    /// signing time. Every verdict resting on an unattested moment is reported
    /// with a `NO_POE` sub-indication for exactly this reason: EN 319 102-1
    /// treats a time nothing proves as no time at all, and so does this.
    pub attested: bool,
}

/// What the seal's own revocation material says about its certificate.
///
/// **Read from the seal, never fetched.** A CRL distribution point is a URL
/// inside a certificate an operator was handed, and following one would make a
/// background task issue requests to an address chosen by whoever produced the
/// seal. The long-term profiles exist precisely so this is unnecessary: ETSI
/// EN 319 122-1 puts revocation values in `SignedData.crls` from `B-LT` upward,
/// so a seal meant to be checkable years later carries what is needed to check
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// `rename_all` renames the *variants*; the fields inside them need
// `rename_all_fields`, or `as_of` ships as `as_of` while the spec documents
// `asOf`. The same trap put `lapsed_at` on the wire once already — see
// `ArchivalFreshness`, which carries both attributes for the same reason.
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status"
)]
pub enum RevocationStanding {
    /// A CRL covering this certificate lists it as not revoked.
    NotRevoked {
        /// The CRL's `thisUpdate` — the moment its statement is about.
        ///
        /// A CRL issued *before* the seal was made cannot show a revocation that
        /// happened after it. Carried so a reader can see which question was
        /// actually answered rather than assuming the strongest one.
        as_of: DateTime<Utc>,
    },
    /// The certificate appears on a CRL as revoked.
    Revoked {
        /// When the CA says it was revoked.
        at: DateTime<Utc>,
    },
    /// The seal carries no revocation material for this certificate.
    ///
    /// Ordinary below `B-LT`, and not a defect.
    NotAvailable,
    /// Material is present and cannot be relied on.
    Unusable {
        /// Why — an unparseable CRL, one from another issuer, or one whose own
        /// signature does not verify. Separate from [`Self::NotAvailable`]
        /// because something was there and failed, which is worth looking at.
        reason: String,
    },
}

/// What this node can establish about the seal's signing certificate.
///
/// Art. 32(1)(b) has two limbs — issued by a qualified provider, and **valid at
/// the time of signing** — and this answers the second. The first is a trusted
/// list question, answered elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateStanding {
    /// The certificate's window, and where the judged moment falls in it.
    pub validity: ValidityWindow,
    /// The moment judged against, and whether anything proves it.
    pub judged_at: JudgedTime,
    /// What the seal's own revocation material says.
    pub revocation: RevocationStanding,
}

impl SealValidationStatus {
    /// The EN 319 102-1 status for a seal, from everything this node checked.
    ///
    /// # The order is the point
    ///
    /// A seal can fail in several ways at once, and the reported answer must be
    /// the one that decides the outcome. Cryptography first: a signature that
    /// does not verify makes every later question moot, because the attributes
    /// those questions read sit inside it. Then the certificate, whose failures
    /// are `TOTAL-FAILED` only when a timestamp proves the ordering — without
    /// one they are indeterminate, and reporting them as failures would condemn
    /// every sound seal whose certificate has since expired, which is all of
    /// them eventually.
    ///
    /// # Passing is still not reachable
    ///
    /// Even with the window checked and the CRL read, `TOTAL-PASSED` needs the
    /// whole of clause 5.1.3's list — the format check, the policy constraints,
    /// and a certificate chain validated to a trust anchor.
    /// [`ValidationIndication`] therefore still has two variants, and a seal
    /// that survives every check here reports `indeterminate`.
    #[must_use]
    pub fn of(binding: &SealBinding, certificate: Option<&CertificateStanding>) -> Self {
        use ValidationSubIndication as Sub;

        let failed = |sub| Self {
            indication: ValidationIndication::TotalFailed,
            sub_indication: Some(sub),
        };
        let unsure = |sub| Self {
            indication: ValidationIndication::Indeterminate,
            sub_indication: sub,
        };

        match binding {
            SealBinding::NotIntact => return failed(Sub::SigCryptoFailure),
            SealBinding::CoversAnotherDigest { .. } => return failed(Sub::HashFailure),
            SealBinding::CoversThisSignature | SealBinding::Unknown => {}
        }

        let Some(cert) = certificate else {
            return unsure(None);
        };
        let proven = cert.judged_at.attested;

        // Revocation before the window, because a revoked certificate is the
        // stronger statement: expiry is scheduled and ordinary, revocation is
        // someone saying this key should not have been used.
        match &cert.revocation {
            RevocationStanding::Revoked { at } if proven && *at <= cert.judged_at.at => {
                return failed(Sub::Revoked);
            }
            RevocationStanding::Revoked { .. } => return unsure(Some(Sub::RevokedNoPoe)),
            RevocationStanding::NotRevoked { .. } => {}
            // Both mean the question could not be answered, which table 6 calls
            // `TRY_LATER` — it may be answerable when the material is there.
            RevocationStanding::NotAvailable | RevocationStanding::Unusable { .. } => {
                return unsure(Some(Sub::TryLater));
            }
        }

        match (cert.validity.standing, proven) {
            (WindowStanding::Inside, _) => unsure(None),
            (WindowStanding::Expired, true) => failed(Sub::Expired),
            (WindowStanding::NotYetValid, true) => failed(Sub::NotYetValid),
            (WindowStanding::Expired | WindowStanding::NotYetValid, false) => {
                unsure(Some(Sub::OutOfBoundsNoPoe))
            }
        }
    }
}

/// How much life is left in a seal's archival timestamp.
///
/// An archival timestamp is what keeps a `B-LTA` seal verifiable after its
/// signing certificate expires — the whole point for a retention-locked
/// passport, which outlives every certificate involved. **It expires too**: its
/// own timestamping authority's certificate has a validity period, and ETSI's
/// long-term profiles expect re-timestamping before that. Nothing here does
/// that, and the level says `baseline-lta` either way, so a lapse is otherwise
/// invisible.
///
/// **A signal, never a verdict.** A seal nearing its renewal date still
/// verifies, and that window is the only chance to renew without an outage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// `rename_all` renames the *variants*; the fields inside them need
// `rename_all_fields`. `SealBinding` above happens not to show the difference —
// its one field is a single word — which is exactly how this would have shipped
// with `lapsed_at` on the wire had the contract gate not compared the spec to
// the type.
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "state"
)]
pub enum ArchivalFreshness {
    /// No archival timestamp at all — a seal below `B-LTA`.
    ///
    /// Nothing to renew, which is a different thing from a renewal that has
    /// lapsed: a `B-LT` seal was never promised long-term protection, and saying
    /// it lapsed would raise an alarm about a commitment nobody made.
    NotArchived,
    /// The archival timestamp's authority certificate is still valid.
    Current {
        /// When the authority's certificate expires — the date by which
        /// re-timestamping must have happened.
        ///
        /// No threshold is applied: how much notice is enough is a policy
        /// question for whoever reads this.
        expires: DateTime<Utc>,
    },
    /// It has expired, so the archival protection has lapsed.
    ///
    /// The seal may still verify today. What is gone is the thing meant to keep
    /// it verifying once its signing certificate goes.
    Lapsed {
        /// When the authority's certificate expired.
        ///
        /// The same date `current` carries, read from the other side of it —
        /// one value, so the wire has one name for it rather than two that must
        /// be kept in step.
        expires: DateTime<Utc>,
    },
    /// An archival timestamp is present and could not be read.
    ///
    /// **Not `current`.** A token that cannot be checked is not a fresh one, and
    /// reporting it as current is how a staleness signal goes quiet at the
    /// moment it matters.
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

    /// The baseline level the envelope's **bytes** carry, as distinct from the
    /// level recorded on it.
    ///
    /// `SealedEnvelope::conformance_level` records what this node *asked* for.
    /// This reports what arrived. The two disagreeing is a downgrade — a
    /// provider enabled for a weaker profile than was paid for — and it is the
    /// failure that matters most, because it lands on a retention-locked
    /// passport that cannot be re-sealed and only shows years later when the
    /// signing certificate expires.
    ///
    /// A floor, not a conformance verdict: it reports that the *distinguishing
    /// material* for a level is present, never that the material was validated.
    ///
    /// `None` when the bytes cannot be read.
    fn evidenced_level(&self, envelope: &SealedEnvelope) -> Option<SealConformanceLevel>;

    /// The time a timestamp authority attests the seal was made.
    ///
    /// Not [`SealedEnvelope::sealed_at`], which is the sealing node's own clock
    /// when the backend answered — an unattested claim by the party that bought
    /// the seal. From `B-T` upward the envelope carries a time-stamp token, and
    /// that token is the only place in a seal an attested time can be.
    ///
    /// The implementation must check the token's own signature **and** that its
    /// imprint covers this seal's signature. The attribute carrying it is
    /// *unsigned*, so swapping in a genuine token from another seal costs
    /// nothing and would otherwise be accepted.
    ///
    /// `None` for a `B-B` seal, and for a token that fails either check — a time
    /// that did not survive checking must not be reported as a time.
    ///
    /// Says nothing about whether the authority is **trusted** or **qualified**:
    /// Art. 42 makes a qualified time stamp a QTSP service, which is a Trusted
    /// List question about the `TSA/QTST` service type and is not asked here.
    fn attested_sealing_time(&self, envelope: &SealedEnvelope) -> Option<DateTime<Utc>>;

    /// How much life is left in the envelope's archival timestamp, as of `now`.
    ///
    /// `now` is a parameter rather than read from the clock so the answer is a
    /// function of its inputs — the same seal is current today and lapsed later,
    /// and a caller reporting on a past moment should be able to say so.
    fn archival_freshness(
        &self,
        envelope: &SealedEnvelope,
        now: DateTime<Utc>,
    ) -> ArchivalFreshness;

    /// What the seal's own certificate's standing was when the seal was made.
    ///
    /// The second limb of Reg. (EU) No 910/2014 Art. 32(1)(b), reached for seals
    /// by Art. 40: a qualified certificate must have been **valid at the time of
    /// signing**. Whether its issuer was a qualified provider is the other limb
    /// and a trusted list question; this one is answerable from the seal alone.
    ///
    /// `now` is a parameter for the same reason it is on
    /// [`Self::archival_freshness`] — so the answer is a function of its inputs.
    /// It is used only as the fallback moment, and only when the seal carries no
    /// attested time; [`JudgedTime::attested`] says which happened, and that
    /// distinction decides whether an out-of-window certificate is a failure or
    /// merely unproven.
    ///
    /// `None` when the bytes cannot be read — never a verdict of valid or
    /// invalid, for the reason every other question here returns an option.
    fn certificate_standing(
        &self,
        envelope: &SealedEnvelope,
        now: DateTime<Utc>,
    ) -> Option<CertificateStanding>;
}

#[cfg(test)]
mod validation_vocabulary {
    use super::*;

    /// **The one that matters: a sound seal has not passed.**
    ///
    /// EN 319 102-1 clause 5.1.3 puts "the constraints applicable to the
    /// signer's certificate have been positively validated" among the conditions
    /// for `TOTAL-PASSED`, and this node validates no certificate. Reporting a
    /// pass would claim a check nobody ran — the same failure as reporting a
    /// zero for an audit that has not completed, one level down.
    #[test]
    fn a_seal_this_node_calls_sound_is_indeterminate_not_passed() {
        let status = SealBinding::CoversThisSignature.validation_status();
        assert_eq!(status.indication, ValidationIndication::Indeterminate);
        assert_eq!(
            status.sub_indication, None,
            "no table 6 value says 'the certificate was never checked' — that is the \
             standard's custom-diagnostic case, and `binding` is the diagnostic"
        );
    }

    /// A broken seal is the stable verdict, and the whole basis of the repair
    /// route: more validation data cannot lift a `TOTAL-FAILED`.
    #[test]
    fn a_broken_seal_is_total_failed_on_the_cryptography() {
        let status = SealBinding::NotIntact.validation_status();
        assert_eq!(status.indication, ValidationIndication::TotalFailed);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::SigCryptoFailure)
        );
    }

    /// Against *this passport's current signature*, a superseded seal fails on
    /// the hash. It remains a sound attestation of the signature it covers,
    /// which is why the node counts it apart and refuses to repair it.
    #[test]
    fn a_superseded_seal_fails_on_the_hash_of_this_signature() {
        let status = SealBinding::CoversAnotherDigest {
            covered: "ab".repeat(32),
        }
        .validation_status();
        assert_eq!(status.indication, ValidationIndication::TotalFailed);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::HashFailure)
        );
    }

    /// "Cannot read" is not "failed" — the distinction CIR (EU) 2025/1945 makes
    /// a technical outcome in its own right, and the reason repairing one is
    /// refused.
    #[test]
    fn an_unreadable_seal_is_indeterminate_not_failed() {
        let status = SealBinding::Unknown.validation_status();
        assert_eq!(status.indication, ValidationIndication::Indeterminate);
        assert_eq!(status.sub_indication, None);
    }

    fn standing(
        window: WindowStanding,
        attested: bool,
        revocation: RevocationStanding,
    ) -> CertificateStanding {
        let at = "2027-06-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("a time");
        CertificateStanding {
            validity: ValidityWindow {
                not_before: "2026-01-01T00:00:00Z".parse().expect("a time"),
                not_after: "2027-01-01T00:00:00Z".parse().expect("a time"),
                standing: window,
            },
            judged_at: JudgedTime { at, attested },
            revocation,
        }
    }

    fn clean() -> RevocationStanding {
        RevocationStanding::NotRevoked {
            as_of: "2027-06-01T00:00:00Z".parse().expect("a time"),
        }
    }

    /// **An expired certificate fails only when a timestamp proves the order.**
    ///
    /// Art. 32(1)(b) asks whether the certificate was valid *at the time of
    /// signing*, so the verdict turns entirely on whether the signing time is
    /// known. With an attested time the seal was made after expiry and that is a
    /// failure; without one, all that is known is that the certificate is
    /// expired *now* — which is the eventual state of every certificate, and
    /// says nothing about a seal made years earlier.
    #[test]
    fn an_expired_certificate_fails_only_against_a_proven_time() {
        let proven = standing(WindowStanding::Expired, true, clean());
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&proven));
        assert_eq!(status.indication, ValidationIndication::TotalFailed);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::Expired)
        );

        let unproven = standing(WindowStanding::Expired, false, clean());
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&unproven));
        assert_eq!(
            status.indication,
            ValidationIndication::Indeterminate,
            "without a proof of existence this must not read as a failure"
        );
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::OutOfBoundsNoPoe)
        );
    }

    /// The same rule for revocation, and the asymmetry matters more here: a
    /// certificate revoked *after* a seal was made does not unmake the seal.
    #[test]
    fn a_revoked_certificate_fails_only_against_a_proven_time() {
        let revoked_before = RevocationStanding::Revoked {
            at: "2027-01-05T00:00:00Z".parse().expect("a time"),
        };
        let proven = standing(WindowStanding::Inside, true, revoked_before.clone());
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&proven));
        assert_eq!(status.indication, ValidationIndication::TotalFailed);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::Revoked)
        );

        let unproven = standing(WindowStanding::Inside, false, revoked_before);
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&unproven));
        assert_eq!(status.indication, ValidationIndication::Indeterminate);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::RevokedNoPoe)
        );
    }

    /// A revocation *after* the attested sealing time is not a finding at all —
    /// the seal was made while the certificate was good.
    #[test]
    fn a_revocation_after_sealing_does_not_condemn_the_seal() {
        let later = RevocationStanding::Revoked {
            at: "2027-12-01T00:00:00Z".parse().expect("a time"),
        };
        let cert = standing(WindowStanding::Inside, true, later);
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&cert));
        assert_eq!(status.indication, ValidationIndication::Indeterminate);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::RevokedNoPoe),
            "reported, because a reader should see it — but not as a failure"
        );
    }

    /// No revocation material is `TRY_LATER`: the question could not be asked,
    /// which is the ordinary state of a `B-B` or `B-T` seal.
    #[test]
    fn a_seal_carrying_no_revocation_material_is_try_later() {
        let cert = standing(
            WindowStanding::Inside,
            true,
            RevocationStanding::NotAvailable,
        );
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&cert));
        assert_eq!(status.indication, ValidationIndication::Indeterminate);
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::TryLater)
        );
    }

    /// **The cryptography decides first.**
    ///
    /// A seal whose signature does not verify is `SIG_CRYPTO_FAILURE` whatever
    /// the certificate says — and it must be, because the attributes every other
    /// question reads sit inside that signature. Reporting the revocation
    /// instead would hand a reader a finding drawn from bytes nothing vouches
    /// for.
    #[test]
    fn a_broken_signature_outranks_every_certificate_finding() {
        let revoked = standing(
            WindowStanding::Expired,
            true,
            RevocationStanding::Revoked {
                at: "2026-06-01T00:00:00Z".parse().expect("a time"),
            },
        );
        let status = SealValidationStatus::of(&SealBinding::NotIntact, Some(&revoked));
        assert_eq!(
            status.sub_indication,
            Some(ValidationSubIndication::SigCryptoFailure)
        );
    }

    /// Everything checked, nothing wrong — and still not a pass, because the
    /// chain has not been validated to a trust anchor and the policy constraints
    /// have not been applied.
    #[test]
    fn a_certificate_that_survives_every_check_is_still_only_indeterminate() {
        let cert = standing(WindowStanding::Inside, true, clean());
        let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&cert));
        assert_eq!(status.indication, ValidationIndication::Indeterminate);
        assert_eq!(
            status.sub_indication, None,
            "nothing in table 6 applies, so this is the custom-diagnostic case"
        );
    }

    /// The wire strings are the standard's names in this API's casing, and
    /// consumers key on them.
    #[test]
    fn the_vocabulary_serialises_to_the_documented_strings() {
        let json = serde_json::to_value(SealBinding::NotIntact.validation_status()).unwrap();
        assert_eq!(json["indication"], "totalFailed");
        assert_eq!(json["subIndication"], "sigCryptoFailure");

        let sound = serde_json::to_value(SealBinding::CoversThisSignature.validation_status())
            .expect("serialises");
        assert_eq!(sound["indication"], "indeterminate");
        assert!(
            sound["subIndication"].is_null(),
            "the custom-diagnostic case must be visibly empty, not filled with a near fit"
        );
    }
}
