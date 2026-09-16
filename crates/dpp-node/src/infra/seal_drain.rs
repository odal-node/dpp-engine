//! One drain pass over the qualified-seal outbox.
//!
//! Fetches due rows and asks the QTSP to seal each digest, writing the returned
//! envelope onto the passport. Extracted from the node's background loop so the
//! semantics are unit-testable with in-memory doubles — the loop in `main` just
//! calls this on a timer.
//!
//! Structurally mirrors `snapshot_drain`/`webhook_drain`: never panics, never
//! propagates — a per-row failure is recorded (`mark_*`) and the pass continues,
//! so one bad row cannot stall the queue.
//!
//! # Why the row carries the digest
//!
//! Unlike the snapshot outbox, whose row names only a passport so the action can
//! be re-derived, a seal row carries the exact digest to seal. It has to: the
//! seal is an attestation about one specific signature at one specific moment,
//! and re-deriving it at drain time would silently seal whatever the passport
//! says *now* — quietly buying a seal over a signature the operator never
//! intended to attest, if a re-publish landed in between.
//!
//! # Every drained row costs money
//!
//! That shapes two decisions here. Failures back off and retry rather than being
//! dropped, because the expensive outcome is a seal produced and not recorded,
//! not a call that failed. And `mark_sealed` writes the envelope and closes the
//! row in one transaction, so a crash cannot leave a `pending` row for a seal
//! already billed.

use std::sync::Arc;

use dpp_domain::{
    ports::seal::SealPort,
    seal::{
        SealConformanceLevel, SealCredentialRef, SealEnvelope, SealFormat, SealMode, SealRequest,
        SealedEnvelope,
    },
};
use dpp_types::SealOutbox;

/// Max sealing attempts before a row is terminally `exhausted`.
pub const MAX_ATTEMPTS: i32 = 8;

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Rows whose seal is now on the passport.
    pub sealed: u32,
    /// Rows that failed transiently and were backed off for retry.
    pub retried: u32,
    /// Rows that reached terminal `exhausted` — the passport stays unsealed.
    pub exhausted: u32,
}

/// Record a transient failure: back off and retry, unless the attempt cap is
/// reached in which case the row is terminally `exhausted`.
async fn back_off_or_exhaust(
    outbox: &Arc<dyn SealOutbox>,
    id: uuid::Uuid,
    attempts: i32,
    reason: String,
    stats: &mut DrainStats,
) {
    if attempts + 1 >= MAX_ATTEMPTS {
        let _ = outbox
            .mark_exhausted(id, format!("max attempts reached: {reason}"))
            .await;
        metrics::counter!("seal_total", "outcome" => "exhausted").increment(1);
        stats.exhausted += 1;
    } else {
        let _ = outbox.mark_attempt_failed(id, reason).await;
        metrics::counter!("seal_total", "outcome" => "retried").increment(1);
        stats.retried += 1;
    }
}

/// Drain up to `batch` due seal rows once.
///
/// `mode` travels in from the composition root for the same reason `key_ref` and
/// `conformance_level` do, and more urgently than either: it was a literal
/// `ProviderSeal` here, which is a claim about *whose* attestation the seal is —
/// the QTSP's, holding the key on the operator's behalf. Only the QTSP backend
/// advertises that mode. The local development sealer signs under the operator's
/// own self-signed certificate and advertises `OperatorSeal`, so every request
/// this loop built for it was refused by the adapter's capability check, retried
/// eight times and exhausted. `SEAL_PROVIDER=local` could not produce a single
/// seal under any configuration.
///
/// Naming the mode here could not have been right for both backends: it is a
/// property of the arrangement, not of the drain.
pub async fn drain_once(
    outbox: &Arc<dyn SealOutbox>,
    seal: &Arc<dyn SealPort>,
    key_ref: &SealCredentialRef,
    mode: SealMode,
    conformance_level: SealConformanceLevel,
    batch: i64,
) -> DrainStats {
    let mut stats = DrainStats::default();
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "seal outbox drain: query failed");
            return stats;
        }
    };

    for row in due {
        let req = SealRequest {
            payload_hash: row.payload_hash.clone(),
            mode: mode.clone(),
            // CSC-shaped, and no backend here reads it — each one's credential
            // is adapter config rather than a per-request reference. Passed in
            // from the composition root rather than named here: the drain is
            // provider-agnostic, and a literal in this file would put a false
            // provider name on every request of whichever backend it was not.
            key_ref: key_ref.clone(),
            sig_format: SealFormat::Cades,
            // From the composition root, for the same reason `key_ref` is: what
            // a deployment can obtain is a property of its provider arrangement,
            // not of this loop. A backend not enabled for the level refuses in
            // the adapter, before any billable call — the row then backs off and
            // eventually exhausts, which the boot log and the `seal_outbox`
            // gauges already surface as published-but-unsealed.
            conformance_level,
            // The seal covers a digest and travels beside the passport it
            // covers; there is no document for it to wrap.
            envelope: SealEnvelope::Detached,
        };

        let started = std::time::Instant::now();
        let outcome = seal.seal(req).await;
        metrics::histogram!("seal_seconds").record(started.elapsed().as_secs_f64());

        match outcome {
            Ok(envelope) => {
                report_shortfall(&envelope, conformance_level, &row.passport_id);
                if let Some(why) = covers_something_else(&envelope, &row.payload_hash) {
                    metrics::counter!("seal_total", "outcome" => "misbound").increment(1);
                    tracing::error!(
                        passport_id = %row.passport_id,
                        requested = %row.payload_hash,
                        %why,
                        "the seal that came back does not cover the digest it was bought for — \
                         not stored. The passport stays visibly unsealed, which is true, rather \
                         than carrying a seal that attests to something else"
                    );
                    back_off_or_exhaust(
                        outbox,
                        row.id,
                        row.attempts,
                        format!("seal does not cover the requested digest: {why}"),
                        &mut stats,
                    )
                    .await;
                    continue;
                }
                match outbox.mark_sealed(row.id, &envelope).await {
                    Ok(()) => {
                        metrics::counter!("seal_total", "outcome" => "sealed").increment(1);
                        stats.sealed += 1;
                    }
                    // The seal exists and has been billed, but recording it failed.
                    // Back off and retry the *write* — `mark_sealed` is the only
                    // thing that closes the row, so leaving it pending is correct
                    // even though the next attempt will buy a second seal. Loud,
                    // because this is the one path that can cost twice.
                    Err(e) => {
                        tracing::error!(
                            passport_id = %row.passport_id,
                            error = %e,
                            "seal produced but not recorded — a retry will re-seal and re-bill"
                        );
                        back_off_or_exhaust(
                            outbox,
                            row.id,
                            row.attempts,
                            format!("seal recorded failed: {e}"),
                            &mut stats,
                        )
                        .await;
                    }
                }
            }
            Err(e) => {
                back_off_or_exhaust(outbox, row.id, row.attempts, e.to_string(), &mut stats).await;
            }
        }
    }
    stats
}

/// How many broken passports one walk names before it stops collecting.
///
/// A node with thousands of broken seals has one problem, not thousands; the
/// count says how big it is, and a list long enough to prove that is a list
/// nobody reads. Bounded here rather than at the route so the memory is bounded
/// too — a walk over a damaged estate must not accumulate an id per row.
pub const MAX_NAMED_BROKEN: usize = 100;

/// How far ahead a lapsing archive timestamp is worth reporting.
///
/// A `B-LTA` seal's archival protection ends when its timestamping authority's
/// certificate does, and ETSI's long-term profiles handle that by re-stamping
/// before it happens. Nothing here re-stamps — this is the **noticing** half,
/// and the window it reports in is the only one where renewing is routine rather
/// than an incident.
///
/// Ninety days is chosen to be comfortably longer than any plausible
/// procurement: a renewal needs a timestamp from a provider, and an operator who
/// learns about it the week it expires has a problem rather than a task. It is
/// deliberately **not** configurable yet. A threshold becomes a policy the moment
/// something acts on it, and the drain that will act on it does not exist — so
/// picking the knob now would be guessing at the shape of a decision nobody has
/// taken.
pub const RENEWAL_LEAD: chrono::Duration = chrono::Duration::days(90);

/// What one audit pass found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealAudit {
    /// Seals opened.
    pub checked: u64,
    /// Seals that cover their passport's current signature **and** whose
    /// certificate nothing has been shown to fail.
    ///
    /// The second half is weaker than it looks, deliberately. A certificate that
    /// is expired *now* with nothing attesting when the seal was made stays
    /// here: EN 319 102-1 calls that indeterminate, not failed, and treating it
    /// otherwise would eventually condemn every seal this node holds.
    pub sound: u64,
    /// Seals whose signature is sound and whose **certificate** was not, at the
    /// moment they were made.
    ///
    /// Revoked before sealing, or outside its validity window, with an attested
    /// time to prove the order — `TOTAL-FAILED` under EN 319 102-1 with a
    /// certificate sub-indication.
    ///
    /// Counted apart from [`Self::broken`] because the two need opposite
    /// actions. A broken seal is repairable: buy another one, and the
    /// replacement is sound. A seal made under a revoked certificate is not —
    /// the same backend would produce another seal under the same certificate —
    /// so folding these into `broken` would put them in front of a repair route
    /// that cannot help them.
    pub certificate_failed: u64,
    /// Seals over a **different** digest — ordinarily a passport re-published
    /// after sealing, which is not a defect.
    pub superseded: u64,
    /// Seals whose own signature does not verify. These are the finding.
    pub broken: u64,
    /// Seals this node could not read. Not a finding, and not counted as one.
    pub unreadable: u64,
    /// The passports carrying a broken seal, up to [`MAX_NAMED_BROKEN`].
    ///
    /// `broken` keeps counting after this stops filling, so the two together say
    /// "this many, and here are the first hundred".
    pub broken_passports: Vec<dpp_domain::passport::PassportId>,
    /// `B-LTA` seals whose archival protection has already gone.
    pub archival_lapsed: u64,
    /// `B-LTA` seals whose archival protection expires within [`RENEWAL_LEAD`].
    pub archival_due: u64,
    /// `B-LTA` seals carrying an archive timestamp this node cannot use — it
    /// does not parse, or it is not a timestamp of this seal.
    pub archival_unverifiable: u64,
    /// The passports behind `archival_lapsed` and `archival_due`, capped the
    /// same way `broken_passports` is.
    pub renewal_passports: Vec<dpp_domain::passport::PassportId>,
}

impl SealAudit {
    /// Fold one batch's findings into a running walk.
    ///
    /// 🚨 **A method rather than a dozen `+=` at the call site, because the call
    /// site got it wrong.** A walk is many batches; the totals, the gauges and
    /// the published report are all read from the accumulator. When the archival
    /// fields were added to this struct the loop in the node's audit task was
    /// not extended to carry them, so they were counted per batch and then
    /// dropped — every completed report said zero lapsed, zero due, zero
    /// unverifiable and named nobody, on an estate where all of those could be
    /// true. The feature was inert and nothing failed.
    ///
    /// Adding a field to this struct is now the same edit as carrying it: the
    /// destructure below has no `..`, so a new field stops this compiling, and
    /// `every_field_of_a_batch_reaches_the_walk` stops compiling with it.
    pub fn absorb(&mut self, batch: Self) {
        let Self {
            checked,
            sound,
            certificate_failed,
            superseded,
            broken,
            unreadable,
            broken_passports,
            archival_lapsed,
            archival_due,
            archival_unverifiable,
            renewal_passports,
        } = batch;

        self.checked += checked;
        self.sound += sound;
        self.certificate_failed += certificate_failed;
        self.superseded += superseded;
        self.broken += broken;
        self.unreadable += unreadable;
        self.archival_lapsed += archival_lapsed;
        self.archival_due += archival_due;
        self.archival_unverifiable += archival_unverifiable;

        // The counts above keep going after the lists stop filling, which is
        // what makes "this many, and here are the first hundred" true across a
        // whole walk rather than per batch.
        for id in broken_passports {
            if self.broken_passports.len() < MAX_NAMED_BROKEN {
                self.broken_passports.push(id);
            }
        }
        for id in renewal_passports {
            if self.renewal_passports.len() < MAX_NAMED_BROKEN {
                self.renewal_passports.push(id);
            }
        }
    }
}

/// Open a bounded batch of stored seals and report what they are worth.
///
/// # The gap this closes
///
/// The repair sweep and the operator rollup both ask the database whether the
/// `seal` member is **absent**. A seal that is present and worthless satisfies
/// neither: its passport is not swept, not counted, and looks healthy in every
/// number this node reports, while being in substance unsealed.
///
/// That question is cryptographic rather than relational, so it needs a pass
/// that opens seals. This is that pass.
///
/// # It reports and does not repair, deliberately
///
/// The existing sweep carries a guarantee worth keeping: *it cannot double-bill,
/// because it only queues passports carrying no seal at all.* Re-queueing a
/// broken seal breaks exactly that — the row was already paid for, and buying a
/// second seal is justified only because the first is worthless. That is a
/// decision an operator should take knowingly, not one a background loop should
/// take on their behalf on the strength of a check that has never met a real
/// provider's seal.
///
/// So this counts and names them, and an operator decides per passport through
/// `POST /api/v1/dpp/{dppId}/seal/repair` — which re-checks the seal at the
/// moment of the request rather than trusting this list, because a finding here
/// can be hours old.
///
/// # What is not a finding
///
/// A seal over a **different** digest is ordinarily a passport re-published
/// after sealing, which the read route already reports as `superseded` and which
/// the sweep deliberately leaves alone. It is counted separately rather than
/// alarmed on.
///
/// # Three outcomes, not two
///
/// `None` means the batch could not be read at all. It is separate from an empty
/// batch — which is how a walk reports that it reached the end — because the two
/// would otherwise be indistinguishable on the first batch of a walk, and the
/// caller would publish a completed pass that had checked nothing.
///
/// A seal this node **cannot read** is not a finding either. Treating "cannot
/// check" as "broken" would make every seal from a backend emitting a format
/// this node does not parse look like corruption. EU law keeps the same three
/// answers apart: CIR (EU) 2025/1945, which pins how a qualified seal is to be
/// validated, makes *indeterminate* its own technical outcome — neither valid
/// nor invalid — and requires it to be reported as such.
///
/// # `sealed_before` bounds what the pass is about
///
/// Seals are written while a walk runs, and which of them a pass happens to see
/// otherwise depends on where its cursor had reached. Passing the walk's start
/// time makes the pass a statement about exactly the seals that existed then,
/// and costs no coverage: the drain checks a seal's binding before accepting it,
/// so one written during the walk was verified as it landed and is covered by
/// the next pass anyway.
/// What a seal's archival freshness means for the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalFinding {
    /// Nothing to say: below `B-LTA`, or protection with time left on it.
    Nothing,
    /// Protection expires within [`RENEWAL_LEAD`].
    Due,
    /// Protection has already gone.
    Lapsed,
    /// An archive timestamp that cannot be used — unparseable, or not a
    /// timestamp of this seal.
    Unverifiable,
}

/// Classify one seal's archival freshness.
///
/// Extracted from the walk so the boundary is testable without a database. The
/// boundary is the part worth pinning: a lead time is a number, and a comparison
/// written the wrong way round reports every healthy seal as due, or none of
/// them ever.
#[must_use]
pub fn renewal_finding(
    freshness: &dpp_types::ArchivalFreshness,
    now: chrono::DateTime<chrono::Utc>,
) -> RenewalFinding {
    match freshness {
        // A seal below `B-LTA` was never promised long-term protection, so this
        // is silence rather than a finding — the same distinction the read route
        // draws between `notArchived` and `lapsed`.
        dpp_types::ArchivalFreshness::NotArchived => RenewalFinding::Nothing,
        dpp_types::ArchivalFreshness::Current { expires } if *expires - now > RENEWAL_LEAD => {
            RenewalFinding::Nothing
        }
        dpp_types::ArchivalFreshness::Current { .. } => RenewalFinding::Due,
        dpp_types::ArchivalFreshness::Lapsed { .. } => RenewalFinding::Lapsed,
        dpp_types::ArchivalFreshness::Unknown => RenewalFinding::Unverifiable,
    }
}

/// What a seal whose signature holds amounts to, once its certificate and its
/// archival protection have both been looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealFinding {
    /// The certificate behind the signature did not hold. **Nothing further is
    /// asked of this seal**, including its archival state — which is not asked
    /// even as a question, see [`seal_finding`].
    CertificateFailed,
    /// The certificate held. This is what the archival protection says.
    Sound {
        /// What to do about the protection, if anything.
        finding: RenewalFinding,
        /// When the protection runs out, for the operator-facing log line.
        /// `None` where there is no protection, or none that can be read.
        expires: Option<chrono::DateTime<chrono::Utc>>,
    },
}

/// When a seal's archival protection runs out, where that is knowable.
///
/// For the log line only — the classification is [`renewal_finding`]'s.
#[must_use]
fn expiry_of(freshness: &dpp_types::ArchivalFreshness) -> Option<chrono::DateTime<chrono::Utc>> {
    match freshness {
        dpp_types::ArchivalFreshness::Current { expires }
        | dpp_types::ArchivalFreshness::Lapsed { expires } => Some(*expires),
        _ => None,
    }
}

/// Decide what one seal with an intact signature amounts to.
///
/// Extracted from the walk for one property, which is the ordering: a failed
/// certificate ends the enquiry, and the archival question is never asked. Left
/// in the loop, that ordering was a comment claiming a guard the code did not
/// have — the archival block ran regardless, so a seal made under a revoked
/// certificate was counted in `archival_due` and named in `renewal_passports`.
/// An operator would have been handed a renewal queue with a passport in it that
/// renewing cannot fix, and the count it came from would have been wrong too.
///
/// # 🚨 `archival_freshness` is a closure, and that is the point
///
/// Taking the freshness *by value* would have meant computing it before this
/// function could refuse to use it — so the counts would have been right and the
/// work would still have been done. And the work is not a lookup: reading a
/// seal's archival state re-parses the whole CMS and **verifies the signature on
/// every archive timestamp it carries**. Paying for that on a seal already known
/// to be worthless is a cost repeated on every pass, for as long as the seal is
/// stored.
///
/// Passing it lazily also makes the ordering a fact a unit test can hold: a
/// closure that records whether it ran needs no database, no seal and no
/// inspector double.
#[must_use]
pub fn seal_finding(
    status: &dpp_types::SealValidationStatus,
    archival_freshness: impl FnOnce() -> dpp_types::ArchivalFreshness,
    now: chrono::DateTime<chrono::Utc>,
) -> SealFinding {
    if status.indication == dpp_types::ValidationIndication::TotalFailed {
        return SealFinding::CertificateFailed;
    }
    let freshness = archival_freshness();
    SealFinding::Sound {
        finding: renewal_finding(&freshness, now),
        expires: expiry_of(&freshness),
    }
}

/// Record a passport as needing renewal, up to the naming cap.
///
/// Lapsed and due share the list because they share the action. The counts stay
/// exact after it stops filling, which is the arrangement `broken_passports`
/// already uses — "this many, and here are the first hundred".
fn name_for_renewal(audit: &mut SealAudit, passport_id: dpp_domain::passport::PassportId) {
    if audit.renewal_passports.len() < MAX_NAMED_BROKEN {
        audit.renewal_passports.push(passport_id);
    }
}

pub async fn audit_seals_once(
    outbox: &Arc<dyn SealOutbox>,
    inspector: &dyn dpp_types::SealInspector,
    limit: i64,
    after: Option<dpp_domain::passport::PassportId>,
    sealed_before: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<(SealAudit, Option<dpp_domain::passport::PassportId>)> {
    let batch = match outbox.sealed_passports(limit, after, sealed_before).await {
        Ok(b) => b,
        // `None`, not an empty pass. An empty *batch* is how a walk says it
        // reached the end, so returning one here would tell the caller the
        // estate had been covered — and on the first batch of a walk, where the
        // cursor is `None` too, that published a completed report saying zero
        // seals were checked and none were broken.
        //
        // A database blip must not produce a clean bill of health from a check
        // that never ran. The caller keeps its cursor and tries again.
        Err(e) => {
            tracing::warn!(error = %e, "seal audit could not read stored seals");
            return None;
        }
    };

    // An empty batch means the walk reached the end; the caller restarts it.
    let cursor = batch.last().map(|p| p.passport_id);
    let mut audit = SealAudit::default();

    for row in &batch {
        audit.checked += 1;
        let binding = inspector.binding(&row.seal, &row.payload_hash);
        match &binding {
            dpp_types::SealBinding::CoversThisSignature => {
                // The signature holds; the certificate behind it is a separate
                // question, and one nothing asked until now. A seal made under a
                // certificate its CA had already revoked covers its passport
                // perfectly and is worth nothing.
                let now = chrono::Utc::now();
                let certificate = inspector.certificate_standing(&row.seal, now);
                let status = dpp_types::SealValidationStatus::of(&binding, certificate.as_ref());

                // 🚨 The archival read is passed as a closure, not a value, so
                // it is never performed for a seal whose certificate failed. It
                // re-parses the CMS and verifies every archive timestamp it
                // carries — not a cost to pay on a seal already known to be
                // worthless, on every pass, forever.
                //
                // A seal below `B-LTA` was never promised long-term protection,
                // so `NotArchived` is silence rather than a finding — the same
                // distinction `ArchivalFreshness` draws for the read route.
                let (finding, expires) = match seal_finding(
                    &status,
                    || inspector.archival_freshness(&row.seal, now),
                    now,
                ) {
                    SealFinding::CertificateFailed => {
                        audit.certificate_failed += 1;
                        tracing::error!(
                            passport_id = %row.passport_id,
                            sub_indication = ?status.sub_indication,
                            "a stored seal's certificate was not valid when the seal was made — \
                             the seal covers its passport and carries no weight. Re-sealing does \
                             not help: the replacement would come from the same certificate"
                        );
                        // Nothing further is asked of it — see `seal_finding`.
                        // Renewal advice about a seal whose certificate was
                        // already revoked is advice about the wrong problem.
                        continue;
                    }
                    SealFinding::Sound { finding, expires } => {
                        audit.sound += 1;
                        (finding, expires)
                    }
                };

                match finding {
                    RenewalFinding::Nothing => {}
                    RenewalFinding::Due => {
                        audit.archival_due += 1;
                        name_for_renewal(&mut audit, row.passport_id);
                        tracing::warn!(
                            passport_id = %row.passport_id,
                            expires = ?expires,
                            "a stored seal's archival protection expires soon — renewing it \
                             before it lapses is routine; afterwards the seal stops being \
                             verifiable past its signing certificate"
                        );
                    }
                    RenewalFinding::Lapsed => {
                        audit.archival_lapsed += 1;
                        name_for_renewal(&mut audit, row.passport_id);
                        tracing::error!(
                            passport_id = %row.passport_id,
                            expires = ?expires,
                            "a stored seal's archival protection has lapsed — the seal still \
                             verifies, and no longer carries what B-LTA exists to provide"
                        );
                    }
                    RenewalFinding::Unverifiable => {
                        audit.archival_unverifiable += 1;
                        tracing::error!(
                            passport_id = %row.passport_id,
                            "a stored seal carries an archive timestamp this node cannot use — \
                             it does not parse, or it is not a timestamp of this seal. Not a \
                             renewal candidate: there is no protection here to carry forward"
                        );
                    }
                }
            }
            dpp_types::SealBinding::CoversAnotherDigest { .. } => audit.superseded += 1,
            dpp_types::SealBinding::NotIntact => {
                audit.broken += 1;
                if audit.broken_passports.len() < MAX_NAMED_BROKEN {
                    audit.broken_passports.push(row.passport_id);
                }
                tracing::error!(
                    passport_id = %row.passport_id,
                    "stored seal does not verify — this passport is published and, in \
                     substance, unsealed. It is invisible to `unsealedPublished`, which asks \
                     only whether a seal is present"
                );
            }
            dpp_types::SealBinding::Unknown => audit.unreadable += 1,
        }
    }

    // No gauge here, deliberately. This function sees **one batch**, and a gauge
    // set from a batch flaps: three after a batch carrying three, zero after the
    // next clean one, on an estate where both are true at once. The quantity an
    // operator can act on is "broken seals in the last complete pass", which
    // only the caller owning the walk can know — see `spawn_seal_audit`.
    Some((audit, cursor))
}

/// Refuse a seal that does not cover the digest it was bought for.
///
/// `Some(reason)` means do not store it.
///
/// # Why this one refuses where `report_shortfall` only warns
///
/// The two failures look similar and are not. A downgraded seal is still a seal
/// **over the right passport** — weaker than ordered, but real, and re-buying
/// gets the same weak thing, so warning and keeping it is right.
///
/// A seal over the wrong digest is not a seal for this passport at all. Storing
/// it would leave a passport that *looks* sealed and is not, and the read route
/// would report it as `coversAnotherDigest` — indistinguishable from the
/// ordinary case of a passport re-published after sealing. A provider error
/// would arrive disguised as routine staleness.
///
/// So it is not stored. The row backs off and eventually exhausts, and the
/// passport stays in `unsealedPublished`, which is the honest state and one the
/// rollup already surfaces.
///
/// # What is deliberately not refused
///
/// `Unknown` — a placeholder, or a format this node does not parse. "Cannot
/// check" must never become "reject", or the first backend emitting something
/// other than CAdES would be unable to seal anything at all.
///
/// The check runs through the same `CadesInspector` the read route uses, so the
/// drain and the route cannot come to disagree about what covering means.
fn covers_something_else(envelope: &SealedEnvelope, requested: &str) -> Option<String> {
    use dpp_types::SealInspector as _;

    match dpp_seal::CadesInspector::new().binding(envelope, requested) {
        dpp_types::SealBinding::CoversThisSignature | dpp_types::SealBinding::Unknown => None,
        dpp_types::SealBinding::CoversAnotherDigest { covered } => {
            Some(format!("it covers {covered}"))
        }
        dpp_types::SealBinding::NotIntact => Some("its signature does not verify".to_owned()),
    }
}

/// Say so when a seal carries less than was asked for.
///
/// Until now nothing looked at what came back. The request names a level, the
/// boot gate checks that level against the backend's *advertised* capabilities,
/// and the returned bytes were taken on trust. A provider answering
/// `CAdES_BASELINE_T` to a request for `LT` — a client enabled for the wrong
/// profile, a plan change, a provider-side default — produced a seal that was
/// correct in every record this node kept, and that stops verifying when the
/// signing certificate expires, years after the passport was retention-locked.
///
/// # Why this only warns
///
/// The seal exists and has been billed. Failing the row would retry and buy the
/// same wrong thing again, so the shortfall is reported and the row closes
/// normally. That is the same reasoning as the `mark_sealed` failure path above,
/// reached from the opposite direction: there the seal is right and the record
/// failed, here the record will be right and the seal is weaker than ordered.
/// Neither is fixed by re-buying.
///
/// Silence on the happy path is deliberate. A drain that logged every seal's
/// level would bury the one line that matters under one per passport.
fn report_shortfall(
    envelope: &SealedEnvelope,
    requested: SealConformanceLevel,
    passport_id: &dpp_domain::passport::PassportId,
) {
    // A placeholder is not a seal, so there is nothing to fall short of.
    if envelope.placeholder {
        return;
    }

    let Ok(der) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &envelope.seal_value,
    ) else {
        // Unreadable here means unreadable everywhere, and the seal route says
        // as much through a null `signingCertRef`. Not this function's alarm to
        // raise.
        return;
    };

    let Ok(Some(evidenced)) = dpp_seal::cades::evidenced_level(&der) else {
        return;
    };

    // Ordering by what actually matters rather than by enum position: the
    // question is whether the seal outlives its signing certificate, and that is
    // the line `SealConformanceLevel` itself draws. A `B`-for-`T` substitution is
    // real but survivable; a `T`-for-`LT` one is the permanent kind.
    if requested.survives_certificate_expiry() && !evidenced.survives_certificate_expiry() {
        // Its own counter, not another `seal_total` outcome. That label is a
        // partition — a row is sealed *or* retried *or* exhausted — and a
        // downgraded row is a `sealed` row as well, so adding it there would
        // make `sum(seal_total)` exceed the rows drained and quietly corrupt
        // every ratio built on it.
        metrics::counter!("seal_downgraded_total").increment(1);
        tracing::error!(
            passport_id = %passport_id,
            requested = ?requested,
            evidenced = ?evidenced,
            "sealed below the requested level: this seal carries no long-term validation \
             material and will stop verifying when its signing certificate expires. The \
             passport is retention-locked, so it cannot be re-sealed — check the profile \
             enabled for this client with the provider"
        );
    } else if evidenced != requested {
        tracing::warn!(
            passport_id = %passport_id,
            requested = ?requested,
            evidenced = ?evidenced,
            "the seal's material does not match the level requested"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dpp_domain::{
        DppError,
        passport::PassportId,
        seal::{SealCapabilities, SealVerification, SealedEnvelope},
    };
    use dpp_types::{SealOutboxCounts, SealRow};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeOutbox {
        rows: Mutex<Vec<SealRow>>,
        sealed: Mutex<Vec<uuid::Uuid>>,
        failed: Mutex<Vec<String>>,
        exhausted: Mutex<Vec<String>>,
        /// Forces `mark_sealed` to fail — the produced-but-unrecorded path.
        record_fails: bool,
    }

    #[async_trait]
    impl SealOutbox for FakeOutbox {
        async fn enqueue(&self, _p: PassportId, _h: &str) -> Result<(), DppError> {
            Ok(())
        }
        async fn enqueue_unsealed(&self, _limit: i64, _cooldown: i64) -> Result<u64, DppError> {
            // The sweep is exercised against real Postgres, where the candidate
            // query is the part worth testing; these tests are about the drain.
            Ok(0)
        }
        async fn due(&self, _limit: i64) -> Result<Vec<SealRow>, DppError> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn mark_sealed(&self, id: uuid::Uuid, _e: &SealedEnvelope) -> Result<(), DppError> {
            if self.record_fails {
                return Err(DppError::Internal("db down".into()));
            }
            self.sealed.lock().unwrap().push(id);
            Ok(())
        }
        async fn sealed_digest(&self, _p: PassportId) -> Result<Option<String>, DppError> {
            // Read back by the seal route, never by the drain.
            Ok(None)
        }
        async fn mark_attempt_failed(
            &self,
            _id: uuid::Uuid,
            message: String,
        ) -> Result<(), DppError> {
            self.failed.lock().unwrap().push(message);
            Ok(())
        }
        async fn mark_exhausted(&self, _id: uuid::Uuid, message: String) -> Result<(), DppError> {
            self.exhausted.lock().unwrap().push(message);
            Ok(())
        }
        async fn status_counts(&self) -> Result<SealOutboxCounts, DppError> {
            Ok(SealOutboxCounts::default())
        }

        async fn sealed_passports(
            &self,
            _limit: i64,
            _after: Option<PassportId>,
            _sealed_before: Option<chrono::DateTime<chrono::Utc>>,
        ) -> Result<Vec<dpp_types::SealedPassport>, DppError> {
            Ok(Vec::new())
        }
        async fn rearm_sealed(&self, _p: PassportId, _h: &str, _r: &str) -> Result<bool, DppError> {
            unreachable!("the drain never repairs")
        }
        async fn unsealed_published_count(&self) -> Result<i64, DppError> {
            // These tests drive the drain, which never asks. A passport-level
            // count has no meaning against a fake holding only rows.
            Ok(0)
        }
    }

    struct FakeSeal {
        fail: bool,
        /// Digests the port was actually asked to seal.
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl SealPort for FakeSeal {
        async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, DppError> {
            self.seen.lock().unwrap().push(req.payload_hash.clone());
            if self.fail {
                return Err(DppError::Internal("qtsp unreachable".into()));
            }
            Ok(SealedEnvelope {
                format: SealFormat::Cades,
                seal_value: "p7s".into(),
                signing_cert_ref: None,
                // Not recorded: this fixture asserts nothing about the level.
                conformance_level: None,
                sealed_at: chrono::Utc::now(),
                placeholder: false,
            })
        }
        async fn verify(&self, _e: &SealedEnvelope) -> Result<SealVerification, DppError> {
            unreachable!("the drain never verifies")
        }
        fn capabilities(&self) -> SealCapabilities {
            SealCapabilities {
                supported_formats: vec![SealFormat::Cades],
                supported_modes: vec![SealMode::ProviderSeal],
                supported_levels: SealConformanceLevel::ALL.to_vec(),
                supported_envelopes: vec![SealEnvelope::Detached],
            }
        }
    }

    /// Stands in for whatever the composition root resolved the backend to.
    /// Nothing in the drain reads it, which is exactly why it must not be named
    /// here in production code either.
    fn test_key_ref() -> SealCredentialRef {
        SealCredentialRef {
            qtsp_id: "test-provider".to_owned(),
            credential_id: "test-client".to_owned(),
        }
    }

    fn row(attempts: i32) -> SealRow {
        SealRow {
            id: uuid::Uuid::now_v7(),
            passport_id: PassportId::new(),
            payload_hash: "ab".repeat(32),
            attempts,
        }
    }

    fn fakes(fail: bool, record_fails: bool, attempts: i32) -> (Arc<FakeOutbox>, Arc<FakeSeal>) {
        let outbox = Arc::new(FakeOutbox {
            rows: Mutex::new(vec![row(attempts)]),
            record_fails,
            ..Default::default()
        });
        let seal = Arc::new(FakeSeal {
            fail,
            seen: Mutex::new(Vec::new()),
        });
        (outbox, seal)
    }

    #[tokio::test]
    async fn a_successful_seal_closes_the_row() {
        let (outbox, seal) = fakes(false, false, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal.clone() as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.sealed, 1);
        assert_eq!(outbox.sealed.lock().unwrap().len(), 1);
    }

    /// A backend that seals below the requested level still closes the row.
    ///
    /// The shortfall is reported, and that is *all* it does. The seal exists and
    /// has been billed, so failing the row would back it off and buy the same
    /// **A seal over the wrong digest is not stored, however well-formed it is.**
    ///
    /// A provider answering with a seal over some other document — a mix-up, a
    /// request crossed with another client's, a bug — used to be written onto
    /// the passport unexamined, because nothing compared what came back against
    /// what was asked for. The passport would then *look* sealed while carrying
    /// an attestation about something else, and the read route would call it
    /// `coversAnotherDigest`, which is indistinguishable from the ordinary case
    /// of a passport re-published after sealing. A provider error would arrive
    /// disguised as routine staleness.
    ///
    /// Refused, unlike a downgrade: a weak seal still covers the right passport
    /// and re-buying gets the same weak thing, whereas this is not a seal for
    /// this passport at all. The row backs off and the passport stays in
    /// `unsealedPublished`, which is true.
    ///
    /// Real CAdES bytes again, over a genuinely different digest — a stub would
    /// exercise the unreadable path, which is the one case deliberately allowed
    /// through.
    #[tokio::test]
    async fn a_seal_over_the_wrong_digest_is_refused_rather_than_stored() {
        struct WrongDigest(String);

        #[async_trait]
        impl SealPort for WrongDigest {
            async fn seal(&self, _req: SealRequest) -> Result<SealedEnvelope, DppError> {
                Ok(SealedEnvelope {
                    format: SealFormat::Cades,
                    seal_value: self.0.clone(),
                    signing_cert_ref: None,
                    conformance_level: Some(SealConformanceLevel::BaselineB),
                    sealed_at: chrono::Utc::now(),
                    placeholder: false,
                })
            }
            async fn verify(&self, _e: &SealedEnvelope) -> Result<SealVerification, DppError> {
                unreachable!("the drain never verifies")
            }
            fn capabilities(&self) -> SealCapabilities {
                SealCapabilities {
                    supported_formats: vec![SealFormat::Cades],
                    supported_modes: vec![SealMode::ProviderSeal],
                    supported_levels: SealConformanceLevel::ALL.to_vec(),
                    supported_envelopes: vec![SealEnvelope::Detached],
                }
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let identity =
            dpp_seal::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        // Sealed over a digest that is emphatically not the row's.
        let der = identity.sign_detached(&[0x99; 32]).expect("sign");
        let elsewhere = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);

        let outbox = Arc::new(FakeOutbox {
            rows: Mutex::new(vec![row(0)]),
            ..Default::default()
        });
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(Arc::new(WrongDigest(elsewhere)) as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineB,
            10,
        )
        .await;

        assert_eq!(stats.sealed, 0, "it must not be recorded as a sealed row");
        assert!(
            outbox.sealed.lock().unwrap().is_empty(),
            "and nothing may be written onto the passport"
        );
        assert_eq!(stats.retried, 1);
        assert!(
            outbox.failed.lock().unwrap()[0].contains("does not cover the requested digest"),
            "the reason must name the mismatch, not a transport failure: {:?}",
            outbox.failed.lock().unwrap()
        );
    }

    /// An unreadable seal is stored, because "cannot check" is not "reject".
    ///
    /// The line the check must not cross. A backend emitting a format this node
    /// does not parse — JAdES, PAdES — would otherwise be unable to seal
    /// anything at all, refused by a check that never ran rather than by a
    /// finding.
    #[tokio::test]
    async fn a_seal_this_node_cannot_read_is_still_stored() {
        let (outbox, seal) = fakes(false, false, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(
            stats.sealed, 1,
            "an envelope whose coverage cannot be determined must still be recorded"
        );
    }

    /// The audit names a broken seal that every existing count calls healthy.
    ///
    /// The whole point of the pass. Both `enqueue_unsealed` and
    /// `unsealed_published_count` ask whether the `seal` member is absent, so a
    /// passport carrying a seal that does not verify is swept by neither and
    /// counted by neither — it looks fine in every number the node reports.
    ///
    /// The three non-findings are checked in the same run, because each is a way
    /// this could become a nuisance rather than a signal: a sound seal, a
    /// superseded one (an ordinary re-publish, which the sweep deliberately
    /// leaves alone), and one this node cannot read.
    #[tokio::test]
    async fn the_audit_separates_a_broken_seal_from_the_three_things_that_are_not() {
        struct Stored(Vec<dpp_types::SealedPassport>);

        #[async_trait]
        impl SealOutbox for Stored {
            async fn sealed_passports(
                &self,
                _limit: i64,
                _after: Option<PassportId>,
                _sealed_before: Option<chrono::DateTime<chrono::Utc>>,
            ) -> Result<Vec<dpp_types::SealedPassport>, DppError> {
                Ok(self.0.clone())
            }
            async fn rearm_sealed(
                &self,
                _p: PassportId,
                _h: &str,
                _r: &str,
            ) -> Result<bool, DppError> {
                unreachable!("the audit must not repair")
            }
            async fn enqueue(&self, _p: PassportId, _h: &str) -> Result<(), DppError> {
                unreachable!("the audit must not queue anything")
            }
            async fn enqueue_unsealed(&self, _l: i64, _c: i64) -> Result<u64, DppError> {
                unreachable!("the audit must not queue anything")
            }
            async fn due(&self, _l: i64) -> Result<Vec<SealRow>, DppError> {
                Ok(Vec::new())
            }
            async fn mark_sealed(
                &self,
                _i: uuid::Uuid,
                _e: &SealedEnvelope,
            ) -> Result<(), DppError> {
                unreachable!("the audit must not write")
            }
            async fn sealed_digest(&self, _p: PassportId) -> Result<Option<String>, DppError> {
                Ok(None)
            }
            async fn mark_attempt_failed(
                &self,
                _i: uuid::Uuid,
                _m: String,
            ) -> Result<(), DppError> {
                unreachable!("the audit must not write")
            }
            async fn mark_exhausted(&self, _i: uuid::Uuid, _m: String) -> Result<(), DppError> {
                unreachable!("the audit must not write")
            }
            async fn status_counts(&self) -> Result<dpp_types::SealOutboxCounts, DppError> {
                Ok(dpp_types::SealOutboxCounts::default())
            }
            async fn unsealed_published_count(&self) -> Result<i64, DppError> {
                Ok(0)
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let id = dpp_seal::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let digest = [0x11; 32];
        let hex_digest = hex::encode(digest);
        let sound = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            id.sign_detached(&digest).expect("sign"),
        );

        // One byte of the signature flipped: the structure is intact, so it
        // parses and reaches the signature check, and fails it.
        let corrupted = {
            use der::{Decode as _, Encode as _};
            let der_bytes = id.sign_detached(&digest).expect("sign");
            let info = cms::content_info::ContentInfo::from_der(&der_bytes).expect("CMS");
            let mut sd: cms::signed_data::SignedData =
                info.content.decode_as().expect("SignedData");
            let mut signers = sd.signer_infos.0.as_slice().to_vec();
            let mut bytes = signers[0].signature.as_bytes().to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            signers[0].signature = der::asn1::OctetString::new(bytes).expect("octets");
            let mut set = der::asn1::SetOfVec::new();
            set.insert(signers.remove(0)).expect("signer");
            sd.signer_infos = cms::signed_data::SignerInfos::from(set);
            let rebuilt = cms::content_info::ContentInfo {
                content_type: info.content_type,
                content: der::Any::encode_from(&sd).expect("encode"),
            }
            .to_der()
            .expect("re-encode");
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &rebuilt)
        };

        let envelope = |value: String, placeholder: bool| SealedEnvelope {
            format: SealFormat::Cades,
            seal_value: value,
            signing_cert_ref: None,
            conformance_level: Some(SealConformanceLevel::BaselineB),
            sealed_at: chrono::Utc::now(),
            placeholder,
        };
        let row = |seal: SealedEnvelope, hash: &str| dpp_types::SealedPassport {
            passport_id: PassportId::new(),
            seal,
            payload_hash: hash.to_owned(),
        };

        let outbox: Arc<dyn SealOutbox> = Arc::new(Stored(vec![
            // Sound: covers the digest it is asked about.
            row(envelope(sound.clone(), false), &hex_digest),
            // Superseded: intact, over a different digest. An ordinary
            // re-publish, and not a finding.
            row(envelope(sound.clone(), false), &hex::encode([0x22; 32])),
            // Broken: a real seal whose signature has been corrupted. It must
            // still *parse* — garbage bytes are `unknown`, correctly, because
            // nothing could be checked, and that is a different finding.
            row(envelope(corrupted.clone(), false), &hex_digest),
            // Unreadable: a placeholder carries no certificate to check.
            row(envelope("Z2hvc3Q=".to_owned(), true), &hex_digest),
        ]));

        let (audit, cursor) =
            audit_seals_once(&outbox, &dpp_seal::CadesInspector::new(), 100, None, None)
                .await
                .expect("the batch is readable");

        assert_eq!(audit.checked, 4);
        assert_eq!(audit.sound, 1);
        assert_eq!(audit.superseded, 1, "a re-publish is not a broken seal");
        assert_eq!(
            audit.unreadable, 1,
            "a placeholder is not a broken seal either"
        );
        assert_eq!(
            audit.broken, 1,
            "the one finding: a seal that reads and does not verify"
        );
        assert!(cursor.is_some(), "the walk must hand back a cursor");
    }

    /// weaker seal again on the next pass — paying twice to record the problem
    /// twice. The same reasoning as the produced-but-unrecorded path, reached
    /// from the other side.
    ///
    /// Real CAdES bytes from the local backend rather than a stub: the check
    /// reads unsigned attributes out of a CMS structure, so a placeholder string
    /// would exercise the early return and prove nothing about the shortfall
    /// path. Those bytes carry no timestamp and no revocation material, which is
    /// exactly a `B` answer to an `LT` request.
    #[tokio::test]
    async fn a_seal_below_the_requested_level_is_still_recorded() {
        struct Downgrades(String);

        #[async_trait]
        impl SealPort for Downgrades {
            async fn seal(&self, _req: SealRequest) -> Result<SealedEnvelope, DppError> {
                Ok(SealedEnvelope {
                    format: SealFormat::Cades,
                    seal_value: self.0.clone(),
                    signing_cert_ref: None,
                    // Not recorded: this fixture asserts nothing about the level.
                    conformance_level: None,
                    sealed_at: chrono::Utc::now(),
                    placeholder: false,
                })
            }
            async fn verify(&self, _e: &SealedEnvelope) -> Result<SealVerification, DppError> {
                unreachable!("the drain never verifies")
            }
            fn capabilities(&self) -> SealCapabilities {
                SealCapabilities {
                    supported_formats: vec![SealFormat::Cades],
                    supported_modes: vec![SealMode::ProviderSeal],
                    supported_levels: SealConformanceLevel::ALL.to_vec(),
                    supported_envelopes: vec![SealEnvelope::Detached],
                }
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let identity =
            dpp_seal::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        // Over the digest the row actually asks for. A double that sealed some
        // other digest would now be refused before the level is ever considered
        // — correctly, and it would make this test assert the wrong refusal.
        let requested = row(0).payload_hash;
        let der = identity
            .sign_detached(&hex::decode(&requested).expect("the row's digest is hex"))
            .expect("sign");
        let b_level = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);

        assert_eq!(
            dpp_seal::cades::evidenced_level(&der).unwrap(),
            Some(SealConformanceLevel::BaselineB),
            "the fixture must actually be a downgrade, or this test asserts nothing"
        );

        let outbox = Arc::new(FakeOutbox {
            rows: Mutex::new(vec![SealRow {
                payload_hash: requested,
                ..row(0)
            }]),
            ..Default::default()
        });
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(Arc::new(Downgrades(b_level)) as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.sealed, 1, "a downgraded seal is still a sealed row");
        assert_eq!(
            stats.retried, 0,
            "re-buying would cost twice and fix nothing"
        );
        assert_eq!(outbox.sealed.lock().unwrap().len(), 1);
        assert!(outbox.failed.lock().unwrap().is_empty());
    }

    /// The row's stored digest is what gets sealed — never one re-derived from
    /// whatever the passport says at drain time.
    #[tokio::test]
    async fn the_rows_digest_is_what_is_sealed() {
        let (outbox, seal) = fakes(false, false, 0);
        let expected = outbox.rows.lock().unwrap()[0].payload_hash.clone();

        drain_once(
            &(outbox as Arc<dyn SealOutbox>),
            &(seal.clone() as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(seal.seen.lock().unwrap().as_slice(), &[expected]);
    }

    #[tokio::test]
    async fn a_qtsp_failure_backs_off_rather_than_dropping_the_row() {
        let (outbox, seal) = fakes(true, false, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.retried, 1);
        assert_eq!(stats.sealed, 0);
        assert!(outbox.exhausted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_attempt_cap_exhausts_the_row() {
        let (outbox, seal) = fakes(true, false, MAX_ATTEMPTS - 1);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.exhausted, 1);
        assert_eq!(outbox.exhausted.lock().unwrap().len(), 1);
    }

    /// A seal that was produced but could not be recorded must leave the row
    /// open: dropping it would lose a paid-for seal permanently, which is worse
    /// than the retry that may buy a second one.
    #[tokio::test]
    async fn a_seal_that_cannot_be_recorded_leaves_the_row_open() {
        let (outbox, seal) = fakes(false, true, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealMode::ProviderSeal,
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.sealed, 0);
        assert_eq!(stats.retried, 1);
        assert!(
            outbox.failed.lock().unwrap()[0].contains("seal recorded failed"),
            "the reason must name the recording failure, not the QTSP"
        );
    }
}

#[cfg(test)]
mod renewal_tests {
    use super::*;
    use dpp_types::ArchivalFreshness;

    fn at(days: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::days(days)
    }

    /// The lead time is a boundary, and a boundary is where it gets written
    /// backwards.
    ///
    /// A comparison the wrong way round has two failure modes and both are
    /// quiet: every healthy seal reported as due, which an operator learns to
    /// ignore, or none ever reported, which they discover when protection has
    /// already gone. Neither shows up without pinning the two sides of the line.
    #[test]
    fn protection_is_due_inside_the_lead_time_and_not_outside_it() {
        let now = chrono::Utc::now();
        let lead = RENEWAL_LEAD.num_days();

        let comfortable = ArchivalFreshness::Current {
            expires: at(lead + 30),
        };
        assert_eq!(
            renewal_finding(&comfortable, now),
            RenewalFinding::Nothing,
            "protection with time left on it is not a finding"
        );

        let inside = ArchivalFreshness::Current {
            expires: at(lead - 1),
        };
        assert_eq!(
            renewal_finding(&inside, now),
            RenewalFinding::Due,
            "protection expiring inside the lead time is what the window is for"
        );

        // 🚨 Exactly on the line, and built from `now` rather than from `at()`,
        // which reads the clock again and would land a few microseconds past it
        // — testing the inside case a second time instead of the boundary.
        //
        // The comparison is `expires - now > RENEWAL_LEAD`, so equality falls
        // through to `Due`. That is the side to be on: a seal whose protection
        // expires in exactly the lead time is the first one the window was drawn
        // to catch, and `>=` here would let it pass unreported for a day.
        let exactly_on_the_lead = ArchivalFreshness::Current {
            expires: now + RENEWAL_LEAD,
        };
        assert_eq!(
            renewal_finding(&exactly_on_the_lead, now),
            RenewalFinding::Due,
            "the lead time is inclusive — protection expiring exactly then is due"
        );

        let gone = ArchivalFreshness::Lapsed { expires: at(-1) };
        assert_eq!(renewal_finding(&gone, now), RenewalFinding::Lapsed);
    }

    /// A seal whose certificate failed is never a renewal candidate.
    ///
    /// 🚨 The two questions arrive together and only one of them is worth
    /// asking. A seal made under a certificate that was already revoked, and
    /// whose archive timestamp is also lapsing, has exactly one problem —
    /// renewing the timestamp would leave it as worthless as it is now, and
    /// would spend a real timestamp doing it.
    ///
    /// This is pinned as a *pure* decision because it was written the other way
    /// once: the loop recorded `certificate_failed` and then fell through to the
    /// archival block, so such a seal was counted in `archival_due` and named in
    /// `renewal_passports` as well. The lapsed freshness below is what makes the
    /// test bite — with the fall-through restored, it reports `Sound(Lapsed)`.
    #[test]
    fn a_failed_certificate_ends_the_enquiry_before_the_archive_is_asked_about() {
        let now = chrono::Utc::now();
        let failed = dpp_types::SealValidationStatus {
            indication: dpp_types::ValidationIndication::TotalFailed,
            sub_indication: Some(dpp_types::ValidationSubIndication::Revoked),
        };

        for freshness in [
            ArchivalFreshness::Lapsed { expires: at(-1) },
            ArchivalFreshness::Current {
                expires: at(RENEWAL_LEAD.num_days() - 1),
            },
            ArchivalFreshness::Unknown,
            ArchivalFreshness::NotArchived,
        ] {
            // 🚨 The closure records whether it ran, which is how the *call
            // order* is pinned rather than only the answer. With the freshness
            // passed by value the counts were right and the work was still done
            // — and that work verifies the signature on every archive timestamp
            // the seal carries.
            let asked = std::cell::Cell::new(false);

            assert_eq!(
                seal_finding(
                    &failed,
                    || {
                        asked.set(true);
                        freshness.clone()
                    },
                    now
                ),
                SealFinding::CertificateFailed,
                "a failed certificate is the whole finding, whatever the archive says: \
                 {freshness:?}"
            );
            assert!(
                !asked.get(),
                "and the archive is not even asked — the enquiry ended at the certificate"
            );
        }
    }

    /// Every field a batch can carry reaches the walk.
    ///
    /// 🚨 This is the test for a bug that shipped as *silence*. A walk is many
    /// batches, and the report, the gauges and the saved progress all read the
    /// accumulator. The node's audit loop folded the batch in field by field,
    /// and when `SealAudit` grew the archival counts the loop was not extended —
    /// so every one of them was computed per batch and dropped. A completed pass
    /// reported zero lapsed, zero due, zero unverifiable and named nobody, which
    /// is exactly what a healthy estate reports. Nothing failed, no test went
    /// red, and the feature was inert.
    ///
    /// Two halves make that unrepeatable. `absorb` destructures without `..`, so
    /// a new field stops it compiling; and this test builds its batch as an
    /// exhaustive literal, so a new field stops *this* compiling too — and the
    /// next person has to decide, at the keyboard, what the running total of it
    /// should be.
    #[test]
    fn every_field_of_a_batch_reaches_the_walk() {
        let broken = dpp_domain::passport::PassportId::new();
        let renewal = dpp_domain::passport::PassportId::new();

        // Every count distinct, so a field folded into the wrong one is visible
        // rather than hidden behind two equal numbers.
        let batch = SealAudit {
            checked: 11,
            sound: 7,
            certificate_failed: 3,
            superseded: 5,
            broken: 2,
            unreadable: 1,
            broken_passports: vec![broken],
            archival_lapsed: 13,
            archival_due: 17,
            archival_unverifiable: 19,
            renewal_passports: vec![renewal],
        };

        let mut walk = SealAudit::default();
        walk.absorb(batch.clone());
        walk.absorb(batch);

        assert_eq!(walk.checked, 22);
        assert_eq!(walk.sound, 14);
        assert_eq!(walk.certificate_failed, 6);
        assert_eq!(walk.superseded, 10);
        assert_eq!(walk.broken, 4);
        assert_eq!(walk.unreadable, 2);
        assert_eq!(walk.archival_lapsed, 26);
        assert_eq!(walk.archival_due, 34);
        assert_eq!(
            walk.archival_unverifiable, 38,
            "the archival counts are the ones the loop dropped — all three of them"
        );
        assert_eq!(walk.broken_passports, vec![broken, broken]);
        assert_eq!(
            walk.renewal_passports,
            vec![renewal, renewal],
            "and the renewal list was dropped with them, so a report named nobody \
             to renew however many were due"
        );
    }

    /// The named lists stop at the cap; the counts behind them do not.
    ///
    /// That pairing is what makes "this many, and here are the first hundred"
    /// true of a whole walk rather than of one batch — and it has to hold in the
    /// accumulator, since no single batch is big enough to reach the cap.
    #[test]
    fn the_lists_stop_at_the_cap_while_the_counts_keep_going() {
        let batch = || SealAudit {
            broken: 1,
            broken_passports: vec![dpp_domain::passport::PassportId::new()],
            archival_due: 1,
            renewal_passports: vec![dpp_domain::passport::PassportId::new()],
            ..SealAudit::default()
        };

        let mut walk = SealAudit::default();
        for _ in 0..(MAX_NAMED_BROKEN + 25) {
            walk.absorb(batch());
        }

        assert_eq!(walk.broken_passports.len(), MAX_NAMED_BROKEN);
        assert_eq!(walk.renewal_passports.len(), MAX_NAMED_BROKEN);
        assert_eq!(
            walk.broken as usize,
            MAX_NAMED_BROKEN + 25,
            "the count is the size of the problem; the list is a sample of it"
        );
        assert_eq!(walk.archival_due as usize, MAX_NAMED_BROKEN + 25);
    }

    /// Anything short of a failure lets the archival question through unchanged.
    ///
    /// The other half of the ordering: `seal_finding` must not quietly become a
    /// second classifier. Whatever `renewal_finding` says about the freshness is
    /// what comes out.
    ///
    /// `Indeterminate` rather than a pass, because a pass is not reachable here:
    /// `TOTAL-PASSED` needs the whole of EN 319 102-1 clause 5.1.3, so a seal
    /// that survives every check this node makes still reports indeterminate —
    /// and that is what the audit counts as sound.
    #[test]
    fn anything_short_of_a_failure_reports_exactly_what_the_archive_says() {
        let now = chrono::Utc::now();
        let sound = dpp_types::SealValidationStatus {
            indication: dpp_types::ValidationIndication::Indeterminate,
            sub_indication: None,
        };

        for freshness in [
            ArchivalFreshness::Lapsed { expires: at(-1) },
            ArchivalFreshness::Current {
                expires: at(RENEWAL_LEAD.num_days() - 1),
            },
            ArchivalFreshness::Current {
                expires: at(RENEWAL_LEAD.num_days() + 30),
            },
            ArchivalFreshness::Unknown,
            ArchivalFreshness::NotArchived,
        ] {
            let asked = std::cell::Cell::new(false);

            assert_eq!(
                seal_finding(
                    &sound,
                    || {
                        asked.set(true);
                        freshness.clone()
                    },
                    now
                ),
                SealFinding::Sound {
                    finding: renewal_finding(&freshness, now),
                    expires: expiry_of(&freshness),
                },
                "the archival classification is the classifier's: {freshness:?}"
            );
            assert!(
                asked.get(),
                "and here the archive *is* asked — laziness must not become silence"
            );
        }
    }

    /// A seal below `B-LTA` is silent, not a finding.
    ///
    /// It was never promised long-term protection, and reporting it as needing
    /// renewal would raise an alarm about a commitment nobody made — the same
    /// distinction `ArchivalFreshness` draws between `NotArchived` and `Lapsed`,
    /// carried through to the estate-wide count.
    #[test]
    fn a_seal_below_lta_is_not_a_renewal_candidate() {
        assert_eq!(
            renewal_finding(&ArchivalFreshness::NotArchived, chrono::Utc::now()),
            RenewalFinding::Nothing
        );
    }

    /// An unusable archive timestamp is not something to renew.
    ///
    /// 🚨 The distinction this makes is the one the binding check created.
    /// `Unknown` now covers a token that parses and is **not a timestamp of this
    /// seal** — and renewing assumes there is protection to carry forward. Here
    /// there is none: the seal claims a level it does not have, which is a
    /// corruption finding and belongs beside `broken` rather than in a queue of
    /// things to re-stamp.
    #[test]
    fn an_unusable_archive_timestamp_is_not_renewed_but_reported() {
        assert_eq!(
            renewal_finding(&ArchivalFreshness::Unknown, chrono::Utc::now()),
            RenewalFinding::Unverifiable,
            "an archive timestamp that is not this seal's must not be queued for renewal"
        );
    }
}
