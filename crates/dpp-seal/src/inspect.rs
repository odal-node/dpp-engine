//! The [`SealInspector`] adapter — reading a stored seal's certificate.
//!
//! Answers one question for the services that serve seals: **did a provider
//! issue this, or did the node sign it itself?** That is a property of the
//! bytes, so it is the same answer whichever backend produced them, and this
//! adapter is consequently stateless and provider-agnostic.
//!
//! It sits here rather than in the consuming service because CMS and X.509
//! parsing belongs beside the code that produces seals — one home for
//! certificate handling, so two places cannot disagree about what a seal says.
//! [`dpp_types::SealInspector`] is the seam that keeps the consumer from having
//! to link this crate to ask.

use base64::Engine as _;
use dpp_domain::seal::{SealConformanceLevel, SealFormat, SealedEnvelope};
use dpp_types::{SealBinding, SealInspector, SealOrigin};

use crate::cades;

/// Reads CAdES seals.
///
/// Holds no credential and reaches no network — reading a certificate out of
/// bytes needs neither, and neither does asking a trusted list a question once
/// somebody else has fetched and verified it. Construct it with
/// [`CadesInspector::new`] wherever a [`SealInspector`] is wanted.
///
/// # The lists are given to it, never fetched by it
///
/// [`with_trusted_lists`](Self::with_trusted_lists) hands over an already
/// verified set. That keeps this adapter synchronous and offline, which matters
/// because [`SealInspector`] is called from read handlers: an inspector that
/// could fetch would put a multi-megabyte download on the path of a request
/// somebody is waiting on. Filling the set is a background job's work.
///
/// **Without them it still answers**, and the answer is honest rather than
/// absent: `IssuerStanding::NotListed` with `consulted: 0`, which says the
/// verdict is about nothing. That is what a node with the refresh switched off
/// reports for every provider seal.
///
/// # 🚨 The set is swappable, because a boot-time read is not enough
///
/// [`publish`](Self::publish) replaces the held set on a **live** inspector, and
/// a [`Clone`] of one shares it. That is deliberate: the composition root hands
/// one handle to the read path and keeps another for the background refresh, so
/// a completed pass reaches the verdicts of a node that is already running.
///
/// Without it the set is frozen at boot, and on a fresh deployment the first
/// pass runs *after* the read — so the node answers `consulted: 0` for ever,
/// until somebody restarts it for an unrelated reason. Every verdict would be
/// vacuous and nothing would say so beyond the count.
#[derive(Debug, Clone, Default)]
pub struct CadesInspector {
    /// The set to consult, replaceable while the node runs.
    ///
    /// `Arc<RwLock<Arc<..>>>` rather than a plain `RwLock`: the read path clones
    /// the inner `Arc` and drops the guard immediately, so a verdict is computed
    /// against a stable snapshot and never holds a lock across the work. The
    /// outer `Arc` is what lets a clone of this inspector see a publish.
    held: std::sync::Arc<std::sync::RwLock<std::sync::Arc<TrustedListSet>>>,
}

/// The two halves of a trusted-list snapshot, which travel together.
///
/// 🚨 One struct rather than two fields, so they cannot be replaced
/// independently. A node holding 26 of 27 lists that reported only the 26 would
/// answer "this issuer is on no list" for a perfectly qualified provider in the
/// twenty-seventh, and nothing in the verdict would distinguish that from a
/// genuine miss.
#[derive(Debug, Default)]
struct TrustedListSet {
    /// The national lists to consult, each already verified through a verified
    /// list of trusted lists.
    lists: Vec<crate::trustlist::VerifiedTrustedList>,
    /// The territories the list of trusted lists names and this node could not
    /// read — carried so the verdict can say how wide it is.
    unchecked: Vec<dpp_types::qualification::UncheckedTerritory>,
}

impl CadesInspector {
    /// A new inspector, holding no trusted lists.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consult these lists, and admit these territories as unread.
    ///
    /// The builder form of [`publish`](Self::publish), for a caller that has the
    /// set before it has an inspector.
    #[must_use]
    pub fn with_trusted_lists(
        self,
        lists: Vec<crate::trustlist::VerifiedTrustedList>,
        unchecked: Vec<dpp_types::qualification::UncheckedTerritory>,
    ) -> Self {
        self.publish(lists, unchecked);
        self
    }

    /// Replace the held set on a running inspector.
    ///
    /// Takes `&self` so the background refresh can call it through the same
    /// handle the read path holds. Publish only what a **completed** pass
    /// produced: a set from half the Union reads exactly like a set from all of
    /// it — the rule the seal audit already took in migration
    /// `ops/pg/0038_seal_audit_state.sql`, which keeps its report NULL until a
    /// walk reaches the end of the estate.
    ///
    /// 🚨 Both halves or neither — see [`TrustedListSet`].
    pub fn publish(
        &self,
        lists: Vec<crate::trustlist::VerifiedTrustedList>,
        unchecked: Vec<dpp_types::qualification::UncheckedTerritory>,
    ) {
        let next = std::sync::Arc::new(TrustedListSet { lists, unchecked });
        // A poisoned lock is not a reason to stop answering. The only writer is
        // this function and the only reader clones and leaves, so nothing here
        // can observe a half-written set — recovering the inner value keeps a
        // panic in some unrelated task from silently freezing the verdicts.
        let mut held = self
            .held
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *held = next;
    }

    /// How many lists and unchecked territories the held set carries.
    ///
    /// Test-only, and it exists because the two halves are not equally
    /// observable through a verdict: a self-issued seal short-circuits to
    /// `IssuerStanding::SelfIssued` before any list is consulted, so the `lists`
    /// half of a swap cannot be seen through `qualification` without a
    /// provider-issued certificate this crate cannot produce. Asserting the
    /// snapshot directly is honest about that, rather than dressing a
    /// half-observation up as a whole one.
    #[cfg(test)]
    fn held_counts(&self) -> (usize, usize) {
        let held = self.snapshot();
        (held.lists.len(), held.unchecked.len())
    }

    /// The set a verdict should be computed against, as a stable snapshot.
    fn snapshot(&self) -> std::sync::Arc<TrustedListSet> {
        self.held
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl SealInspector for CadesInspector {
    /// # What yields `None`
    ///
    /// A placeholder envelope, a format this adapter does not parse, a
    /// `sealValue` that is not base64, and bytes that are not readable CMS. All
    /// four are *not read* rather than a finding, which is why none of them
    /// fabricates a `SealOrigin` — a `self_issued` of either value would be a
    /// claim about a certificate nobody examined.
    ///
    /// An unreadable seal is logged at `warn`: a stored seal that will not parse
    /// is an anomaly worth investigating, and the caller only learns that the
    /// field is absent.
    fn origin(&self, envelope: &SealedEnvelope) -> Option<SealOrigin> {
        if envelope.placeholder {
            return None;
        }
        // Only CAdES here. The other formats in `SealFormat` are lawful and this
        // crate does not emit them; silently parsing one as CMS would either
        // fail confusingly or, worse, half-succeed.
        if envelope.format != SealFormat::Cades {
            tracing::debug!(
                format = ?envelope.format,
                "seal origin not read: this inspector reads CAdES only"
            );
            return None;
        }

        let der = match base64::engine::general_purpose::STANDARD.decode(&envelope.seal_value) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "stored seal value is not base64; origin not read");
                return None;
            }
        };

        match cades::signer_certificate(&der) {
            Ok(c) => Some(c.origin()),
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; origin not read");
                None
            }
        }
    }

    /// # The order of the two checks
    ///
    /// The signature is checked **first**, and a failure short-circuits without
    /// reporting a digest. The digest lives in an attribute inside that
    /// signature: reading it out of a seal whose signature does not verify and
    /// then comparing it would be comparing against a value anybody could have
    /// written, and reporting it would hand a caller a number that nothing
    /// vouches for.
    fn binding(&self, envelope: &SealedEnvelope, payload_hash: &str) -> SealBinding {
        let Some(der) = self.readable(envelope) else {
            return SealBinding::Unknown;
        };

        match cades::verify_against_embedded_certificate(&der) {
            Ok(true) => {}
            Ok(false) => return SealBinding::NotIntact,
            Err(e) => {
                // A seal carrying no signed attributes lands here: its digest is
                // not inside it and cannot be recovered from the envelope alone.
                // That is unknown, not broken.
                tracing::warn!(error = %e, "stored seal could not be checked; binding not read");
                return SealBinding::Unknown;
            }
        }

        let covered = match cades::covered_digest(&der) {
            Ok(Some(d)) => hex::encode(d),
            Ok(None) => return SealBinding::Unknown,
            Err(e) => {
                tracing::warn!(error = %e, "stored seal names no readable digest");
                return SealBinding::Unknown;
            }
        };

        // Compared case-insensitively on the hex rather than on bytes: the value
        // arrives as a string from an outbox row and a wire field, and a seal
        // that matched or not depending on who upper-cased it would be a very
        // confusing bug to meet.
        if covered.eq_ignore_ascii_case(payload_hash) {
            SealBinding::CoversThisSignature
        } else {
            SealBinding::CoversAnotherDigest { covered }
        }
    }
    fn evidenced_level(&self, envelope: &SealedEnvelope) -> Option<SealConformanceLevel> {
        let der = self.readable(envelope)?;
        match cades::evidenced_level(&der) {
            Ok(level) => level,
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; level not evidenced");
                None
            }
        }
    }
    fn attested_sealing_time(
        &self,
        envelope: &SealedEnvelope,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let der = self.readable(envelope)?;
        match cades::attested_sealing_time(&der) {
            Ok(at) => at,
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; no attested time");
                None
            }
        }
    }
    /// # What the lists are questioned about
    ///
    /// The token's own `genTime`, which [`cades::signature_timestamp_token`] has
    /// already checked — never [`SealedEnvelope::sealed_at`], this node's clock.
    /// Like [`Self::qualification`], this answers from the held snapshot and
    /// fetches nothing.
    fn timestamp_authority(
        &self,
        envelope: &SealedEnvelope,
    ) -> Option<dpp_types::qualification::TimestampStanding> {
        let der = self.readable(envelope)?;
        let held = self.snapshot();
        match crate::qualification::qualify_timestamp(&der, &held.lists, &held.unchecked) {
            Ok(standing) => Some(standing),
            // Not read, rather than a standing drawn from bytes nobody could
            // parse — see `qualification` for the same reasoning.
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; timestamp authority unknown");
                None
            }
        }
    }

    fn archival_freshness(
        &self,
        envelope: &SealedEnvelope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> dpp_types::ArchivalFreshness {
        let Some(der) = self.readable(envelope) else {
            return dpp_types::ArchivalFreshness::NotArchived;
        };
        match cades::archival_freshness(&der, now) {
            Ok(cades::ArchivalFreshness::NotArchived) => dpp_types::ArchivalFreshness::NotArchived,
            Ok(cades::ArchivalFreshness::Current { expires }) => {
                dpp_types::ArchivalFreshness::Current { expires }
            }
            Ok(cades::ArchivalFreshness::Lapsed { expires }) => {
                dpp_types::ArchivalFreshness::Lapsed { expires }
            }
            Ok(cades::ArchivalFreshness::Unknown) => dpp_types::ArchivalFreshness::Unknown,
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; archival state unknown");
                dpp_types::ArchivalFreshness::Unknown
            }
        }
    }

    /// # 🚨 The attested time is passed only when its authority qualifies
    ///
    /// The token's moment decides whether an out-of-window certificate is a
    /// failure (proven) or an open question (not), so a token whose authority
    /// nobody lists must not be allowed to settle it — a self-made token is a
    /// perfectly well-formed time. The moment reaches
    /// [`cades::certificate_standing`] only when the Trusted Lists say the
    /// authority was a qualified one **when it stamped**; in every other case,
    /// including *this node could not tell*, the certificate is judged against
    /// the node's own clock and reported as unproven.
    ///
    /// The time itself stays visible on the seal route either way — this gates
    /// what the time is *worth*, not whether it is shown.
    fn certificate_standing(
        &self,
        envelope: &SealedEnvelope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<dpp_types::CertificateStanding> {
        let der = self.readable(envelope)?;
        let held = self.snapshot();
        let trusted_time = match cades::signature_timestamp_token(&der) {
            Ok(Some(token))
                if crate::qualification::timestamp_standing(
                    &token,
                    &held.lists,
                    held.unchecked.len(),
                )
                .counts_as_proof_of_existence() =>
            {
                Some(token.gen_time())
            }
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; certificate standing unknown");
                return None;
            }
        };
        match cades::certificate_standing(&der, now, trusted_time) {
            Ok(standing) => Some(standing),
            // Nothing is reported rather than a standing built on a guess. A
            // seal that will not parse has no certificate to speak about, and
            // saying "not revoked, window unknown" would be an assurance drawn
            // from bytes nobody could read.
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; certificate standing unknown");
                None
            }
        }
    }

    /// # What the lists are questioned about
    ///
    /// `envelope.sealed_at`, not the present moment. A provider granted
    /// qualified status in 2029 was not qualified in 2027, and a present-tense
    /// check would certify a seal that never was; a provider withdrawn last week
    /// did not retroactively unmake the seals it issued. Art. 32(1)(b) asks
    /// about the time of sealing, and trusted lists carry the history to answer
    /// it.
    ///
    /// ⚠️ `sealed_at` is **this node's clock when the backend answered** — an
    /// unattested claim by the party that bought the seal. An attested time
    /// lives in the seal's own timestamp token and is read by
    /// [`cades::attested_sealing_time`]; feeding it here would make the verdict
    /// stronger, and is the other half of the timestamp-authority work that is
    /// tracked separately. Using the recorded time meanwhile is what the seal
    /// route already does for the certificate's validity window.
    fn qualification(
        &self,
        envelope: &SealedEnvelope,
    ) -> Option<dpp_types::qualification::SealQualification> {
        let der = self.readable(envelope)?;
        // Snapshot first, then compute: the guard is released before any of the
        // ASN.1 and signature work below, so a refresh publishing mid-verdict
        // never blocks a read and never changes the set underneath one.
        let held = self.snapshot();
        match crate::qualification::qualify(&der, &held.lists, &held.unchecked, envelope.sealed_at)
        {
            Ok(verdict) => Some(verdict),
            // Not read, rather than a verdict drawn from bytes nobody could
            // parse. `readable` has already refused what it can see — a
            // placeholder, a format this adapter does not parse, a `sealValue`
            // that is not base64 — so reaching here means the bytes decoded and
            // `signer_certificate`, inside `qualify`, could not read a CMS out
            // of them.
            Err(e) => {
                tracing::warn!(error = %e, "stored seal could not be read; qualification unknown");
                None
            }
        }
    }
}

/// A stored seal, renewed.
#[derive(Debug, Clone)]
pub struct RenewedEnvelope {
    /// The envelope to store: the same seal with one more archive timestamp, and
    /// everything the envelope records about it — `sealed_at`, the signing
    /// certificate reference, the level — exactly as it was. A renewal is not a
    /// re-seal.
    pub envelope: SealedEnvelope,
    /// When the protection it replaces would have ended.
    pub previous_expires: chrono::DateTime<chrono::Utc>,
    /// When the new protection ends.
    pub expires: chrono::DateTime<chrono::Utc>,
}

impl CadesInspector {
    /// Renew a stored seal's archive timestamp from `source`.
    ///
    /// # Who may stamp, and why this lives on the inspector
    ///
    /// Whether to accept an authority is a Trusted List question, and the
    /// inspector is what holds the lists — the same snapshot every verdict is read
    /// against, so a renewal and the seal route cannot disagree about who counts as
    /// qualified.
    ///
    /// With `require_qualified`, a stamp is kept only from an authority the lists
    /// name as a qualified timestamp authority **when it stamped**
    /// ([`TimestampStanding::QualifiedAtStamping`](dpp_types::qualification::TimestampStanding)).
    /// That is the production posture, and it is deliberately strict: an archive
    /// timestamp is the thing that keeps a retention-locked seal verifiable for
    /// years, and a stamp nobody can vouch for protects nothing while *looking*
    /// like protection — a seal that reads as freshly renewed and is not. A node
    /// that holds no lists therefore renews nothing under it, which is the safe
    /// direction. Without it, any authority whose token verifies is accepted, which
    /// is what a development node stamping with its own authority needs.
    ///
    /// # Errors
    ///
    /// See [`RenewalError`](crate::renewal::RenewalError). On every error the
    /// stored envelope is untouched: the result is a new value.
    pub async fn renew_archive_timestamp(
        &self,
        envelope: &SealedEnvelope,
        source: &dyn crate::timestamp_source::TimestampSource,
        now: chrono::DateTime<chrono::Utc>,
        require_qualified: bool,
    ) -> Result<RenewedEnvelope, crate::renewal::RenewalError> {
        let Some(der) = self.readable(envelope) else {
            return Err(crate::renewal::RenewalError::NotRenewable(
                "the stored seal is not a CAdES this node can read".to_owned(),
            ));
        };
        // Snapshot first, then work: the guard is released before any of the
        // network and signature work, so a refresh publishing mid-renewal never
        // blocks and never changes the set underneath one.
        let held = self.snapshot();
        let renewed = crate::renewal::renew_archive_timestamp(&der, source, now, |token| {
            let standing =
                crate::qualification::timestamp_standing(token, &held.lists, held.unchecked.len());
            if require_qualified && !standing.counts_as_proof_of_existence() {
                Err(standing)
            } else {
                Ok(())
            }
        })
        .await?;

        let mut next = envelope.clone();
        next.seal_value = base64::engine::general_purpose::STANDARD.encode(&renewed.seal_der);
        Ok(RenewedEnvelope {
            envelope: next,
            previous_expires: renewed.previous_expires,
            expires: renewed.expires,
        })
    }

    /// The seal's DER, when there is something readable to work with.
    ///
    /// Shared by both questions so they cannot disagree about which envelopes
    /// are worth opening — a placeholder that yielded no origin but did yield a
    /// binding would be incoherent.
    fn readable(&self, envelope: &SealedEnvelope) -> Option<Vec<u8>> {
        if envelope.placeholder || envelope.format != SealFormat::Cades {
            return None;
        }
        base64::engine::general_purpose::STANDARD
            .decode(&envelope.seal_value)
            .ok()
    }
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
