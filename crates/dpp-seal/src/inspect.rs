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
    /// it, which is the rule `0038` already took for the seal audit.
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

    fn certificate_standing(
        &self,
        envelope: &SealedEnvelope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<dpp_types::CertificateStanding> {
        let der = self.readable(envelope)?;
        match cades::certificate_standing(&der, now) {
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

impl CadesInspector {
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
mod tests {
    use super::*;
    use dpp_domain::seal::SealConformanceLevel;

    /// An envelope carrying `seal_value`, with everything else plausible.
    fn envelope(seal_value: String, format: SealFormat, placeholder: bool) -> SealedEnvelope {
        SealedEnvelope {
            format,
            seal_value,
            signing_cert_ref: None,
            conformance_level: Some(SealConformanceLevel::BaselineB),
            sealed_at: chrono::Utc::now(),
            placeholder,
        }
    }

    /// A real local seal reads back as self-issued.
    ///
    /// The whole point of the adapter, over genuine bytes rather than a fixture:
    /// the local backend is the only source of real CMS in this crate.
    #[test]
    fn a_real_local_seal_reads_as_self_issued() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x11; 32]).expect("sign");
        let value = base64::engine::general_purpose::STANDARD.encode(&der);

        let origin = CadesInspector::new()
            .origin(&envelope(value, SealFormat::Cades, false))
            .expect("a readable seal");

        assert!(origin.self_issued, "the local backend is self-signed");
        assert_eq!(origin.issuer, origin.subject);
        assert_eq!(
            origin.creation_device,
            dpp_types::CreationDevice::NotAQualifiedCertificate
        );
    }

    /// A placeholder is never read, and never reported as self-issued.
    ///
    /// The trap this guards: a ghost envelope carries no certificate, and the
    /// cheapest wrong answer — "no issuer, so self-issued" — would report the
    /// most alarming finding about a seal that does not exist. Absent is the
    /// only honest answer.
    #[test]
    fn a_placeholder_yields_no_origin_rather_than_a_finding() {
        let e = envelope("Z2hvc3Q=".to_owned(), SealFormat::Cades, true);
        assert!(CadesInspector::new().origin(&e).is_none());
    }

    /// Unreadable bytes yield no origin either, for the same reason.
    #[test]
    fn unreadable_bytes_yield_no_origin() {
        let junk = base64::engine::general_purpose::STANDARD.encode(b"not a CMS structure");
        assert!(
            CadesInspector::new()
                .origin(&envelope(junk, SealFormat::Cades, false))
                .is_none()
        );
        assert!(
            CadesInspector::new()
                .origin(&envelope(
                    "not base64 at all!!".to_owned(),
                    SealFormat::Cades,
                    false
                ))
                .is_none()
        );
    }

    // ─── What the seal says it covers ────────────────────────────────────────

    /// The digest a local seal was taken over, hex-encoded.
    fn digest_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// A seal reports the signature it actually covers.
    ///
    /// The whole point: this comes out of the seal's own `messageDigest`
    /// attribute, not out of any record this node keeps, so it holds for a seal
    /// restored from a backup or produced somewhere else entirely.
    #[test]
    fn a_seal_reports_the_signature_it_actually_covers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let digest = [0x11; 32];
        let der = id.sign_detached(&digest).expect("sign");
        let e = envelope(
            base64::engine::general_purpose::STANDARD.encode(&der),
            SealFormat::Cades,
            false,
        );

        assert_eq!(
            CadesInspector::new().binding(&e, &digest_hex(&digest)),
            SealBinding::CoversThisSignature
        );
    }

    /// Asked about a different signature, the same seal says so.
    ///
    /// What a re-published passport looks like: the passport re-signed, so its
    /// current signature is not the one sealed. The digest the seal *does* cover
    /// is reported, because a caller holding it can go and find which version it
    /// belongs to.
    #[test]
    fn a_seal_asked_about_another_signature_reports_the_one_it_covers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let digest = [0x11; 32];
        let der = id.sign_detached(&digest).expect("sign");
        let e = envelope(
            base64::engine::general_purpose::STANDARD.encode(&der),
            SealFormat::Cades,
            false,
        );

        let SealBinding::CoversAnotherDigest { covered } =
            CadesInspector::new().binding(&e, &digest_hex(&[0x22; 32]))
        else {
            panic!("this seal covers a different digest");
        };
        assert_eq!(covered, digest_hex(&digest));
    }

    /// **A seal cannot be retargeted by editing what it says it covers.**
    ///
    /// The attack this check exists to stop, and the reason the signature is
    /// verified before the digest is read. Rewriting the `messageDigest`
    /// attribute to name another passport's signature is trivial — the attribute
    /// is plain DER — but it sits *inside* the signature, so the edit breaks it.
    ///
    /// Note what is reported: `NotIntact`, with **no digest**. Reporting the
    /// forged value would hand a caller a number that nothing vouches for, and
    /// reporting `CoversAnotherDigest` would describe a broken seal as merely
    /// out of date.
    #[test]
    fn a_seal_cannot_be_retargeted_by_editing_the_digest_it_names() {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::{Decode as _, Encode as _};

        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x11; 32]).expect("sign");

        let target = [0x22; 32];
        let info = ContentInfo::from_der(&der).expect("CMS");
        let mut sd: SignedData = info.content.decode_as().expect("SignedData");
        let mut signers = sd.signer_infos.0.as_slice().to_vec();

        let attrs = signers[0].signed_attrs.as_ref().expect("signed attributes");
        let mut rebuilt = der::asn1::SetOfVec::new();
        for a in attrs.iter() {
            let a = if a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST {
                let mut values = der::asn1::SetOfVec::new();
                values
                    .insert(
                        der::Any::encode_from(
                            &der::asn1::OctetString::new(target.as_slice()).expect("octets"),
                        )
                        .expect("any"),
                    )
                    .expect("value");
                x509_cert::attr::Attribute { oid: a.oid, values }
            } else {
                a.clone()
            };
            rebuilt.insert(a).expect("attribute");
        }
        signers[0].signed_attrs = Some(rebuilt);

        let mut set = der::asn1::SetOfVec::new();
        set.insert(signers.remove(0)).expect("signer");
        sd.signer_infos = cms::signed_data::SignerInfos::from(set);
        let forged = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&sd).expect("encode"),
        }
        .to_der()
        .expect("re-encode");

        let e = envelope(
            base64::engine::general_purpose::STANDARD.encode(&forged),
            SealFormat::Cades,
            false,
        );

        assert_eq!(
            CadesInspector::new().binding(&e, &digest_hex(&target)),
            SealBinding::NotIntact,
            "the edit must break the signature rather than succeed in retargeting the seal"
        );
    }

    /// A placeholder binds to nothing, and says so rather than denying.
    #[test]
    fn a_placeholder_binds_to_nothing_rather_than_mismatching() {
        let e = envelope("Z2hvc3Q=".to_owned(), SealFormat::Cades, true);
        assert_eq!(
            CadesInspector::new().binding(&e, &digest_hex(&[0x11; 32])),
            SealBinding::Unknown,
            "an unread seal must never report as covering something else"
        );
    }

    /// A format this adapter does not parse is skipped, not guessed at.
    #[test]
    fn a_non_cades_format_is_not_parsed_as_cms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x11; 32]).expect("sign");
        let value = base64::engine::general_purpose::STANDARD.encode(&der);

        // The very bytes that read fine as CAdES, labelled otherwise.
        assert!(
            CadesInspector::new()
                .origin(&envelope(value, SealFormat::Jades, false))
                .is_none(),
            "the declared format decides, not what the bytes happen to be"
        );
    }

    /// 🚨 A published set reaches a verdict taken through a **clone** of the
    /// inspector, without rebuilding it.
    ///
    /// This is the property the composition root depends on and that a
    /// boot-time read alone cannot provide. `main` keeps one handle for the read
    /// path and hands another to the refresh task; the two are clones of each
    /// other, so a pass that completes has to be visible through the first one
    /// or the node answers `consulted: 0` until it is restarted.
    ///
    /// Observed through `unchecked` rather than `consulted` deliberately: the
    /// local backend is self-signed, so `standing` returns `SelfIssued` without
    /// consulting anything, while `qualify` copies the unchecked territories
    /// onto every verdict whatever the standing. That makes the swap observable
    /// with a real seal and no network.
    #[test]
    fn a_published_set_reaches_a_verdict_through_a_clone_of_the_inspector() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x11; 32]).expect("sign");
        let value = base64::engine::general_purpose::STANDARD.encode(&der);
        let seal = envelope(value, SealFormat::Cades, false);

        // The read path's handle, and the refresh task's — as `main` wires them.
        let read_path = CadesInspector::new();
        let refresher = read_path.clone();

        let before = read_path
            .qualification(&seal)
            .expect("a readable seal yields a verdict");
        assert!(
            before.unchecked.is_empty(),
            "a node that has not refreshed admits no territories: {:?}",
            before.unchecked
        );

        refresher.publish(
            Vec::new(),
            vec![dpp_types::qualification::UncheckedTerritory {
                territory: "DE".to_owned(),
                reason: "over the parser ceiling".to_owned(),
            }],
        );

        let after = read_path
            .qualification(&seal)
            .expect("a readable seal yields a verdict");
        assert_eq!(
            after.unchecked.len(),
            1,
            "the pass published by the refresher must reach the read path without a restart"
        );
        assert_eq!(after.unchecked[0].territory, "DE");
        assert_eq!(
            after.unchecked[0].reason, "over the parser ceiling",
            "and the reason travels with it, so the verdict can say why it is narrow"
        );
    }
}
