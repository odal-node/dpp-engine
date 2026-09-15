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
use dpp_domain::seal::{SealFormat, SealedEnvelope};
use dpp_types::{SealBinding, SealInspector, SealOrigin};

use crate::cades;

/// Reads CAdES seals.
///
/// Stateless: it holds no credential and reaches no network, because reading a
/// certificate out of bytes needs neither. Construct it with
/// [`CadesInspector::new`] wherever a [`SealInspector`] is wanted.
#[derive(Debug, Clone, Copy, Default)]
pub struct CadesInspector;

impl CadesInspector {
    /// A new inspector.
    #[must_use]
    pub fn new() -> Self {
        Self
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
}
