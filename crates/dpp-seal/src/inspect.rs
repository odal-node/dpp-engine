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
use dpp_types::{SealInspector, SealOrigin};

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
