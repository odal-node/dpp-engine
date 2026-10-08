//! Fixtures the certificate and path tests both use.
//!
//! Both build seals around certificates they issue themselves, so the clock
//! helper and the seal surgery live here rather than in one file and a copy.

use chrono::Utc;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode as _, Encode as _};
use time::OffsetDateTime;
use x509_cert::Certificate;

/// Seconds, as `rcgen`'s date type.
pub(super) fn at(offset_days: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() + offset_days * 86_400)
        .expect("a representable date")
}

/// A seal carrying `certificates` and `crls`, built from a real local seal
/// so the CMS structure is one this crate actually produces.
pub(super) fn seal_with(
    certificates: &[Vec<u8>],
    crls: &[x509_cert::crl::CertificateList],
) -> (Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x22; 32]).expect("sign");

    let info = ContentInfo::from_der(&der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");

    let parsed: Vec<Certificate> = certificates
        .iter()
        .map(|d| Certificate::from_der(d).expect("a certificate"))
        .collect();
    let mut certs = der::asn1::SetOfVec::new();
    for c in &parsed {
        certs
            .insert(cms::cert::CertificateChoices::Certificate(c.clone()))
            .expect("certificate");
    }
    sd.certificates = Some(cms::signed_data::CertificateSet(certs));

    // The signer must name the certificate under test, or the parser refuses
    // the seal before any of this is reached.
    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    signers[0].sid = cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
        cms::cert::IssuerAndSerialNumber {
            issuer: parsed[0].tbs_certificate.issuer.clone(),
            serial_number: parsed[0].tbs_certificate.serial_number.clone(),
        },
    );
    let mut set = der::asn1::SetOfVec::new();
    set.insert(signers.remove(0)).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(set);

    if !crls.is_empty() {
        let mut choices = der::asn1::SetOfVec::new();
        for crl in crls {
            choices
                .insert(cms::revocation::RevocationInfoChoice::Crl(crl.clone()))
                .expect("crl");
        }
        sd.crls = Some(cms::revocation::RevocationInfoChoices(choices));
    }

    let reencoded = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode");
    (reencoded, dir)
}
