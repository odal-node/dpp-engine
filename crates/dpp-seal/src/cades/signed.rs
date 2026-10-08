//! The parsed CMS every reader here starts from, and the attributes a seal can
//! carry.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::Decode as _;
use x509_cert::Certificate;

use crate::error::SealError;

pub(super) fn malformed(what: impl std::fmt::Display) -> SealError {
    SealError::Backend(format!("cannot read the seal: {what}"))
}

/// The signer, its certificate, and everything else the seal carries.
pub(super) struct Signed {
    /// The `SignedData` exactly as it was parsed.
    ///
    /// Kept whole, and only for the archive timestamp: its `ats-hash-index-v3`
    /// hashes every `CertificateChoices` and `RevocationInfoChoice` as encoded,
    /// which the filtered views below cannot reproduce — `chain` drops every
    /// choice that is not an X.509 certificate and `crls` drops every choice
    /// that is not a CRL, and either omission changes the index.
    pub(super) data: SignedData,
    pub(super) signer: SignerInfo,
    pub(super) certificate: Certificate,
    /// Every X.509 certificate embedded in the seal, the signer's included.
    ///
    /// A real CAdES seal usually travels with its issuing chain, which is what
    /// makes a path to a trusted list's anchor reachable without fetching
    /// anything: Italy's list publishes self-signed **roots**, so the
    /// intermediate that actually issued a seal certificate will be found here
    /// or nowhere.
    pub(super) chain: Vec<Certificate>,
    /// The encapsulated content, when the structure carries one.
    ///
    /// Absent for a detached seal — that is what detached means. Present for a
    /// **time-stamp token**, which is itself a `SignedData` and carries its
    /// `TSTInfo` here; reading an attested sealing time means reaching it.
    pub(super) econtent: Option<Vec<u8>>,
    /// Whatever `SignedData.crls` carried, as certificate revocation lists.
    ///
    /// Held rather than counted. This was a boolean for as long as nothing read
    /// the values — the reasoning being that carrying them would invite a caller
    /// to treat "revocation data is present" as "revocation was checked", which
    /// is the confusion this module is arranged to prevent. [`certificate_standing`]
    /// now actually reads them, so the distinction is made by what that function
    /// returns instead: presence alone reports `NotAvailable` until a CRL is
    /// found that covers this certificate and verifies under its issuer.
    ///
    /// Only the `crl` choice is kept. `other` is a container for formats this
    /// crate cannot read — an OCSP response among them — and keeping an
    /// unreadable value would have to be reported as material this node checked.
    pub(super) crls: Vec<x509_cert::crl::CertificateList>,
}

/// `id-ce-subjectKeyIdentifier` — RFC 5280 §4.2.1.2.
pub(super) const ID_CE_SUBJECT_KEY_IDENTIFIER: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.5.29.14");

/// Which embedded certificate the `SignerInfo` actually names.
///
/// **Not simply the first.** RFC 5652 makes `SignedData.certificates` a SET, so
/// its order carries no meaning, and a seal travelling with its issuing chain
/// may well list an intermediate before the end-entity certificate. Taking
/// `[0]` happens to work for a seal carrying exactly one certificate — which is
/// every seal this crate produces — and silently reports the wrong certificate
/// for a real provider's seal, which is the case that matters.
pub(super) fn signer_certificate_of<'a>(
    signer: &SignerInfo,
    certs: &'a [Certificate],
) -> Option<&'a Certificate> {
    match &signer.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) => certs.iter().find(|c| {
            c.tbs_certificate.issuer == ias.issuer
                && c.tbs_certificate.serial_number == ias.serial_number
        }),
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(ski) => certs.iter().find(|c| {
            c.tbs_certificate
                .extensions
                .as_ref()
                .and_then(|e| e.iter().find(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER))
                // The extension wraps the key identifier in an OCTET STRING, so
                // its DER is a 2-byte header plus the bytes the SignerInfo names.
                .is_some_and(|e| e.extn_value.as_bytes().ends_with(ski.0.as_bytes()))
        }),
    }
}

/// Parse a detached CMS `SignedData` down to its single signer and certificates.
///
/// One signer is not a simplification: this crate sends one digest per request
/// and a response bearing more than one signature does not answer the request
/// that was made. Reaching into `[0]` and hoping would turn that into a silent
/// mismatch.
pub(super) fn parse(seal_der: &[u8]) -> Result<Signed, SealError> {
    let info = ContentInfo::from_der(seal_der).map_err(|e| malformed(format!("not CMS: {e}")))?;
    let sd: SignedData = info
        .content
        .decode_as()
        .map_err(|e| malformed(format!("not SignedData: {e}")))?;

    let signers = sd.signer_infos.0.as_slice();
    let [signer] = signers else {
        return Err(malformed(format!(
            "expected exactly one signer, found {}",
            signers.len()
        )));
    };

    let certs = sd
        .certificates
        .as_ref()
        .ok_or_else(|| malformed("it carries no certificate"))?;
    let chain: Vec<Certificate> = certs
        .0
        .as_slice()
        .iter()
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    if chain.is_empty() {
        return Err(malformed("it carries no X.509 certificate"));
    }

    // A seal naming a certificate it does not carry cannot be read: the
    // alternative is to guess, and a guess here misattributes the seal.
    let certificate = signer_certificate_of(signer, &chain)
        .ok_or_else(|| malformed("it names a signer certificate it does not carry"))?
        .clone();

    Ok(Signed {
        data: sd.clone(),
        signer: signer.clone(),
        certificate,
        chain,
        econtent: sd
            .encap_content_info
            .econtent
            .as_ref()
            .and_then(|c| c.decode_as::<der::asn1::OctetString>().ok())
            .map(|o| o.as_bytes().to_vec()),
        crls: sd.crls.as_ref().map_or_else(Vec::new, |c| {
            c.0.as_slice()
                .iter()
                .filter_map(|choice| match choice {
                    cms::revocation::RevocationInfoChoice::Crl(crl) => Some(crl.clone()),
                    cms::revocation::RevocationInfoChoice::Other(_) => None,
                })
                .collect()
        }),
    })
}

/// `id-aa-signatureTimeStampToken` — the timestamp that distinguishes T.
///
/// RFC 3161 / RFC 5126 §6.1.1. Not in `const-oid`'s bundled databases, so it is
/// written out here with its source rather than reached for by a path that does
/// not exist.
pub(super) const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// `id-aa-ets-revocationValues` — revocation material carried as an attribute.
///
/// RFC 5126 §6.3.4. The **older** home for the material that distinguishes a
/// long-term seal; see [`evidenced_level`] for why both homes are accepted.
pub(super) const ID_AA_ETS_REVOCATION_VALUES: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");

/// `id-aa-ets-archiveTimestampV3` — the archival timestamp that distinguishes LTA.
///
/// ETSI-assigned (`itu-t(0) identified-organization(4) etsi(0) 1733 attributes(2)
/// 4`), which is why it is not in any RFC database.
pub(super) const ID_AA_ETS_ARCHIVE_TIMESTAMP_V3: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");

/// `id-aa-ets-archiveTimestampV2` — the predecessor of the above.
///
/// RFC 5126 §6.4.1. Accepted alongside v3 because a seal carrying either has
/// archival material; which generation it is does not change that.
pub(super) const ID_AA_ETS_ARCHIVE_TIMESTAMP_V2: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.48");
