//! Unit tests for `signature.rs`: the thumbprint and the evidenced level.

use super::*;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

/// Unreadable bytes yield no reference rather than an error.
///
/// The seal itself is fine — it was produced, paid for, and stored. Losing it
/// because a convenience field could not be filled would trade something that
/// matters for something that does not.
#[test]
fn unreadable_bytes_yield_no_thumbprint() {
    assert_eq!(
        signer_certificate_thumbprint(b"not a CMS structure at all").unwrap(),
        None
    );
    assert_eq!(signer_certificate_thumbprint(&[]).unwrap(), None);
}

/// Reading the certificate out of a seal agrees with the identity that
/// signed it.
///
/// This is the claim that makes `signing_cert_ref` comparable across
/// backends. One backend knows its own certificate and reports it directly;
/// the other can only read it back out of the bytes a provider returned. If
/// those two ever produced different values for the same certificate, the
/// field would silently stop being a key an auditor can match on.
///
/// The local backend supplies realistic bytes here because it is the only
/// source of a genuine CMS structure in this crate — a hand-rolled fixture
/// would prove that the parser agrees with the fixture, not with reality.
#[test]
fn the_thumbprint_matches_the_identity_that_signed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id.sign_detached(&[0x11; 32]).expect("sign");

    assert_eq!(
        signer_certificate_thumbprint(&seal).unwrap(),
        Some(id.cert_thumbprint()),
        "the certificate read out of a seal must be the one that signed it"
    );
}

// ─── evidenced_level ─────────────────────────────────────────────────────

/// A real seal from the local backend, and the same seal with material added.
///
/// Built by decorating genuine bytes rather than assembling a fixture from
/// nothing, for the reason given above: a hand-rolled structure would prove
/// the reader agrees with the fixture. Decorating leaves the signature
/// invalid — nothing here re-signs — which is correct for this function,
/// because it reports what a seal *carries* and validates none of it.
fn decorated(
    attrs: &[const_oid::ObjectIdentifier],
    with_crls: bool,
) -> (Vec<u8>, tempfile::TempDir) {
    use der::asn1::SetOfVec;

    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x11; 32]).expect("sign");

    let info = ContentInfo::from_der(&der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");

    if !attrs.is_empty() {
        let mut unsigned = SetOfVec::new();
        for oid in attrs {
            let mut values = SetOfVec::new();
            // The content is irrelevant: presence is the whole signal, and
            // a real token would still not be validated by anything here.
            values
                .insert(der::Any::from(der::asn1::Null))
                .expect("attribute value");
            unsigned
                .insert(x509_cert::attr::Attribute { oid: *oid, values })
                .expect("unsigned attribute");
        }
        let mut signers = sd.signer_infos.0.as_slice().to_vec();
        signers[0].unsigned_attrs = Some(unsigned);
        let mut set = SetOfVec::new();
        set.insert(signers.remove(0)).expect("signer");
        sd.signer_infos = cms::signed_data::SignerInfos::from(set);
    }

    if with_crls {
        // One CRL entry stands for "the revocation material an LT seal
        // carries". Its contents are never read — `crls_present` is a
        // boolean by design.
        let crl = x509_cert::crl::CertificateList {
            tbs_cert_list: x509_cert::crl::TbsCertList {
                version: x509_cert::Version::V2,
                signature: sd.signer_infos.0.as_slice()[0].signature_algorithm.clone(),
                issuer: match &sd.signer_infos.0.as_slice()[0].sid {
                    cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) => {
                        ias.issuer.clone()
                    }
                    other => panic!("the local backend identifies by issuer+serial: {other:?}"),
                },
                this_update: x509_cert::time::Time::UtcTime(
                    der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(0))
                        .expect("time"),
                ),
                next_update: None,
                revoked_certificates: None,
                crl_extensions: None,
            },
            signature_algorithm: sd.signer_infos.0.as_slice()[0].signature_algorithm.clone(),
            signature: der::asn1::BitString::from_bytes(&[0]).expect("bits"),
        };
        let mut set = SetOfVec::new();
        set.insert(cms::revocation::RevocationInfoChoice::Crl(crl))
            .expect("crl");
        sd.crls = Some(cms::revocation::RevocationInfoChoices(set));
    }

    let info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    };
    (info.to_der().expect("der"), dir)
}

/// Unreadable bytes yield no level rather than a wrong one.
#[test]
fn unreadable_bytes_evidence_no_level() {
    assert_eq!(evidenced_level(b"not a CMS structure").unwrap(), None);
    assert_eq!(evidenced_level(&[]).unwrap(), None);
}

/// The local backend's seal evidences `BaselineB`, and that is what it
/// advertises.
///
/// The one place in this crate where the claim and the bytes can be checked
/// against each other end to end: `sign_detached` sets `unsigned_attrs:
/// None`, `capabilities()` advertises `BaselineB` only, and this asserts the
/// two agree. If the sealer ever grew a timestamp without its advertisement
/// following, this fails.
#[test]
fn the_local_seal_evidences_baseline_b() {
    let (der, _dir) = decorated(&[], false);
    assert_eq!(
        evidenced_level(&der).unwrap(),
        Some(SealConformanceLevel::BaselineB)
    );
}

/// A signature timestamp, and nothing more, evidences `BaselineT`.
#[test]
fn a_signature_timestamp_evidences_baseline_t() {
    let (der, _dir) = decorated(&[ID_AA_SIGNATURE_TIME_STAMP_TOKEN], false);
    assert_eq!(
        evidenced_level(&der).unwrap(),
        Some(SealConformanceLevel::BaselineT)
    );
}

/// Both homes of the long-term material evidence `BaselineLt`.
///
/// The finding this test exists for. ETSI EN 319 122-1 — Annex I of
/// Commission Implementing Regulation (EU) 2026/248 — puts an LT seal's
/// revocation material in `SignedData.crls` and forbids the
/// `revocation-values` attribute at that level. ETSI TS 103 173, that
/// Regulation's Annex II, carries it in that very attribute.
///
/// Both annexes are live: Article 3(2) obliges recognition of Annex II
/// formats for seals created before 23 February 2028. So a seal produced to
/// either profile is lawful today and carries exactly what the other
/// forbids. Reading only one home would report an Annex II seal as
/// `BaselineT` and raise a downgrade alarm against a provider that did
/// nothing wrong.
#[test]
fn either_home_of_the_revocation_material_evidences_baseline_lt() {
    let (modern, _a) = decorated(&[ID_AA_SIGNATURE_TIME_STAMP_TOKEN], true);
    let (legacy, _b) = decorated(
        &[
            ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
            ID_AA_ETS_REVOCATION_VALUES,
        ],
        false,
    );

    assert_eq!(
        evidenced_level(&modern).unwrap(),
        Some(SealConformanceLevel::BaselineLt),
        "EN 319 122-1 (2026/248 Annex I) puts the material in SignedData.crls"
    );
    assert_eq!(
        evidenced_level(&legacy).unwrap(),
        Some(SealConformanceLevel::BaselineLt),
        "TS 103 173 (2026/248 Annex II, lawful until Feb 2028) puts it in revocation-values"
    );
}

/// Both archival timestamp generations evidence `BaselineLta`.
#[test]
fn an_archival_timestamp_evidences_baseline_lta() {
    for oid in [
        ID_AA_ETS_ARCHIVE_TIMESTAMP_V3,
        ID_AA_ETS_ARCHIVE_TIMESTAMP_V2,
    ] {
        let (der, _dir) = decorated(&[ID_AA_SIGNATURE_TIME_STAMP_TOKEN, oid], true);
        assert_eq!(
            evidenced_level(&der).unwrap(),
            Some(SealConformanceLevel::BaselineLta),
            "{oid} is an archival timestamp"
        );
    }
}

/// Material for a high level without the levels beneath it reports the floor.
///
/// The direction of this rounding is the whole point. Under-reporting
/// prompts a look at a seal that may be fine; over-reporting hides the
/// downgrade the function exists to catch, so an archival timestamp over a
/// seal carrying no revocation material must not read as `BaselineLta`.
#[test]
fn a_level_is_never_reported_above_the_material_beneath_it() {
    let (no_revocation, _a) = decorated(
        &[
            ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
            ID_AA_ETS_ARCHIVE_TIMESTAMP_V3,
        ],
        false,
    );
    assert_eq!(
        evidenced_level(&no_revocation).unwrap(),
        Some(SealConformanceLevel::BaselineT),
        "archival material without long-term material is not LTA"
    );

    let (no_timestamp, _b) = decorated(&[ID_AA_ETS_REVOCATION_VALUES], true);
    assert_eq!(
        evidenced_level(&no_timestamp).unwrap(),
        Some(SealConformanceLevel::BaselineB),
        "revocation material without a signature timestamp is not LT"
    );
}

/// A seal signed by a different identity reports a different certificate.
///
/// Without this, the function could return a constant and the test above
/// would still pass.
#[test]
fn a_different_signer_yields_a_different_thumbprint() {
    let make = || {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let seal = id.sign_detached(&[0x11; 32]).expect("sign");
        (signer_certificate_thumbprint(&seal).unwrap(), dir)
    };

    let (a, _da) = make();
    let (b, _db) = make();
    assert!(a.is_some() && b.is_some());
    assert_ne!(a, b, "two certificates must not report the same thumbprint");
}
