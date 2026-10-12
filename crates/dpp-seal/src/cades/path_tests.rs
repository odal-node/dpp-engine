//! Unit tests for `path.rs`: a chain caught mid-rotation.

use super::*;

use crate::cades::test_support::{at, seal_with};

/// CA parameters under a chosen subject name.
fn ca_params(name: &str) -> rcgen::CertificateParams {
    let mut p = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name.push(rcgen::DnType::CommonName, name);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    p.not_before = at(-3650);
    p.not_after = at(3650);
    p
}

/// A certificate authority caught mid-rotation, as a seal would carry it.
///
/// Root → intermediate → leaf, plus a **second** intermediate certificate
/// with the same subject name and a different key, also issued by the root.
/// That is what a key rotation looks like on the wire: both certificates
/// published under one name so relying parties do not break at the cutover.
/// Only one of them signed the leaf.
struct Rotation {
    root_der: Vec<u8>,
    /// The intermediate that signed nothing, and the one that signed the
    /// leaf — in that order, and the order is the point.
    decoy_der: Vec<u8>,
    real_der: Vec<u8>,
    leaf_der: Vec<u8>,
}

/// Build one, with the decoy guaranteed to be met first.
///
/// A CMS `certificates` field is a DER `SET OF`, which is ordered by
/// encoding rather than by insertion — so which intermediate the walk meets
/// first is decided by bytes nobody chooses. Left to chance this test would
/// pass roughly half the time against a broken walk, which is worse than no
/// test, so the decoy has to sort **before** the real intermediate.
///
/// 🚨 **The order is constructed, not drawn.** This generated decoys until
/// one happened to sort first, capped at 64 attempts, and that ran out — on
/// `main`, in a local `just check`, passing six reruns afterwards.
///
/// Sixty-four tries is not as many as it looks. The comparison is
/// lexicographic over the whole DER, so the **outer length bytes come
/// first**, and a certificate's total length varies with two things that are
/// not fixed here: the randomly generated serial, whose integer encoding
/// varies in length, and the ECDSA signature, whose `r` and `s` each take 32
/// or 33 bytes depending on their high bit. When the real intermediate's
/// length lands at the short end of that spread, no decoy can be shorter and
/// only an exactly-equal-length one can win — on the bytes after the header.
/// The per-attempt probability is then a fraction of a small number rather
/// than the ~1/2 the retry count was chosen for.
///
/// So: generate a small pool, sort it, and take the ends. The smallest is the
/// decoy and the largest signs the leaf, which cannot fail — two distinct
/// certificates always compare — and costs one extra key generation.
fn rotating_chain() -> Rotation {
    fn key() -> rcgen::KeyPair {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key")
    }
    const INTERMEDIATE: &str = "Rotation Intermediate CA";

    let root =
        rcgen::CertifiedIssuer::self_signed(ca_params("Rotation Root CA"), key()).expect("a root");

    // Four, so the ends are comfortably apart and the pool stays cheap.
    let mut candidates: Vec<_> = (0..4)
        .map(|_| {
            rcgen::CertifiedIssuer::signed_by(ca_params(INTERMEDIATE), key(), &root)
                .expect("a rotation certificate")
        })
        .collect();
    candidates.sort_by(|a, b| a.der().as_ref().cmp(b.der().as_ref()));

    let decoy_der = candidates
        .first()
        .expect("the pool is not empty")
        .der()
        .to_vec();
    let real = candidates.pop().expect("the pool is not empty");
    let real_der = real.der().to_vec();
    assert!(
        decoy_der < real_der,
        "the decoy must sort first, which is what makes the walk meet the wrong \
         certificate before the right one"
    );

    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["Rotating Sealing Certificate".to_owned()])
            .expect("params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rotating Sealing Certificate");
    leaf_params.not_before = at(-30);
    leaf_params.not_after = at(365);
    leaf_params.serial_number = Some(rcgen::SerialNumber::from(7331u64));
    let leaf = leaf_params
        .signed_by(&key(), &*real)
        .expect("a leaf signed by the real intermediate");

    Rotation {
        root_der: root.der().to_vec(),
        decoy_der,
        real_der,
        leaf_der: leaf.der().to_vec(),
    }
}

/// A seal from a certificate authority mid-rotation still reaches its root.
///
/// The walk climbs the embedded chain, and at each link more than one
/// certificate can carry the issuer's name — a CA rotating its key publishes
/// the old and the new together. Taking the first and returning its verdict
/// reports a genuine seal as `NotSignedByThisIssuer`, which
/// `qualification::standing` turns into `SignatureNotFromListedCa`: the
/// variant this crate reserves for *this CA did not sign it*, and documents
/// as the one that is an accusation.
///
/// So the failure is not a missed detection — it is a false statement about
/// a provider who did nothing wrong, intermittent, and only during a
/// rotation. `find_issuer_candidates` already takes every certificate under
/// a matching subject on the *listed* side of the same question; this is the
/// embedded side.
#[test]
fn a_rotating_authority_verifies_through_the_certificate_that_signed() {
    let chain = rotating_chain();
    let (seal, _dir) = seal_with(
        &[
            chain.leaf_der.clone(),
            chain.decoy_der.clone(),
            chain.real_der.clone(),
            chain.root_der.clone(),
        ],
        &[],
    );

    assert_eq!(
        check_path_to(&seal, &chain.root_der).expect("the seal parses"),
        IssuerCheck::Verified,
        "the rotation certificate that signed nothing was met first and its verdict \
         returned, instead of trying the one that signed the leaf"
    );
}

/// The decoy really is one, so the test above is not passing by accident.
///
/// Anchored on the decoy, the leaf's issuer name matches its subject, so the
/// walk takes the anchor branch and checks the signature directly — and it
/// does not verify. Without this, a decoy that had somehow signed the leaf
/// would make the case above pass while testing nothing.
#[test]
fn the_rotation_decoy_did_not_sign_the_leaf() {
    let chain = rotating_chain();
    let (seal, _dir) = seal_with(
        &[
            chain.leaf_der.clone(),
            chain.decoy_der.clone(),
            chain.real_der.clone(),
            chain.root_der.clone(),
        ],
        &[],
    );

    assert_eq!(
        check_path_to(&seal, &chain.decoy_der).expect("the seal parses"),
        IssuerCheck::NotSignedByThisIssuer,
        "the decoy must not verify the leaf, or the rotation case proves nothing"
    );
}
