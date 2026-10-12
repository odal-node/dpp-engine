//! Unit tests for `certificate.rs`: the certificate's own standing.

use super::*;
use dpp_domain::seal::SealConformanceLevel;

use crate::cades::attested_sealing_time;
use crate::cades::test_support::{at, seal_with};

/// A CA, a leaf it issued, and whatever CRLs a test wants to embed.
///
/// Real certificates and a real CRL signature, because every assertion below is
/// about whether a signature checks out. A fixture that faked one would be
/// testing the fixture.
struct Issued {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    leaf_der: Vec<u8>,
    leaf_serial: rcgen::SerialNumber,
}

/// A CA and a leaf whose validity window is `from`..`to`, in days from now.
fn issue(from: i64, to: i64) -> Issued {
    issue_from("Test Issuing CA", from, to)
}

/// The same, under a chosen CA name — so a test can produce either a
/// genuinely different issuer or a different key wearing the same name.
fn issue_from(ca_name: &str, from: i64, to: i64) -> Issued {
    fn key() -> rcgen::KeyPair {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key")
    }
    let mut ca_params = rcgen::CertificateParams::new(vec![ca_name.to_owned()]).expect("params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_name);
    // A CA that may sign CRLs, or `rcgen` refuses to make one with it.
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = at(-3650);
    ca_params.not_after = at(3650);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, key()).expect("a CA");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["Test Sealing Certificate".to_owned()]).expect("params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Sealing Certificate");
    leaf_params.not_before = at(from);
    leaf_params.not_after = at(to);
    let leaf_serial = leaf_params.serial_number.clone().unwrap_or_else(|| {
        let s = rcgen::SerialNumber::from(42u64);
        leaf_params.serial_number = Some(s.clone());
        s
    });
    let leaf = leaf_params
        .signed_by(&key(), &*ca)
        .expect("a leaf signed by the CA");

    Issued {
        ca,
        leaf_der: leaf.der().to_vec(),
        leaf_serial,
    }
}

/// A CRL from `issued`'s CA, listing the leaf as revoked `days` from now
/// when `revoked` is set.
fn crl(issued: &Issued, revoked: Option<i64>) -> x509_cert::crl::CertificateList {
    let params = rcgen::CertificateRevocationListParams {
        this_update: at(0),
        next_update: at(30),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
        revoked_certs: revoked
            .map(|days| rcgen::RevokedCertParams {
                serial_number: issued.leaf_serial.clone(),
                revocation_time: at(days),
                reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .into_iter()
            .collect(),
    };
    let der = params
        .signed_by(&issued.ca)
        .expect("a signed CRL")
        .der()
        .to_vec();
    x509_cert::crl::CertificateList::from_der(&der).expect("the CRL parses")
}

/// **A certificate that expired before now is reported expired.**
///
/// The gap #323 named: nothing read `notAfter`, so a seal made with a
/// long-dead certificate reached the same verdict as one made yesterday.
#[test]
fn an_expired_certificate_is_seen_to_be_expired() {
    let issued = issue(-400, -30);
    let (seal, _dir) = seal_with(&[issued.leaf_der.clone(), issued.ca.der().to_vec()], &[]);

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    assert_eq!(standing.validity.standing, WindowStanding::Expired);
    assert!(standing.validity.not_after < Utc::now());
    assert!(
        !standing.judged_at.attested,
        "this fixture seals at B-B, which carries no timestamp at all — so the moment \
         is this clock, and the flag says so. `Expired` here is an observation; only \
         the attested case turns it into a finding"
    );
}

/// **An LTA seal's certificate is judged against its attested time.**
///
/// The two readers must agree: `certificate_standing` calls
/// `attested_sealing_time` for its moment, and the `attested` flag it sets is
/// what decides whether an out-of-window certificate is a failure or an open
/// question. A disagreement here would be invisible — the verdict would
/// simply be the weaker one, for ever, on every seal that carries a
/// timestamp.
#[test]
fn an_lta_seals_certificate_is_judged_against_its_attested_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id
        .sign_detached_at(&[0x33; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");

    let attested = attested_sealing_time(&seal).expect("readable");
    assert!(
        attested.is_some(),
        "an LTA seal carries a timestamp whose signature and imprint both check out"
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    assert!(
        standing.judged_at.attested,
        "the standing must be judged against that time, not against this clock"
    );
    assert_eq!(Some(standing.judged_at.at), attested);
}

/// A certificate valid now is inside its window, and the window is reported
/// so a reader can check the arithmetic rather than trust the verdict.
#[test]
fn a_current_certificate_is_inside_its_window() {
    let issued = issue(-30, 400);
    let (seal, _dir) = seal_with(&[issued.leaf_der.clone(), issued.ca.der().to_vec()], &[]);

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    assert_eq!(standing.validity.standing, WindowStanding::Inside);
    assert!(standing.validity.not_before < standing.validity.not_after);
}

/// **A revoked certificate is found, from the seal's own CRL.**
///
/// No network: the CRL travels inside the seal, which is what ETSI's
/// long-term profiles put it there for.
#[test]
fn a_revoked_certificate_is_found_in_the_seals_own_crl() {
    let issued = issue(-30, 400);
    let revocation = crl(&issued, Some(-1));
    let (seal, _dir) = seal_with(
        &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
        &[revocation],
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    match standing.revocation {
        RevocationStanding::Revoked { at } => assert!(at < Utc::now()),
        other => panic!("expected a revocation, got {other:?}"),
    }
}

/// **Every applicable CRL is read, not the first one that verifies.**
///
/// A long-term seal accumulates revocation material, and `SignedData.crls`
/// is a SET — its order carries no meaning. Answering from whichever copy
/// came first would report `notRevoked` from a stale list while a later one
/// carries the revocation, and the order deciding it would be an encoding
/// accident.
#[test]
fn a_stale_clean_crl_does_not_outrank_a_later_revocation() {
    let issued = issue(-30, 400);
    let (seal, _dir) = seal_with(
        &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
        // Clean first, revoking second: the SET may present them either way.
        &[crl(&issued, None), crl(&issued, Some(-1))],
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    match standing.revocation {
        RevocationStanding::Revoked { .. } => {}
        other => panic!("a revocation anywhere ends the search, got {other:?}"),
    }
}

/// A CRL that covers the certificate and does not list it says so, and says
/// *as of when* — a CRL older than the seal cannot rule out a later
/// revocation, and the field is there so a reader can see which question was
/// answered.
#[test]
fn a_clean_crl_reports_the_moment_it_speaks_for() {
    let issued = issue(-30, 400);
    let (seal, _dir) = seal_with(
        &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
        &[crl(&issued, None)],
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    match standing.revocation {
        RevocationStanding::NotRevoked { as_of } => {
            assert!((Utc::now() - as_of).num_minutes().abs() < 5);
        }
        other => panic!("expected a clean CRL, got {other:?}"),
    }
}

/// **A CRL nobody signed for is not evidence.**
///
/// The attack this closes is the interesting direction: an empty CRL
/// *unrevokes* a certificate. Anyone able to add one to a seal could turn a
/// revoked certificate into a clean report, so the list's own signature is
/// checked against a certificate the seal carries before a word of it is
/// believed.
#[test]
fn a_crl_whose_signature_does_not_verify_is_unusable() {
    let issued = issue(-30, 400);
    let mut tampered = crl(&issued, Some(-1));
    // Drop the revocation, leaving the signature over the original content.
    tampered.tbs_cert_list.revoked_certificates = None;
    let (seal, _dir) = seal_with(
        &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
        &[tampered],
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    match standing.revocation {
        RevocationStanding::Unusable { reason } => {
            assert!(
                reason.contains("signature"),
                "the reason must name what failed: {reason}"
            );
        }
        other => panic!("a tampered CRL must not be believed, got {other:?}"),
    }
}

/// A seal carrying no revocation material says so, and that is not a defect:
/// `B-B` and `B-T` seals are not required to carry any.
#[test]
fn a_seal_with_no_crl_reports_that_it_could_not_ask() {
    let issued = issue(-30, 400);
    let (seal, _dir) = seal_with(&[issued.leaf_der.clone(), issued.ca.der().to_vec()], &[]);

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    assert_eq!(standing.revocation, RevocationStanding::NotAvailable);
}

/// A CRL from a different issuer is silently not about this certificate —
/// neither an answer nor a problem. A seal legitimately carries the CRLs for
/// every certificate in its chain.
#[test]
fn a_crl_from_another_issuer_is_not_an_answer() {
    let issued = issue(-30, 400);
    let other = issue_from("Some Other CA", -30, 400);
    let (seal, _dir) = seal_with(
        &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
        &[crl(&other, Some(-1))],
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    assert_eq!(
        standing.revocation,
        RevocationStanding::NotAvailable,
        "another CA's list says nothing about this certificate, in either direction"
    );
}

/// **A CRL wearing the issuer's name, signed by another key, is refused.**
///
/// The same asymmetry #323 was opened about, one level down: a name is not a
/// signature. Matching a CRL to a certificate by issuer name alone would let
/// anyone who can put bytes in a seal revoke a certificate they do not
/// control — or, worse in the other direction, clear a revoked one by
/// shipping an empty list under the right name.
///
/// The answer is `unusable` rather than `notAvailable` on purpose: something
/// claiming to be authoritative was there and did not check out, which is
/// worth looking at. Silence would file it beside "no CRL was included",
/// which is an ordinary state of a `B-T` seal.
#[test]
fn a_crl_naming_the_issuer_but_signed_by_another_key_is_unusable() {
    let issued = issue(-30, 400);
    // Same subject name, freshly generated key.
    let impostor = issue(-30, 400);
    let (seal, _dir) = seal_with(
        &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
        &[crl(&impostor, Some(-1))],
    );

    let standing = certificate_standing(
        &seal,
        Utc::now(),
        attested_sealing_time(&seal).expect("readable"),
    )
    .expect("readable");
    match standing.revocation {
        RevocationStanding::Unusable { reason } => assert!(
            reason.contains("signature"),
            "the reason must name what failed: {reason}"
        ),
        other => panic!("a CRL under a borrowed name must not be believed, got {other:?}"),
    }
}
