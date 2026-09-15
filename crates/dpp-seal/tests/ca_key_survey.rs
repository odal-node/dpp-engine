//! What key algorithms the listed qualified CAs actually use.
//!
//! Sizes the certificate-path verification that `super::super::qualification`
//! does not do. Verifying that a listed CA issued a seal's certificate means
//! checking the CA's signature over that certificate, and **the CA's key type
//! decides which verifier is needed** — a CA holding an RSA key signs with RSA.
//!
//! Measured rather than assumed, because assuming from a sample is the mistake
//! this workspace has already made twice: the fetch cap was sized from the
//! fixtures that happened to be committed, and "only Italy and France need the
//! fork" was a stale measurement by the time it was written down.

use base64::Engine as _;
use der::{Decode as _, Encode as _};
use dpp_domain::trusted_list::TrustServiceType;

use dpp_seal::trustlist::{VerifiedTrustedList, verify_lotl, verify_trusted_list};

const EU_LOTL: &str = include_str!("fixtures/eu-lotl.xml");
const FI_LIST: &str = include_str!("fixtures/fi-trusted-list.xml");

/// `rsaEncryption` — RFC 8017.
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `id-ecPublicKey` — RFC 5480.
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// Every distinct public-key algorithm among a list's qualified CA certificates.
///
/// Returns `(algorithm OID, count)`, and counts certificates rather than
/// services: one service may name several, and a rotation publishes old and new
/// together.
fn ca_key_algorithms(list_xml: &str, territory: &str) -> Vec<(String, usize)> {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some(territory))
        .expect("the LOTL points at this territory")
        .clone();
    let list = verify_trusted_list(list_xml, &pointer).expect("the list verifies");

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (_, services) in list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA) {
        for service in services {
            for c in &service.certificates {
                let Ok(der) = base64::engine::general_purpose::STANDARD.decode(c.trim()) else {
                    continue;
                };
                let Ok(cert) = x509_cert::Certificate::from_der(&der) else {
                    continue;
                };
                let oid = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oid
                    .to_string();
                *counts.entry(oid).or_default() += 1;
            }
        }
    }
    counts.into_iter().collect()
}

/// **RSA is not optional.** A path verifier that handles only P-256 verifies
/// almost nothing.
///
/// This is the measurement behind the decision to take on an RSA dependency
/// rather than reuse the `p256` verifier already in this crate. `cades`'s
/// [`verify_against_embedded_certificate`](crate::cades::verify_against_embedded_certificate)
/// is P-256-only, which is right for the local development backend that emits
/// P-256 and useless against the population below.
///
/// Recorded as an assertion rather than a comment so it re-checks itself
/// whenever Finland republishes: if RSA ever stopped dominating, the scope of
/// that work would change and this would say so.
#[test]
fn the_listed_qualified_cas_are_overwhelmingly_rsa() {
    let algorithms = ca_key_algorithms(FI_LIST, "FI");
    assert!(
        !algorithms.is_empty(),
        "Finland lists qualified CA certificates"
    );

    let total: usize = algorithms.iter().map(|(_, n)| n).sum();
    let rsa = algorithms
        .iter()
        .find(|(oid, _)| oid == RSA_ENCRYPTION)
        .map_or(0, |(_, n)| *n);
    let ec = algorithms
        .iter()
        .find(|(oid, _)| oid == EC_PUBLIC_KEY)
        .map_or(0, |(_, n)| *n);

    println!("FI qualified-CA certificate keys ({total} certificates):");
    for (oid, n) in &algorithms {
        let name = match oid.as_str() {
            RSA_ENCRYPTION => "rsaEncryption",
            EC_PUBLIC_KEY => "id-ecPublicKey",
            _ => "(other)",
        };
        println!("  {oid}  {name:<16} {n}");
    }

    assert!(
        rsa > ec,
        "RSA dominates, so a P-256-only path verifier would verify almost nothing \
         (rsa={rsa}, ec={ec}, total={total})"
    );
    assert_eq!(
        rsa + ec,
        total,
        "only RSA and EC keys appear; a third algorithm would widen the verifier's scope \
         and should be looked at rather than silently skipped"
    );
}

/// **Every listed qualified CA yields a usable verifier.**
///
/// The survey above says what algorithms are out there; this says we can
/// actually check a signature made with them. It is the test that would have
/// caught the real gap: `verify_against_embedded_certificate` was P-256 only,
/// which covers the local development backend and **none** of the certificates
/// below — so the first real provider seal would have failed to verify, taken
/// the seal-to-passport binding with it (the digest lives inside the signature),
/// and reported "unknown" rather than anything alarming.
///
/// Run over the real published certificates rather than a fixture, because the
/// question is whether this build copes with what Member States actually
/// publish, and that is not a thing a fixture can answer.
#[test]
fn every_listed_qualified_ca_yields_a_usable_verifier() {
    let mut checked = 0;
    let mut unusable = Vec::new();

    for (territory, xml) in available_lists() {
        let list = verified(&xml, territory);
        for (_, services) in list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA) {
            for service in services {
                for c in &service.certificates {
                    let Some(der) = base64::engine::general_purpose::STANDARD
                        .decode(c.trim())
                        .ok()
                    else {
                        continue;
                    };
                    let Ok(cert) = x509_cert::Certificate::from_der(&der) else {
                        continue;
                    };
                    checked += 1;
                    if !dpp_seal::cades::can_verify_signatures_of(&der) {
                        unusable.push(format!(
                            "{territory} oid={} subject={}",
                            cert.tbs_certificate.subject_public_key_info.algorithm.oid,
                            cert.tbs_certificate.subject,
                        ));
                    }
                }
            }
        }
    }

    println!(
        "{checked} listed qualified-CA certificates, {} this build cannot verify",
        unusable.len()
    );
    assert!(
        checked > 0,
        "no certificate was checked, so this proves nothing"
    );
    assert!(
        unusable.is_empty(),
        "this build cannot verify signatures from these listed CAs, so a seal issued under          one would report as unverifiable rather than as sound: {unusable:?}"
    );
}

/// The same survey across the larger lists held locally, when they are present.
///
/// Finland alone is a sample of one, and sizing work from the sample that
/// happened to be committed is precisely the error recorded in this module's
/// header. These documents are ~3 MB each and git-ignored, so this skips loudly
/// rather than failing when they are absent — a checkout without them reads as
/// "not measured here", never as a pass.
#[test]
fn the_larger_lists_agree_about_the_algorithms_in_play() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local");
    let mut measured = 0;

    for (territory, file) in [("IT", "it-trusted-list.xml"), ("FR", "fr-trusted-list.xml")] {
        let path = dir.join(file);
        let Ok(xml) = std::fs::read_to_string(&path) else {
            eprintln!("SKIPPED {territory}: {} is absent", path.display());
            continue;
        };
        let algorithms = ca_key_algorithms(&xml, territory);
        let total: usize = algorithms.iter().map(|(_, n)| n).sum();
        println!("{territory} qualified-CA certificate keys ({total} certificates):");
        for (oid, n) in &algorithms {
            println!("  {oid}  {n}");
        }
        assert!(
            algorithms
                .iter()
                .all(|(oid, _)| oid == RSA_ENCRYPTION || oid == EC_PUBLIC_KEY),
            "{territory} lists a key algorithm outside RSA and EC, which widens the \
             verifier's scope: {algorithms:?}"
        );
        measured += 1;
    }

    if measured == 0 {
        eprintln!(
            "SKIPPED: no local trusted lists present, so this measurement did not run. \
             See crates/dpp-seal/tests/fixtures/local/ for how to fetch them."
        );
    }
}

/// The curves in play, where a CA holds an EC key.
///
/// Relevant because `p256` — the only elliptic-curve verifier this crate has —
/// does not cover them. Finland's EC qualified CAs are **all P-384**, so the
/// existing verifier covers none of them, and "we already have P-256" is not a
/// head start on this work.
#[test]
fn ec_listed_cas_are_not_the_curve_this_crate_already_verifies() {
    let mut curves = std::collections::BTreeMap::new();
    collect_curves(FI_LIST, "FI", &mut curves);

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local");
    for (territory, file) in [("IT", "it-trusted-list.xml"), ("FR", "fr-trusted-list.xml")] {
        match std::fs::read_to_string(dir.join(file)) {
            Ok(xml) => collect_curves(&xml, territory, &mut curves),
            Err(_) => eprintln!("SKIPPED {territory}: local list absent"),
        }
    }

    println!("EC qualified-CA curves across the lists measured: {curves:?}");
    for curve in curves.keys() {
        assert!(
            [P256, P384, P521].contains(&curve.as_str()),
            "an unexpected curve widens the verifier's scope: {curve}"
        );
    }
    assert!(
        curves.contains_key(P384),
        "P-384 is in the population, so an elliptic-curve leg cannot stop at P-256"
    );
}

/// `secp256r1` / NIST P-256 — RFC 5480 §2.1.1.1. What `cades` already verifies.
const P256: &str = "1.2.840.10045.3.1.7";
/// `secp384r1` / NIST P-384.
const P384: &str = "1.3.132.0.34";
/// `secp521r1` / NIST P-521.
const P521: &str = "1.3.132.0.35";

/// Tally the named curves of one list's EC qualified-CA certificates.
fn collect_curves(
    list_xml: &str,
    territory: &str,
    into: &mut std::collections::BTreeMap<String, usize>,
) {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some(territory))
        .expect("the LOTL points at this territory")
        .clone();
    let list = verify_trusted_list(list_xml, &pointer).expect("the list verifies");

    for (_, services) in list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA) {
        for service in services {
            for c in &service.certificates {
                let Ok(der) = base64::engine::general_purpose::STANDARD.decode(c.trim()) else {
                    continue;
                };
                let Ok(cert) = x509_cert::Certificate::from_der(&der) else {
                    continue;
                };
                let spki = &cert.tbs_certificate.subject_public_key_info;
                if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY {
                    continue;
                }
                // The named curve travels in the algorithm parameters.
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.to_der().ok())
                    .and_then(|d| der::asn1::ObjectIdentifier::from_der(&d).ok())
                    .map_or_else(|| "(unnamed)".to_owned(), |o| o.to_string());
                *into.entry(curve).or_default() += 1;
            }
        }
    }
}

/// **The lists publish trust anchors, not chains.**
///
/// No listed certificate is issued by another listed certificate — measured
/// across every list available here. That is what makes the intermediate a real
/// problem rather than a tidy-up: a seal's certificate is issued by a CA that
/// may be a listed entry itself, or may be one level below a listed root, and
/// the list never carries the link between.
///
/// Member States do not even agree on which they publish. Italy's list is
/// overwhelmingly self-signed roots; Finland's and France's carry no self-signed
/// certificate at all, so their entries are issuing CAs whose own roots are
/// outside the list. A verifier that matched only a seal's direct issuer would
/// work for Finland and France and fail for most of Italy.
///
/// Hence `cades::check_path_to` walking intermediates **out of the seal**, and
/// `chain_issuer_names` widening candidate selection past the signer's own
/// issuer.
#[test]
fn the_lists_publish_anchors_not_chains() {
    use std::collections::HashMap;

    for (territory, xml) in available_lists() {
        let list = verified(&xml, territory);

        let mut by_subject: HashMap<Vec<u8>, ()> = HashMap::new();
        let mut certificates: Vec<x509_cert::Certificate> = Vec::new();
        for (_, services) in list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA) {
            for service in services {
                for c in &service.certificates {
                    let Some(cert) = base64::engine::general_purpose::STANDARD
                        .decode(c.trim())
                        .ok()
                        .and_then(|d| x509_cert::Certificate::from_der(&d).ok())
                    else {
                        continue;
                    };
                    if let Ok(subject) = cert.tbs_certificate.subject.to_der() {
                        by_subject.insert(subject, ());
                    }
                    certificates.push(cert);
                }
            }
        }

        let mut self_signed = 0;
        let mut chaining = 0;
        for cert in &certificates {
            let (Ok(issuer), Ok(subject)) = (
                cert.tbs_certificate.issuer.to_der(),
                cert.tbs_certificate.subject.to_der(),
            ) else {
                continue;
            };
            if issuer == subject {
                self_signed += 1;
            } else if by_subject.contains_key(&issuer) {
                chaining += 1;
            }
        }

        println!(
            "{territory}: {} certificates, {self_signed} self-signed, {chaining} issued by another listed certificate",
            certificates.len()
        );
        assert_eq!(
            chaining, 0,
            "{territory} lists a certificate issued by another listed certificate, so the              assumption that a list is a set of anchors no longer holds and candidate              selection should be looked at again"
        );
    }
}

/// Every list this checkout can verify: Finland always, the larger two when the
/// git-ignored fixtures are present.
fn available_lists() -> Vec<(&'static str, String)> {
    let mut lists = vec![("FI", FI_LIST.to_owned())];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local");
    for (territory, file) in [("IT", "it-trusted-list.xml"), ("FR", "fr-trusted-list.xml")] {
        match std::fs::read_to_string(dir.join(file)) {
            Ok(xml) => lists.push((territory, xml)),
            Err(_) => eprintln!("SKIPPED {territory}: local list absent"),
        }
    }
    lists
}

/// One list, verified through the verified list of lists.
fn verified(xml: &str, territory: &str) -> VerifiedTrustedList {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some(territory))
        .expect("the LOTL points at this territory")
        .clone();
    verify_trusted_list(xml, &pointer).expect("the list verifies")
}
