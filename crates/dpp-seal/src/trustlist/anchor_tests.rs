//! The pinned anchor, against the certificate that really signs the LOTL.

use super::anchor::EU_LOTL_ANCHOR;

/// The DER of the certificate that signed the EU list of trusted lists when this
/// pin was taken, lifted from its `ds:KeyInfo`.
///
/// Subject `EUROPEAN COMMISSION`, OU *Directorate-General for Digital Services
/// (DIGIT)*, issued by a Portuguese qualified trust service provider and valid
/// 2023-11-17 to 2027-11-17.
///
/// A real certificate rather than one generated for the test, because the claim
/// under test is about the real world: that the digests transcribed from the
/// Official Journal actually match what the Commission signs with. A generated
/// certificate could only prove the hash function works.
const LOTL_SIGNING_CERT: &[u8] = include_bytes!("../../tests/fixtures/eu-lotl-signing-cert.der");

/// The certificate that signs the real LOTL is one the Official Journal names.
///
/// The transcription check. Six digests were copied out of a notice by hand, and
/// this is what catches a wrong character in any of them — without it, the
/// anchor could be subtly wrong and nothing would say so until a verification
/// that should have passed did not.
#[test]
fn the_real_lotl_signing_certificate_is_authorised() {
    assert!(
        EU_LOTL_ANCHOR.authorises(LOTL_SIGNING_CERT),
        "the certificate signing the published LOTL must be one the notice at {} names",
        EU_LOTL_ANCHOR.notice_celex()
    );
}

/// Nothing else is authorised.
///
/// Guards the direction that matters. An `authorises` that returned `true`
/// broadly would pass the test above and defeat the anchor entirely, so a
/// near-miss is checked explicitly: the same certificate with one byte changed
/// is a different certificate and must be refused.
#[test]
fn a_certificate_the_notice_does_not_name_is_refused() {
    assert!(!EU_LOTL_ANCHOR.authorises(b""));
    assert!(!EU_LOTL_ANCHOR.authorises(b"not a certificate"));

    let mut tampered = LOTL_SIGNING_CERT.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        !EU_LOTL_ANCHOR.authorises(&tampered),
        "one flipped bit makes it a different certificate"
    );
}

/// The anchor carries its own provenance.
///
/// Asserted because these are the fields someone refreshing the pin has to
/// update together, and a stale CELEX beside fresh digests would misreport where
/// the trust came from — the one thing the provenance exists to prevent.
#[test]
fn the_anchor_states_where_it_came_from() {
    assert_eq!(EU_LOTL_ANCHOR.notice_celex(), "52026XC01944");
    assert!(
        EU_LOTL_ANCHOR.notice_uri().contains("eli/C/2026/1944"),
        "the ELI and the CELEX must name the same notice"
    );
    assert_eq!(
        EU_LOTL_ANCHOR.authorised_count(),
        6,
        "the notice's Annex carries six certificates"
    );
    assert_eq!(EU_LOTL_ANCHOR.pinned_on(), "2026-09-11");
}

/// The pinned location is compared, not assumed.
#[test]
fn only_the_pinned_location_matches() {
    assert!(EU_LOTL_ANCHOR.is_pinned_location("https://ec.europa.eu/tools/lotl/eu-lotl.xml"));
    assert!(
        !EU_LOTL_ANCHOR.is_pinned_location("https://example.test/eu-lotl.xml"),
        "a LOTL from elsewhere may be genuine and is still not the one this anchor describes"
    );
    assert!(
        !EU_LOTL_ANCHOR.is_pinned_location("http://ec.europa.eu/tools/lotl/eu-lotl.xml"),
        "and the scheme is part of the location"
    );
}

/// Every pinned digest is a well-formed base64 SHA-256.
///
/// A transcription slip that produced a string of the wrong length would
/// otherwise sit in the list matching nothing, silently shrinking the authorised
/// set — which fails closed, but fails closed for a reason nobody would find.
#[test]
fn every_pinned_digest_is_a_base64_sha256() {
    use base64::Engine as _;

    for digest in EU_LOTL_ANCHOR.digests_for_test() {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(digest)
            .unwrap_or_else(|e| panic!("{digest} is not base64: {e}"));
        assert_eq!(raw.len(), 32, "{digest} is not a 32-byte SHA-256 digest");
    }
}
