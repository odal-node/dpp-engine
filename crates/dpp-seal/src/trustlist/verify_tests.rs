//! Verifying the real list of trusted lists against the real anchor.

use super::verify::{LotlRejected, verify_lotl};

/// The EU list of trusted lists, as published.
///
/// The real document. It will go stale as the Commission republishes, and that
/// is fine: a signature does not expire when a newer document appears, so an
/// archived LOTL keeps verifying. Every assertion here is about *verification*,
/// never about which providers happen to be listed today.
const EU_LOTL: &str = include_str!("../../tests/fixtures/eu-lotl.xml");

/// The published list of trusted lists verifies against the pinned anchor.
///
/// The end-to-end claim of this module: a document fetched from the Commission,
/// signed by a certificate the Official Journal authorises, over exclusive-C14N
/// canonicalised XML with RSA-SHA512 — and both halves check out.
#[test]
fn the_published_lotl_verifies() {
    let verified = verify_lotl(EU_LOTL).expect("the published LOTL verifies");

    assert!(
        !verified.pointers().is_empty(),
        "and it carries the pointers to the national lists"
    );
    assert_eq!(
        verified.signed_by(),
        "4KYg+7Z0c2K7kzrEQWnWdqVTREcWz18xYF8SoiuDlrE=",
        "signed by the second certificate the notice authorises"
    );
}

/// A single altered byte is rejected.
///
/// Tampering applied at **equal length**, so nothing but the intended bytes
/// changes — a size change would be a second variable and the rejection could be
/// for the wrong reason.
///
/// The target is a trusted list's location. That is the attack worth pinning: a
/// LOTL that points a relying party at an attacker's national list would poison
/// every qualified-status answer downstream, and it is a change of a few
/// characters in a URL.
#[test]
fn a_redirected_pointer_is_rejected() {
    let from = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-378.xml";
    let to = "https://ec.eur0pa.eu/tools/lotl/eu-lotl-pivot-378.xml";
    assert_eq!(from.len(), to.len(), "the tamper must not change length");

    let at = EU_LOTL
        .find(from)
        .expect("the fixture carries that pointer");
    let mut tampered = String::with_capacity(EU_LOTL.len());
    tampered.push_str(&EU_LOTL[..at]);
    tampered.push_str(to);
    tampered.push_str(&EU_LOTL[at + from.len()..]);

    match verify_lotl(&tampered) {
        Err(LotlRejected::SignatureInvalid(_)) => {}
        other => panic!("a redirected pointer must be rejected, got {other:?}"),
    }
}

/// A document signed by an unanchored key is rejected before its signature is
/// even considered.
///
/// The Finnish trusted list is genuine, correctly signed, and signed by
/// **Finland's** scheme operator — which the Official Journal does not authorise
/// to sign the *list of lists*. So it must be refused, and refused as
/// `NotAnchored` rather than as a bad signature: the signature is perfectly
/// good, and reporting it as invalid would send an operator hunting a tampered
/// document that does not exist.
///
/// It is also what the anchor is *for*. Drop the anchor check and this document
/// verifies cleanly, because it really is properly signed — by the wrong
/// authority. The signature alone cannot tell those apart.
#[test]
fn a_genuine_document_signed_by_the_wrong_authority_is_not_anchored() {
    let finnish = include_str!("../../tests/fixtures/fi-trusted-list.xml");

    match verify_lotl(finnish) {
        Err(LotlRejected::NotAnchored {
            offered,
            pinned_notice,
        }) => {
            assert!(!offered.is_empty(), "the offered digest is reported");
            assert_eq!(pinned_notice, "52026XC01944");
        }
        other => panic!("Finland does not sign the list of lists, got {other:?}"),
    }
}

/// Each malformed shape is told apart, because the operator response differs.
#[test]
fn the_rejection_says_which_kind_of_wrong() {
    assert!(matches!(
        verify_lotl("not xml"),
        Err(LotlRejected::Malformed(_))
    ));

    let unsigned = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><SchemeTerritory>EU</SchemeTerritory></SchemeInformation>
</TrustServiceStatusList>"#;
    assert!(matches!(
        verify_lotl(unsigned),
        Err(LotlRejected::NotSigned)
    ));

    let no_cert = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo/></ds:Signature>
</TrustServiceStatusList>"#;
    assert!(matches!(
        verify_lotl(no_cert),
        Err(LotlRejected::NoCertificate)
    ));
}

/// A rejection reads as an instruction, not a code.
///
/// `NotAnchored` is the one an operator will actually meet, most often because
/// the pin went stale rather than because anyone attacked them. The message has
/// to say that, and name the notice to compare against.
#[test]
fn the_not_anchored_message_tells_an_operator_what_to_do() {
    let rendered = LotlRejected::NotAnchored {
        offered: "AAAA".to_owned(),
        pinned_notice: "52026XC01944",
    }
    .to_string();

    assert!(rendered.contains("52026XC01944"), "names the pinned notice");
    assert!(rendered.contains("refresh"), "says what to do: {rendered}");
    assert!(rendered.contains("AAAA"), "and what was offered");
}
