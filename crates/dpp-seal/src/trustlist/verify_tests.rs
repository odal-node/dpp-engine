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

/// The transform profile CID (EU) 2015/1505 Annex I mandates is asserted, and a
/// document that misses it is rejected *for that reason*.
///
/// # Why each case asserts the variant and not merely an error
///
/// Altering the XML also breaks the signature, so every case below would fail
/// somehow with no profile check at all. `NonConformantProfile` rather than
/// `SignatureInvalid` is what proves the gate ran — and that it ran *first*, so
/// a chain the law does not permit is refused before anything canonicalises it.
/// A valid signature must not be able to excuse a non-conformant chain, and
/// asserting only "it errored" could not tell the two apart.
///
/// Tampered in memory rather than through text tooling: these documents use CRLF
/// terminators, and a line-oriented edit rewrites every line, which makes a
/// rejection prove nothing about the change that was intended.
///
/// The positive control is `the_published_lotl_verifies` above — the real
/// document passes its own mandated profile, so these cases test the check
/// rather than a fixture that never conformed.
///
/// # This was confirmed, not assumed
///
/// With the profile check removed, all four cases still fail — for four
/// unrelated, incidental reasons: a dangling ID reference, a digest mismatch, a
/// signature mismatch, and an XPath *resource* ceiling. So `is_err()` alone
/// would have passed against a verifier doing none of this.
///
/// The last of those is the sharpest evidence that the gap was real rather than
/// theoretical: the injected XPath transform was **evaluated** — 5800 context
/// evaluations before a resource limit stopped it — which is `xml-sec` honouring
/// a transform the law does not permit. A cheaper XPath would not have hit that
/// limit at all.
mod signature_profile {
    use super::*;

    const CONFORMANT: &str = "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>";

    fn lotl_with(transforms: &str) -> String {
        assert_eq!(
            EU_LOTL.matches(CONFORMANT).count(),
            1,
            "the fixture no longer carries the transform chain these cases rewrite"
        );
        EU_LOTL.replace(CONFORMANT, transforms)
    }

    fn rejection(xml: &str) -> LotlRejected {
        verify_lotl(xml).expect_err("a non-conformant signature must be refused")
    }

    #[test]
    fn a_third_transform_is_refused() {
        let extra = CONFORMANT.replace(
            "</ds:Transforms>",
            "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms>",
        );
        let err = rejection(&lotl_with(&extra));
        assert!(
            matches!(err, LotlRejected::NonConformantProfile(ref why) if why.contains("exactly two")),
            "an extra XPath transform is the wrapping case this exists for, got: {err}"
        );
    }

    #[test]
    fn the_two_transforms_in_the_wrong_order_are_refused() {
        let swapped = "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms>";
        let err = rejection(&lotl_with(swapped));
        assert!(
            matches!(err, LotlRejected::NonConformantProfile(ref why) if why.contains("in that order")),
            "the clause fixes the order, got: {err}"
        );
    }

    #[test]
    fn inclusive_canonicalization_is_refused() {
        let inclusive = CONFORMANT.replace(
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        );
        let err = rejection(&lotl_with(&inclusive));
        assert!(
            matches!(err, LotlRejected::NonConformantProfile(ref why) if why.contains("in that order")),
            "the clause names exclusive canonicalization specifically, got: {err}"
        );
    }

    /// Without a `URI=""` reference nothing in the signature covers the whole
    /// document — which is the wrapping outcome itself, not a shape quibble.
    #[test]
    fn a_reference_that_no_longer_covers_the_document_is_refused() {
        const WHOLE_DOCUMENT: &str = "<ds:Reference Id=\"ref-enveloped-signature\" URI=\"\">";
        assert_eq!(
            EU_LOTL.matches(WHOLE_DOCUMENT).count(),
            1,
            "the fixture no longer carries the document-wide reference this case rewrites"
        );
        let xml = EU_LOTL.replace(
            WHOLE_DOCUMENT,
            "<ds:Reference Id=\"ref-enveloped-signature\" URI=\"#not-the-document\">",
        );
        let err = rejection(&xml);
        assert!(
            matches!(err, LotlRejected::NonConformantProfile(ref why) if why.contains("covers the")),
            "a signature covering something other than the document must be refused, got: {err}"
        );
    }
}
