//! Verifying the real list of trusted lists against the real anchor.

use super::verify::{
    AnchorFreshness, LotlRejected, TrustedListRejected, anchor_freshness, verify_lotl,
};
use chrono::TimeZone as _;

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

    /// A namespaced `x:URI=""` must not be read as the document-wide reference.
    ///
    /// The case above with one attribute added. roxmltree 0.21.0 changed an
    /// unprefixed `attribute("URI")` lookup to match any *local* name — `x:URI`
    /// included — returning the first in document order, which the document
    /// being parsed chooses. So a decoy placed ahead of the real `URI` makes a
    /// reference covering `#not-the-document` read back as covering everything,
    /// and the profile check waves through exactly the wrapping it exists to
    /// stop.
    ///
    /// # Why this asserts the variant rather than merely an error
    ///
    /// For the same reason the module above does, and here it is the whole
    /// point: with the decoy in place and the unprefixed lookup restored, this
    /// document *is* still rejected — by `xml-sec`, for a dangling ID
    /// reference, incidentally and one layer too late. `NonConformantProfile`
    /// is what distinguishes "the profile check caught it" from "something
    /// else happened to". Asserting `is_err()` would pass against the bug.
    #[test]
    fn a_namespaced_decoy_uri_does_not_impersonate_the_document_reference() {
        const WHOLE_DOCUMENT: &str = "<ds:Reference Id=\"ref-enveloped-signature\" URI=\"\">";
        assert_eq!(
            EU_LOTL.matches(WHOLE_DOCUMENT).count(),
            1,
            "the fixture no longer carries the document-wide reference this case rewrites"
        );
        let xml = EU_LOTL.replace(
            WHOLE_DOCUMENT,
            "<ds:Reference xmlns:x=\"urn:x\" Id=\"ref-enveloped-signature\" x:URI=\"\" \
             URI=\"#not-the-document\">",
        );
        let err = rejection(&xml);
        assert!(
            matches!(err, LotlRejected::NonConformantProfile(ref why) if why.contains("covers the")),
            "the profile check must read the real URI, not a namespaced decoy, got: {err}"
        );
    }

    /// The same decoy, against the transform algorithms.
    ///
    /// `Algorithm` is read by the identical lookup, so it carries the identical
    /// exposure — and this is the sharper half. A wrapped signature needs a
    /// permissive transform, and `xml-sec` accepts XPath by default (the
    /// module doc above measured it evaluating one). A decoy `x:Algorithm`
    /// naming the mandated transform, ahead of a real `Algorithm` naming XPath,
    /// would let the chain read as conformant while something else entirely was
    /// canonicalised.
    #[test]
    fn a_namespaced_decoy_algorithm_does_not_impersonate_the_mandated_transform() {
        let decoyed = CONFORMANT.replace(
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
            "<ds:Transform xmlns:x=\"urn:x\" \
             x:Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" \
             Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"/>",
        );
        let err = rejection(&lotl_with(&decoyed));
        assert!(
            matches!(err, LotlRejected::NonConformantProfile(ref why) if why.contains("in that order")),
            "the profile check must read the real Algorithm, not a namespaced decoy, got: {err}"
        );
    }
}

/// The certificate the anchor is checked against is the one the signature is
/// verified with.
///
/// Nothing downstream re-establishes this. `verify_lotl` decides trust from the
/// certificate it reads out of the document, and `xml-sec` then verifies the
/// signature using a certificate **it** selects, by a different rule —
/// `select_x509_signing_certificate` resolves the leaf of the embedded chain and
/// falls back to document order only when that finds nothing. `VerifyResult`
/// exposes no certificate, so a mismatch cannot be detected afterwards: it has
/// to be made impossible beforehand.
///
/// Two constraints do that, and these cases pin both — the read is scoped to
/// `ds:KeyInfo`, and `ds:KeyInfo` must carry exactly one certificate.
mod signing_certificate_binding {
    use super::*;
    use base64::Engine as _;

    /// A second certificate in `ds:KeyInfo` is refused, not chosen between.
    ///
    /// This is the case the constraint exists for. With two certificates the
    /// reader takes the first and `xml-sec` takes the leaf, and for a chain
    /// published leaf-last those are different bytes — so the anchor decision
    /// would be about a certificate the signature was never verified with.
    ///
    /// # The injected certificate does not disturb the signature
    ///
    /// Worth stating, because it is why this is a check rather than a comment:
    /// the case below rewrites the **published** LOTL and the result is still
    /// refused *for the certificate count*, not as `SignatureInvalid`. It cannot
    /// be — `ds:KeyInfo` sits inside `ds:Signature`, which the mandated
    /// enveloped-signature transform removes from the digest input, so what it
    /// holds is outside everything the signature covers.
    ///
    /// So an attacker may add a certificate to a genuine, correctly signed
    /// document for free. Reading "the first one" would then have taken the
    /// real, anchored certificate, passed the anchor, and gone on to verify — a
    /// document nobody could distinguish from the Commission's. What binds the
    /// certificate is XAdES `SigningCertificate` in the signed properties, which
    /// this module does not read.
    #[test]
    fn a_second_certificate_in_key_info_is_refused() {
        const ONE: &str = "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
        assert_eq!(
            EU_LOTL.matches(ONE).count(),
            1,
            "the fixture no longer carries the single-certificate ds:KeyInfo this case rewrites"
        );
        let two = EU_LOTL.replace(
            ONE,
            "</ds:X509Certificate><ds:X509Certificate>QUFB</ds:X509Certificate></ds:X509Data>\
             </ds:KeyInfo>",
        );

        match verify_lotl(&two) {
            Err(LotlRejected::AmbiguousSigningCertificate { found }) => assert_eq!(found, 2),
            other => panic!("a second certificate must be refused, got {other:?}"),
        }
    }

    /// A certificate outside `ds:KeyInfo` is never mistaken for the signing one.
    ///
    /// `ds:Object` legitimately carries certificates — XAdES `CertificateValues`
    /// is where an LT or LTA signature keeps its chain — and `xml-sec` resolves
    /// keys from `ds:KeyInfo` alone. A reader searching the whole `ds:Signature`
    /// would pick one of those up whenever it came first, and the document's
    /// author decides what comes first, so the ordering here is the adversarial
    /// one rather than the schema's.
    ///
    /// The digest in `NotAnchored` is what makes this observable: it names the
    /// certificate that was actually read.
    #[test]
    fn a_certificate_outside_key_info_is_not_read_as_the_signing_one() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:Object><ds:X509Certificate>QkJC</ds:X509Certificate></ds:Object>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>QUFB</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>"#;

        let from_key_info = base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(b"AAA"));

        match verify_lotl(xml) {
            Err(LotlRejected::NotAnchored { offered, .. }) => assert_eq!(
                offered, from_key_info,
                "the certificate in ds:Object was read instead of ds:KeyInfo's"
            ),
            other => panic!("an unanchored certificate must be refused, got {other:?}"),
        }
    }

    /// Both refusals say which document is at fault and why nothing was chosen.
    #[test]
    fn the_ambiguity_message_says_why_it_refused() {
        for rendered in [
            LotlRejected::AmbiguousSigningCertificate { found: 3 }.to_string(),
            TrustedListRejected::AmbiguousSigningCertificate { found: 3 }.to_string(),
        ] {
            assert!(rendered.contains('3'), "names the count: {rendered}");
            assert!(
                rendered.contains("refusing"),
                "says it refused rather than guessed: {rendered}"
            );
        }
    }
}

/// Every rejection renders as one line of prose.
///
/// These strings are wrapped across source lines with a trailing `\`, which
/// continues the literal and swallows the indentation. Writing `\n` there
/// instead — one character different, and neither `rustfmt` nor `clippy` reads
/// inside a string literal — breaks the message into a line and a run of
/// leading spaces wherever an operator reads it. That shipped in
/// `TrustedListRejected::NonConformantProfile` and nothing caught it, because
/// no test rendered that variant.
#[test]
fn no_rejection_message_carries_a_stray_line_break() {
    let rendered = [
        LotlRejected::Malformed("why".to_owned()).to_string(),
        LotlRejected::NotSigned.to_string(),
        LotlRejected::NoCertificate.to_string(),
        LotlRejected::AmbiguousSigningCertificate { found: 2 }.to_string(),
        LotlRejected::NotAnchored {
            offered: "AAAA".to_owned(),
            pinned_notice: "52026XC01944",
        }
        .to_string(),
        LotlRejected::SignatureInvalid("why".to_owned()).to_string(),
        LotlRejected::NonConformantProfile("why".to_owned()).to_string(),
        TrustedListRejected::Malformed("why".to_owned()).to_string(),
        TrustedListRejected::NotSigned.to_string(),
        TrustedListRejected::NoCertificate.to_string(),
        TrustedListRejected::AmbiguousSigningCertificate { found: 2 }.to_string(),
        TrustedListRejected::NoAuthorisedCertificates.to_string(),
        TrustedListRejected::NotNamedByLotl {
            offered: "AAAA".to_owned(),
            authorised: 2,
        }
        .to_string(),
        TrustedListRejected::SignatureInvalid("why".to_owned()).to_string(),
        TrustedListRejected::NonConformantProfile("why".to_owned()).to_string(),
    ];

    for message in rendered {
        assert!(
            !message.contains('\n'),
            "a rejection must render as one line, got: {message:?}"
        );
        assert!(
            !message.contains("  "),
            "and without a run of swallowed indentation, got: {message:?}"
        );
    }
}

/// Whether the pinned anchor is still the notice the Commission names.
///
/// The anchor is pinned from an Official Journal notice and the Commission
/// republishes that notice. A pin nobody refreshes eventually meets a LOTL
/// signed by a certificate it does not name, and fails closed on a date nobody
/// has in a calendar. This is the only warning before that.
mod anchor_freshness_signal {
    use super::*;

    /// The assumption the whole check rests on, asserted against the real
    /// document rather than trusted.
    ///
    /// The LOTL lists its notice **first** in `SchemeInformationURI`, ahead of
    /// the pivot chain and twenty-three per-language legal notices. If that
    /// ordering ever changed, this check would compare against a pivot URL and
    /// report `Superseded` forever — noisy rather than silent, which is the
    /// right way round, but still wrong.
    #[test]
    fn the_notice_is_the_first_entry_the_document_lists() {
        let freshness = anchor_freshness(EU_LOTL, "https://eur-lex.europa.eu/eli/C/2026/1944/oj");
        assert_eq!(
            freshness,
            AnchorFreshness::Current,
            "the first SchemeInformationURI entry is no longer the OJ notice"
        );
    }

    /// The published document and this build's pin agree today.
    ///
    /// When this fails, the Commission has republished and the anchor needs
    /// refreshing from the notice named in the failure — which is the whole
    /// point of the signal, arriving as a red test rather than an outage.
    #[test]
    fn the_pinned_anchor_is_still_the_notice_in_force() {
        let verified = verify_lotl(EU_LOTL).expect("the LOTL verifies");
        assert_eq!(
            verified.anchor_freshness(),
            &AnchorFreshness::Current,
            "the pinned notice is no longer the one the LOTL names"
        );
    }

    /// A superseded pin is named, and names what to go and read.
    #[test]
    fn a_superseded_pin_says_which_notice_replaced_it() {
        let freshness = anchor_freshness(EU_LOTL, "https://eur-lex.europa.eu/eli/C/2019/276/oj");
        let AnchorFreshness::Superseded { lotl_names } = &freshness else {
            panic!("a pin the document does not name must be reported: {freshness:?}");
        };
        assert_eq!(lotl_names, "https://eur-lex.europa.eu/eli/C/2026/1944/oj");
        assert!(
            freshness.to_string().contains("refresh the anchor"),
            "an operator has to be told what to do: {freshness}"
        );
    }

    /// Freshness is a signal, never a verdict.
    ///
    /// The document that would report `Superseded` against an older pin is the
    /// same document that verifies cleanly — which is the situation this exists
    /// for. Refusing it would turn an early warning into the outage it is meant
    /// to prevent.
    #[test]
    fn a_superseded_pin_does_not_refuse_a_document_that_verifies() {
        assert!(
            verify_lotl(EU_LOTL).is_ok(),
            "the real LOTL verifies against the real anchor"
        );
        assert!(
            matches!(
                anchor_freshness(EU_LOTL, "https://eur-lex.europa.eu/eli/C/2019/276/oj"),
                AnchorFreshness::Superseded { .. }
            ),
            "and would report a stale pin, without that changing the verdict"
        );
    }

    /// A document naming no notice is `Unknown`, not `Current`.
    ///
    /// Treating "could not tell" as "up to date" is how a staleness signal goes
    /// quiet exactly when it matters — the same fail-closed direction the
    /// capacity and date questions take elsewhere in this workspace.
    #[test]
    fn a_document_that_names_no_notice_is_not_reported_as_current() {
        assert_eq!(
            anchor_freshness(
                "<TrustServiceStatusList/>",
                "https://example.invalid/notice"
            ),
            AnchorFreshness::Unknown
        );
        assert_eq!(
            anchor_freshness("not xml at all", "https://example.invalid/notice"),
            AnchorFreshness::Unknown
        );
    }
}

/// A verified list survives being stored and restored.
///
/// The cache's premise is that verification can be done once and written down,
/// so what is written down has to answer the same questions as what was
/// verified. This takes the real Finnish list through the store's round trip —
/// parsed form to JSON and back — and asks it the question a qualification
/// verdict asks.
///
/// Whole-value equality is not the assertion. `UnverifiedTrustedList` derives
/// `PartialEq`, so comparing the two would pass for a round trip that preserved
/// every field and dropped the lookup that uses them. The certificates and the
/// service histories are what a verdict reads, so those are what is checked.
#[test]
fn a_verified_list_survives_the_store_round_trip() {
    let finnish = include_str!("../../tests/fixtures/fi-trusted-list.xml");
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| {
            p.territory.as_deref() == Some("FI")
                && p.mime_type.as_deref() != Some("application/pdf")
        })
        .expect("the LOTL points at Finland");
    let verified =
        super::verify::verify_trusted_list(finnish, pointer).expect("Finland's list verifies");

    let json = serde_json::to_value(verified.content()).expect("the parsed form serialises");
    let restored: super::model::UnverifiedTrustedList =
        serde_json::from_value(json).expect("and reads back");
    let from_store =
        super::verify::VerifiedTrustedList::from_store(restored, verified.signed_by().to_owned());

    assert_eq!(from_store.territory(), verified.territory());
    assert_eq!(from_store.signed_by(), verified.signed_by());
    assert_eq!(
        from_store.providers().len(),
        verified.providers().len(),
        "a provider lost in storage is a provider a verdict cannot find"
    );

    // The lookup a verdict actually performs, on both. Certificates are what
    // the issuer match is made against and histories are what "qualified at
    // sealing" is read from, so a round trip that kept the names and dropped
    // either would pass every assertion above and be useless.
    let ca = dpp_domain::trusted_list::TrustServiceType::QUALIFIED_CERTIFICATE_CA;
    let certificates = |list: &super::verify::VerifiedTrustedList| -> usize {
        list.providers_offering(ca)
            .flat_map(|(_, services)| services)
            .map(|s| s.certificates.len())
            .sum()
    };
    // `was_granted_at` is the whole reason a history is stored rather than a
    // current status: Art. 32(1)(b) asks whether the provider was qualified
    // **when the seal was made**, not now.
    //
    // So asking only about now would be the one question a flattened history
    // still answers correctly — it is asked at two moments instead, and the two
    // are asserted to *differ* before they are compared. Without that, a fixture
    // whose every service happened to be granted throughout would make this pass
    // against a round trip that dropped the history entirely.
    let granted_at = |list: &super::verify::VerifiedTrustedList, when| -> usize {
        list.providers_offering(ca)
            .flat_map(|(_, services)| services)
            .filter(|s| s.history.was_granted_at(when))
            .count()
    };
    let now = chrono::Utc::now();
    let before_the_scheme = chrono::Utc
        .with_ymd_and_hms(2010, 1, 1, 0, 0, 0)
        .single()
        .expect("a real instant");

    assert!(certificates(&verified) > 0, "the fixture lists CAs");
    assert_eq!(certificates(&from_store), certificates(&verified));

    assert!(
        granted_at(&verified, now) > 0,
        "some of the fixture's CAs are granted today"
    );
    assert_ne!(
        granted_at(&verified, now),
        granted_at(&verified, before_the_scheme),
        "the fixture's history has to actually vary over time, or asking two moments \
         proves nothing about whether the history survived"
    );

    assert_eq!(granted_at(&from_store, now), granted_at(&verified, now));
    assert_eq!(
        granted_at(&from_store, before_the_scheme),
        granted_at(&verified, before_the_scheme),
        "a round trip that kept only the current status answers today correctly and \
         every past question wrongly — which is the question Art. 32(1)(b) asks"
    );
}
