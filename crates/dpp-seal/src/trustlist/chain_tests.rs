//! The whole chain: Official Journal → list of lists → a national list.

use super::verify::{TrustedListRejected, verify_lotl, verify_trusted_list};
use dpp_domain::trusted_list::TrustServiceType;

const EU_LOTL: &str = include_str!("../../tests/fixtures/eu-lotl.xml");
const FI_LIST: &str = include_str!("../../tests/fixtures/fi-trusted-list.xml");

/// The pointer the verified LOTL carries for Finland.
fn finnish_pointer() -> super::model::TrustedListPointer {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    lotl.pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some("FI"))
        .expect("the LOTL points at Finland")
        .clone()
}

/// The chain closes: a national list verifies against a verified LOTL.
///
/// The claim the whole module exists for. Nothing in this test trusts a document
/// because it was fetched — the Official Journal vouches for the list of lists,
/// and the list of lists vouches for Finland.
///
/// Note what is *not* pinned anywhere: Finland's certificates. They arrive in a
/// document that was itself verified, which is the point of a list of lists.
#[test]
fn a_national_list_verifies_through_the_verified_lotl() {
    let pointer = finnish_pointer();
    assert!(
        !pointer.certificates.is_empty(),
        "the LOTL names Finland's signing certificates"
    );

    let verified = verify_trusted_list(FI_LIST, &pointer).expect("Finland's list verifies");

    assert_eq!(verified.territory(), Some("FI"));
    assert!(!verified.providers().is_empty());
    assert!(
        verified
            .providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA)
            .count()
            > 0,
        "and the Art. 39a-style lookup now runs over verified content"
    );
}

/// A Member State names several certificates, and any of them may be the signer.
///
/// Not an edge case: a scheme operator rotating its certificate publishes the
/// old and the new together so relying parties do not break at the cutover. A
/// verifier that accepted only the first listed would fail every Member State on
/// the day it rotated — intermittently, and only for some countries.
#[test]
fn any_of_the_named_certificates_may_be_the_signer() {
    let pointer = finnish_pointer();
    assert!(
        pointer.certificates.len() > 1,
        "Finland names several, which is why position must not matter"
    );

    // Verification succeeds without the signer being first.
    let mut reordered = pointer.clone();
    reordered.certificates.rotate_left(1);
    assert!(verify_trusted_list(FI_LIST, &reordered).is_ok());

    let mut reversed = pointer.clone();
    reversed.certificates.reverse();
    assert!(verify_trusted_list(FI_LIST, &reversed).is_ok());
}

/// A list signed by a key the LOTL does not name for it is refused.
///
/// The substitution this link exists to stop: a genuine, correctly signed
/// trusted list from *somewhere else* served in place of Finland's. Its
/// signature is perfect; what is wrong is who signed it.
///
/// Reported as `NotNamedByLotl` rather than `SignatureInvalid`, because the two
/// send an operator in opposite directions — one to the Member State, the other
/// to hunt a tampered document that does not exist.
#[test]
fn a_list_signed_by_an_unnamed_certificate_is_refused() {
    let mut pointer = finnish_pointer();
    // Keep the shape, drop the real signer: certificates from another territory.
    let lotl = verify_lotl(EU_LOTL).expect("verifies");
    let other = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some("BE") && !p.certificates.is_empty())
        .expect("the LOTL points at Belgium too");
    pointer.certificates = other.certificates.clone();

    match verify_trusted_list(FI_LIST, &pointer) {
        Err(TrustedListRejected::NotNamedByLotl {
            offered,
            authorised,
        }) => {
            assert!(!offered.is_empty());
            assert_eq!(authorised, other.certificates.len());
        }
        other => panic!("Belgium does not sign Finland's list, got {other:?}"),
    }
}

/// A tampered national list is refused even though its signer is named.
///
/// The other half of the pair above. Here the certificate is right and the bytes
/// are not, so the answer must be `SignatureInvalid` — someone touched the
/// document.
///
/// The tamper flips one service status at equal length, which is the change that
/// would actually pay: making a withdrawn trust service read as granted.
#[test]
fn a_tampered_national_list_is_refused_as_a_bad_signature() {
    let from = "Svcstatus/withdrawn";
    let to = "Svcstatus/granted__";
    assert_eq!(from.len(), to.len(), "the tamper must not change length");

    let at = FI_LIST
        .find(from)
        .expect("the fixture carries a withdrawal");
    let mut tampered = String::with_capacity(FI_LIST.len());
    tampered.push_str(&FI_LIST[..at]);
    tampered.push_str(to);
    tampered.push_str(&FI_LIST[at + from.len()..]);

    match verify_trusted_list(&tampered, &finnish_pointer()) {
        Err(TrustedListRejected::SignatureInvalid(_)) => {}
        other => panic!("a flipped service status must be caught, got {other:?}"),
    }
}

/// A pointer naming no certificates verifies nothing.
///
/// Distinct from a mismatch: there is nothing to check against, and saying so
/// separately keeps "the LOTL vouches for nobody here" from reading as "the
/// signature was wrong".
#[test]
fn a_pointer_with_no_certificates_is_refused_distinctly() {
    let mut pointer = finnish_pointer();
    pointer.certificates.clear();

    assert_eq!(
        verify_trusted_list(FI_LIST, &pointer),
        Err(TrustedListRejected::NoAuthorisedCertificates)
    );
}

/// Having a territory does not make a pointer a national list.
///
/// This test was written asserting the opposite — that non-national pointers are
/// the ones with no `SchemeTerritory` — and failed, which is how the two cases
/// below were found. **Every** pointer in the published LOTL carries a territory,
/// so presence of one distinguishes nothing, and the filter that used it would
/// have fetched two kinds of document that are not trusted lists.
#[test]
fn a_territory_does_not_make_a_pointer_a_national_list() {
    let lotl = verify_lotl(EU_LOTL).expect("verifies");
    let pointers = lotl.pointers();

    assert!(
        pointers.iter().all(|p| p.territory.is_some()),
        "every pointer names a territory, so the field separates nothing"
    );

    // The LOTL points at itself, to declare its own signing certificates.
    let self_pointer = pointers
        .iter()
        .find(|p| {
            p.tsl_type.as_deref()
                == Some("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists")
        })
        .expect("the LOTL carries a pointer to itself");
    assert_eq!(self_pointer.territory.as_deref(), Some("EU"));
    assert_eq!(self_pointer.location, super::fetch::EU_LOTL_URL);

    // And several Member States publish a PDF beside the XML, same territory.
    let pdfs: Vec<_> = pointers
        .iter()
        .filter(|p| p.mime_type.as_deref() == Some("application/pdf"))
        .collect();
    assert!(
        !pdfs.is_empty(),
        "some Member States publish a human-readable PDF as a second pointer"
    );
    assert!(
        pdfs.iter()
            .all(|pdf| pointers.iter().any(|p| p.territory == pdf.territory
                && p.mime_type.as_deref() == Some("application/vnd.etsi.tsl+xml"))),
        "each PDF sits beside the XML for the same territory, not instead of it"
    );

    let national = super::fetch::national_pointers(pointers);
    assert!(national.len() >= 20, "most pointers are national lists");
    assert!(
        !national
            .iter()
            .any(|p| p.location == super::fetch::EU_LOTL_URL),
        "and the filter keeps the list of lists out of its own refresh"
    );
    assert!(
        !national
            .iter()
            .any(|p| p.mime_type.as_deref() == Some("application/pdf")),
        "and keeps the PDFs out too"
    );
}

/// Every national pointer names at least one signing certificate.
///
/// The property the second link of the chain rests on. A pointer naming none
/// would be refused by [`verify_trusted_list`] with `NoAuthorisedCertificates`,
/// so a Member State that stopped publishing them would drop out of the refresh
/// entirely — worth knowing as a fact about the published document rather than
/// discovering as an outage.
#[test]
fn every_national_pointer_carries_certificates_to_verify_against() {
    let lotl = verify_lotl(EU_LOTL).expect("verifies");
    let national = super::fetch::national_pointers(lotl.pointers());
    assert!(
        national.len() >= 20,
        "there are lists to check, so an empty result would not prove this"
    );

    let bare: Vec<_> = national
        .iter()
        .filter(|p| p.certificates.is_empty())
        .map(|p| p.territory.as_deref().unwrap_or(&p.location))
        .collect();
    assert!(
        bare.is_empty(),
        "these name no signing certificate: {bare:?}"
    );
}

/// Each signature names exactly one certificate, so "the signer" is unambiguous.
///
/// The assumption underneath both links of the chain, pinned because it is
/// invisible in the code that relies on it. Two separate things read the
/// document: this module takes the **first** `X509Certificate` under the
/// signature and compares it against what the LOTL authorises, while `xml-sec`
/// resolves a key of its own to check the signature with. They agree only while
/// there is one certificate to choose.
///
/// XMLDSig permits a `KeyInfo` to carry a whole chain, and the order within it
/// is not fixed. If a publisher ever ships one, the two could diverge — the
/// certificate we vouched for would not be the certificate that verified — and
/// the failure would be silent. This test goes red first instead.
#[test]
fn each_signature_names_exactly_one_certificate() {
    for (what, xml) in [("the LOTL", EU_LOTL), ("Finland's list", FI_LIST)] {
        let doc = roxmltree::Document::parse(xml).expect("parses");
        let signature = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .expect("is signed");
        let certificates = signature
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "X509Certificate")
            .count();

        assert_eq!(
            certificates, 1,
            "{what} names {certificates} certificates in its signature; picking the first is \
             no longer unambiguous — see this test's note"
        );
    }
}
