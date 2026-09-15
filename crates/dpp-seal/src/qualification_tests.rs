//! What the verdict says about a seal, and what it deliberately does not.

use super::*;
use crate::trustlist::{verify_lotl, verify_trusted_list};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

const EU_LOTL: &str = include_str!("../tests/fixtures/eu-lotl.xml");
const FI_LIST: &str = include_str!("../tests/fixtures/fi-trusted-list.xml");

/// Finland's list, verified through the verified list of lists.
///
/// The real document rather than a fixture assembled here: a hand-built list
/// would prove the matcher agrees with the builder, and the names in a published
/// list are exactly the thing whose encoding this module bets on.
fn finnish_list() -> VerifiedTrustedList {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some("FI"))
        .expect("the LOTL points at Finland")
        .clone();
    verify_trusted_list(FI_LIST, &pointer).expect("Finland's list verifies")
}

/// A seal from the local backend, and the directory holding its key.
///
/// The directory is returned because dropping it removes the key store.
fn local_seal() -> (Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id.sign_detached(&[0x11; 32]).expect("sign");
    (seal, dir)
}

/// The same seal with its certificate's issuer name replaced.
///
/// Nothing is re-signed, deliberately. The relabelling invalidates the
/// certificate's own signature — the one its issuer made over its
/// `tbsCertificate` — and leaves the CMS signature intact, which is precisely the
/// asymmetry these tests exist to show.
fn seal_issued_by(issuer: x509_cert::name::Name) -> (Vec<u8>, tempfile::TempDir) {
    let (der, dir) = local_seal();

    let info = ContentInfo::from_der(&der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");

    let certs = sd.certificates.as_ref().expect("a certificate");
    let mut choices = certs.0.as_slice().to_vec();
    let cms::cert::CertificateChoices::Certificate(cert) = &mut choices[0] else {
        panic!("the local backend embeds an X.509 certificate");
    };
    cert.tbs_certificate.issuer = issuer;

    let mut set = der::asn1::SetOfVec::new();
    set.insert(choices.remove(0)).expect("certificate");
    sd.certificates = Some(cms::signed_data::CertificateSet(set));

    let info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    };
    (info.to_der().expect("re-encode"), dir)
}

/// A qualified CA that Finland lists as granted right now, and its subject name.
fn granted_finnish_ca() -> (String, x509_cert::name::Name) {
    let list = finnish_list();
    let now = Utc::now();

    for (provider, services) in list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA)
    {
        for service in services {
            if !service.history.was_granted_at(now) {
                continue;
            }
            for c in &service.certificates {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(c.trim())
                    .expect("base64");
                if let Ok(cert) = x509_cert::Certificate::from_der(&bytes) {
                    return (
                        provider.name.clone().unwrap_or_default(),
                        cert.tbs_certificate.subject,
                    );
                }
            }
        }
    }
    panic!("Finland lists at least one granted qualified CA");
}

/// A locally signed seal says so, structurally.
///
/// The answer the operator asks for first, and the one that was previously
/// obtainable only by reading configuration. Nothing here consults
/// `SEAL_PROVIDER`: the certificate is its own issuer, which no environment
/// variable can change.
#[test]
fn a_locally_signed_seal_is_self_issued_and_claims_nothing() {
    let (seal, _dir) = local_seal();
    let verdict = qualify(&seal, &[finnish_list()], Utc::now()).expect("readable seal");

    let IssuerStanding::SelfIssued { subject } = &verdict.issuer else {
        panic!("the local backend is self-signed: {:?}", verdict.issuer);
    };
    assert!(!subject.is_empty(), "and it names itself");

    assert!(
        !verdict.is_provider_seal(),
        "no provider stands behind a self-issued certificate"
    );
    assert_eq!(
        verdict.creation_device,
        CreationDevice::NotAQualifiedCertificate,
        "and it carries no QCStatements, so it is not presenting as a qualified certificate"
    );
}

/// Self-issued is decided before any list is consulted.
///
/// So the verdict is the same with no lists at all — which matters because a
/// node that cannot reach a Trusted List must still be able to tell an operator
/// that its seals are locally signed. Degrading that to "unknown" would hide the
/// finding that needs no network to make.
#[test]
fn a_locally_signed_seal_needs_no_trusted_list_to_be_recognised() {
    let (seal, _dir) = local_seal();
    let with_list = qualify(&seal, &[finnish_list()], Utc::now()).expect("readable");
    let without = qualify(&seal, &[], Utc::now()).expect("readable");
    assert_eq!(with_list, without);
}

/// An issuer no list names is reported as unlisted, not as unknown.
#[test]
fn an_issuer_no_list_names_is_not_listed() {
    let issuer: x509_cert::name::Name = "CN=Definitely Not A Qualified CA,C=FI"
        .parse()
        .expect("a name");
    let (seal, _dir) = seal_issued_by(issuer);

    let verdict = qualify(&seal, &[finnish_list()], Utc::now()).expect("readable seal");

    let IssuerStanding::NotListed { issuer } = &verdict.issuer else {
        panic!("nothing lists that name: {:?}", verdict.issuer);
    };
    assert!(issuer.contains("Definitely Not A Qualified CA"));
    assert!(
        verdict.is_provider_seal(),
        "an issuer other than the subject means somebody issued it, listed or not"
    );
}

/// **Naming a listed CA is enough to reach the top verdict.**
///
/// The limitation the module documentation describes, pinned as a test rather
/// than left as prose — because prose next to a variant called
/// `QualifiedAtSealing` is what gets skimmed.
///
/// This seal was minted by the local development backend. Its certificate was
/// then relabelled to carry a genuinely qualified Finnish CA's name, and nothing
/// else about it was touched — the CA never saw it. [`qualify`] reports
/// `QualifiedAtSealing` anyway, because it matches a name and builds no
/// certificate path.
///
/// **And the seal still verifies.** That is the part worth pausing on. A CMS
/// signature covers the signed attributes, not the certificate travelling beside
/// them, so relabelling the issuer leaves it intact; what the relabelling breaks
/// is the *certificate's own* signature, made by its issuer over its
/// `tbsCertificate`, and nothing in this crate checks that. So the two questions
/// this workspace can answer today — *does it verify* and *who does it name* —
/// both come back clean on a seal that is neither qualified nor issued by anyone.
///
/// That is the correct behaviour for what these functions claim to be, and it is
/// exactly why nothing here returns a `SealChecks` rung. The step that closes the
/// gap is path verification: checking the issuer's signature over this
/// certificate, which is the one check that would fail here.
#[test]
fn naming_a_listed_ca_reaches_the_top_verdict_without_any_path_check() {
    let (provider_name, ca_subject) = granted_finnish_ca();
    let (seal, _dir) = seal_issued_by(ca_subject);

    let verdict = qualify(&seal, &[finnish_list()], Utc::now()).expect("readable seal");

    let IssuerStanding::QualifiedAtSealing {
        provider,
        territory,
        ..
    } = &verdict.issuer
    else {
        panic!("a name match reaches this verdict: {:?}", verdict.issuer);
    };
    assert_eq!(provider.as_deref(), Some(provider_name.as_str()));
    assert_eq!(territory.as_deref(), Some("FI"));

    assert!(
        crate::cades::verify_against_embedded_certificate(&seal).expect("checkable"),
        "and the signature still verifies, because it covers the signed attributes \
         rather than the certificate beside them — so neither check this crate can \
         run today notices the relabelling"
    );
}

/// A seal predating the list's history is not granted, and not known either.
///
/// Art. 32(1)(b) asks about the time of sealing. A present-tense check would
/// certify a seal made before its issuer was ever qualified, so the same
/// certificate that passes above fails here on the date alone.
///
/// The status is `None` rather than a withdrawn status: the list is silent about
/// 1999, which is a different finding from a recorded refusal, and the type keeps
/// them apart.
#[test]
fn a_seal_older_than_the_lists_history_is_not_qualified() {
    let (_, ca_subject) = granted_finnish_ca();
    let (seal, _dir) = seal_issued_by(ca_subject);

    let long_ago = "1999-01-01T00:00:00Z"
        .parse::<DateTime<Utc>>()
        .expect("a time");
    let verdict = qualify(&seal, &[finnish_list()], long_ago).expect("readable seal");

    let IssuerStanding::NotQualifiedAtSealing { status, .. } = &verdict.issuer else {
        panic!("nothing was granted in 1999: {:?}", verdict.issuer);
    };
    assert!(
        status.is_none(),
        "the list says nothing about 1999, which is not the same as saying no"
    );
}

/// Unreadable bytes are an error, not a verdict.
///
/// The opposite choice from [`crate::cades::signer_certificate_thumbprint`],
/// which degrades to `None` so a stored seal is never lost to a convenience
/// field. Here the whole answer is the verdict, and inventing one for bytes that
/// could not be read is how a report comes to say "not qualified" about a seal
/// nobody looked at.
#[test]
fn bytes_that_are_not_a_seal_yield_no_verdict() {
    assert!(qualify(b"not a CMS structure", &[], Utc::now()).is_err());
}
