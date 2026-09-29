//! What the verdict says about a seal, and what it deliberately does not.

use super::*;
use crate::trustlist::{verify_lotl, verify_trusted_list};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use dpp_types::CreationDevice;

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
    let relabelled = cert.clone();

    let mut set = der::asn1::SetOfVec::new();
    set.insert(choices.remove(0)).expect("certificate");
    sd.certificates = Some(cms::signed_data::CertificateSet(set));
    // The `SignerInfo` names its certificate by issuer and serial, so relabelling
    // the certificate without re-pointing the signer would leave a seal naming a
    // certificate it does not carry — which the parser rejects outright, and
    // which is a different, less interesting failure than the one under test.
    name_signer(&mut sd, &relabelled);

    (reencode(sd), dir)
}

/// Point the seal's single `SignerInfo` at `certificate`.
fn name_signer(sd: &mut SignedData, certificate: &x509_cert::Certificate) {
    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    signers[0].sid = cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
        cms::cert::IssuerAndSerialNumber {
            issuer: certificate.tbs_certificate.issuer.clone(),
            serial_number: certificate.tbs_certificate.serial_number.clone(),
        },
    );
    let mut set = der::asn1::SetOfVec::new();
    set.insert(signers.remove(0)).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(set);
}

/// Re-encode a modified `SignedData` as a detached CAdES seal.
fn reencode(sd: SignedData) -> Vec<u8> {
    ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode")
}

/// A seal carrying exactly `certificates`, the first being the signer's.
///
/// The CMS signature is left as the local backend made it and no longer matches
/// the certificate now named — which is fine and deliberate, because `qualify`
/// asks who issued the certificate, not whether the seal verifies. The two are
/// separate questions and a helper that conflated them would hide it.
fn seal_carrying(certificates: &[Vec<u8>]) -> (Vec<u8>, tempfile::TempDir) {
    let (der, dir) = local_seal();
    let info = ContentInfo::from_der(&der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");

    let parsed: Vec<x509_cert::Certificate> = certificates
        .iter()
        .map(|d| x509_cert::Certificate::from_der(d).expect("a certificate"))
        .collect();

    let mut set = der::asn1::SetOfVec::new();
    for c in &parsed {
        set.insert(cms::cert::CertificateChoices::Certificate(c.clone()))
            .expect("certificate");
    }
    sd.certificates = Some(cms::signed_data::CertificateSet(set));
    name_signer(&mut sd, &parsed[0]);

    (reencode(sd), dir)
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
    let verdict = qualify(&seal, &[finnish_list()], &[], Utc::now()).expect("readable seal");

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
    let with_list = qualify(&seal, &[finnish_list()], &[], Utc::now()).expect("readable");
    let without = qualify(&seal, &[], &[], Utc::now()).expect("readable");
    assert_eq!(with_list, without);
}

/// A seal carrying one certificate and naming an unlisted issuer reports that
/// the **chain could not be followed**, not that the provider is unlisted.
///
/// The two readings are different accusations. "No list names this issuer" is a
/// statement about the Union's lists; "the seal did not carry the certificate
/// that would have led to one" is a statement about the seal. Only the second is
/// supportable here, because the certificate above this one — listed or not —
/// was never shipped.
#[test]
fn a_seal_whose_chain_runs_out_reports_that_rather_than_an_unlisted_issuer() {
    let issuer: x509_cert::name::Name = "CN=Definitely Not A Qualified CA,C=FI"
        .parse()
        .expect("a name");
    let (seal, _dir) = seal_issued_by(issuer);

    let verdict = qualify(&seal, &[finnish_list()], &[], Utc::now()).expect("readable seal");

    let IssuerStanding::ChainIncomplete {
        issuer,
        missing_issuer,
    } = &verdict.issuer
    else {
        panic!(
            "the seal carries no certificate for its issuer: {:?}",
            verdict.issuer
        );
    };
    assert!(issuer.contains("Definitely Not A Qualified CA"));
    assert_eq!(
        issuer, missing_issuer,
        "with one certificate in the seal, the name it needs next is its own issuer"
    );
    assert!(
        verdict.is_provider_seal(),
        "an issuer other than the subject means somebody issued it, listed or not"
    );
}

/// **A certificate relabelled with a listed CA's name is caught.**
///
/// The case the path check exists for, and one that reached the top verdict
/// before it. A seal minted by the local development backend has its certificate
/// relabelled to carry a genuinely qualified Finnish CA's name; nothing else
/// about it is touched, and that CA never saw it.
///
/// **The seal still verifies as a seal**, which is the part worth pausing on. A
/// CMS signature covers the signed attributes, not the certificate travelling
/// beside them, so relabelling the issuer leaves it intact. What the relabelling
/// breaks is the *certificate's own* signature, made by its issuer over its
/// `tbsCertificate` — so this check is the only thing in the workspace that
/// notices.
#[test]
fn a_certificate_relabelled_with_a_listed_cas_name_is_caught() {
    let (provider_name, ca_subject) = granted_finnish_ca();
    let (seal, _dir) = seal_issued_by(ca_subject);

    let verdict = qualify(&seal, &[finnish_list()], &[], Utc::now()).expect("readable seal");

    let IssuerStanding::SignatureNotFromListedCa {
        provider,
        territory,
        ..
    } = &verdict.issuer
    else {
        panic!(
            "no listed key signed this certificate: {:?}",
            verdict.issuer
        );
    };
    assert_eq!(provider.as_deref(), Some(provider_name.as_str()));
    assert_eq!(territory.as_deref(), Some("FI"));

    assert!(
        crate::cades::verify_against_embedded_certificate(&seal).expect("checkable"),
        "and the seal itself still verifies, which is why the certificate's own \
         signature has to be checked separately"
    );
}

/// A forgery is reported as a forgery, not as a date problem.
///
/// Ordering, stated as a test. The same relabelled certificate, dated to a
/// moment the list says nothing about: were the status consulted first, this
/// would come back `NotQualifiedAtSealing` and read as paperwork trouble with an
/// otherwise sound seal. The path is checked first because the status of a CA
/// that did not issue a certificate is beside the point.
#[test]
fn a_forged_certificate_is_reported_as_forged_rather_than_as_a_date_problem() {
    let (_, ca_subject) = granted_finnish_ca();
    let (seal, _dir) = seal_issued_by(ca_subject);

    let long_ago = "1999-01-01T00:00:00Z"
        .parse::<DateTime<Utc>>()
        .expect("a time");
    let verdict = qualify(&seal, &[finnish_list()], &[], long_ago).expect("readable seal");

    assert!(
        matches!(
            verdict.issuer,
            IssuerStanding::SignatureNotFromListedCa { .. }
        ),
        "the path is checked before the status: {:?}",
        verdict.issuer
    );
}

// ─── A certificate authority whose key the test holds ────────────────────────

/// A root, an optional intermediate, and a certificate genuinely issued under them.
struct TestChain {
    /// The root's DER — what a trusted list would carry.
    root: Vec<u8>,
    /// The intermediate's DER, when the leaf was issued one level down.
    intermediate: Option<Vec<u8>>,
    /// The leaf certificate's DER.
    leaf: Vec<u8>,
}

/// Generate a certificate authority and a certificate it really issued.
///
/// The only way to exercise the **positive** path today. No published trusted
/// list carries a CA whose private key a test can hold, and this workspace can
/// obtain no QTSP credential, so every real-data test can only reach the failure
/// branches. Here the test is the authority, and a real signature is checked to
/// be really recognised.
///
/// P-256 because that is what `rcgen` generates. The published population is
/// RSA, P-384 and P-521 — see `trustlist::ca_key_survey` — so this exercises the
/// mechanism rather than the algorithms, and the algorithm coverage is a feature
/// list in `Cargo.toml` pinned to that measurement.
fn test_chain(with_intermediate: bool) -> TestChain {
    fn params(name: &str, is_ca: bool) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params
    }
    fn key() -> rcgen::KeyPair {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key")
    }

    let root = rcgen::CertifiedIssuer::self_signed(params("Test Root CA", true), key())
        .expect("a self-signed root");

    let intermediate = with_intermediate.then(|| {
        rcgen::CertifiedIssuer::signed_by(params("Test Intermediate CA", true), key(), &root)
            .expect("an intermediate signed by the root")
    });

    let leaf_key = key();
    let leaf_params = params("Test Sealing Certificate", false);
    let leaf = match &intermediate {
        Some(issuer) => leaf_params.signed_by(&leaf_key, &**issuer),
        None => leaf_params.signed_by(&leaf_key, &*root),
    }
    .expect("a leaf signed by its issuer");

    TestChain {
        root: root.der().to_vec(),
        intermediate: intermediate.map(|i| i.der().to_vec()),
        leaf: leaf.der().to_vec(),
    }
}

/// A trusted list naming `ca_der` as a qualified CA, granted since 2000.
fn list_naming(ca_der: &[u8]) -> VerifiedTrustedList {
    use dpp_domain::trusted_list::{TrustServiceHistory, TrustServiceStatusPeriod};

    let service = crate::trustlist::ListedService {
        service_type: TrustServiceType::new(TrustServiceType::QUALIFIED_CERTIFICATE_CA),
        name: Some("Test Qualified CA".to_owned()),
        history: TrustServiceHistory::new(vec![TrustServiceStatusPeriod {
            status: TrustServiceStatus::Granted,
            starting_at: "2000-01-01T00:00:00Z".parse().expect("a time"),
        }]),
        certificates: vec![base64::engine::general_purpose::STANDARD.encode(ca_der)],
    };
    VerifiedTrustedList::asserted_for_tests(
        crate::trustlist::UnverifiedTrustedList {
            territory: Some("FI".to_owned()),
            providers: vec![crate::trustlist::ListedProvider {
                name: Some("Test Provider Oy".to_owned()),
                services: vec![service],
            }],
        },
        "test",
    )
}

/// A certificate a listed CA really issued reaches the top verdict.
///
/// The positive case, which could not be written before the path check existed:
/// `QualifiedAtSealing` now means the issuer is established, not merely claimed.
#[test]
fn a_certificate_a_listed_ca_really_issued_is_qualified() {
    let chain = test_chain(false);
    let (seal, _dir) = seal_carrying(std::slice::from_ref(&chain.leaf));

    let verdict =
        qualify(&seal, &[list_naming(&chain.root)], &[], Utc::now()).expect("readable seal");

    let IssuerStanding::QualifiedAtSealing { provider, .. } = &verdict.issuer else {
        panic!("a genuinely issued certificate: {:?}", verdict.issuer);
    };
    assert_eq!(provider.as_deref(), Some("Test Provider Oy"));
}

/// The walk climbs an intermediate the seal carries to reach a listed root.
///
/// Not a refinement. Member States do not publish the same thing: Italy's list
/// is 194 self-signed roots out of 203 entries, so for most Italian providers
/// the listed certificate is **not** the one that issued the seal. Without this,
/// those seals report `NotListed` — which looks like an unlisted provider and is
/// in fact a missing hop.
#[test]
fn an_intermediate_carried_by_the_seal_reaches_a_listed_root() {
    let chain = test_chain(true);
    let intermediate = chain.intermediate.clone().expect("an intermediate");
    let (seal, _dir) = seal_carrying(&[chain.leaf.clone(), intermediate]);

    let verdict =
        qualify(&seal, &[list_naming(&chain.root)], &[], Utc::now()).expect("readable seal");

    assert!(
        matches!(verdict.issuer, IssuerStanding::QualifiedAtSealing { .. }),
        "the root is two links up, and the seal carries the link between: {:?}",
        verdict.issuer
    );
}

/// **Without the intermediate, the same leaf cannot reach the same root — and
/// the verdict says so in those terms.**
///
/// The control for the test above, and the scenario this distinction exists
/// for: the root *is* listed, the leaf *was* issued under it, and the only thing
/// wrong is that the seal did not carry the link between. Reporting an unlisted
/// provider here would point an operator at their QTSP's qualification when the
/// remedy is a generator setting — ETSI EN 319 122-1 clause 5.2.1 asks for those
/// intermediates where a signature is to be validated through a Trusted List.
#[test]
fn a_leaf_stripped_of_its_intermediate_reports_an_incomplete_chain() {
    let chain = test_chain(true);
    let (seal, _dir) = seal_carrying(std::slice::from_ref(&chain.leaf));

    let verdict =
        qualify(&seal, &[list_naming(&chain.root)], &[], Utc::now()).expect("readable seal");

    let IssuerStanding::ChainIncomplete { missing_issuer, .. } = &verdict.issuer else {
        panic!(
            "the listed root is two links up and the middle one is gone: {:?}",
            verdict.issuer
        );
    };
    assert!(
        missing_issuer.contains("Test Intermediate CA"),
        "the report must name what was missing, or it cannot be acted on: {missing_issuer}"
    );

    // And the strong statement is still available where it is earned: put the
    // intermediate back and the same leaf reaches the listed root.
    let intermediate = chain.intermediate.clone().expect("an intermediate");
    let (whole, _dir) = seal_carrying(&[chain.leaf.clone(), intermediate]);
    assert!(
        matches!(
            qualify(&whole, &[list_naming(&chain.root)], &[], Utc::now())
                .expect("readable seal")
                .issuer,
            IssuerStanding::QualifiedAtSealing { .. }
        ),
        "the gap was the only thing in the way"
    );
}

/// **A complete chain that no list names is still `NotListed`.**
///
/// The other side of the distinction, and the reason `ChainIncomplete` is not
/// simply a softer wording for the same finding. Here the seal carries its whole
/// path up to a certificate that issued itself: everything it has to say about
/// its own provenance has been said, nothing is missing, and no consulted list
/// names any of it. That is a finding about the lists, and it is safe to make.
#[test]
fn a_complete_chain_to_an_unlisted_root_is_still_unlisted() {
    let chain = test_chain(true);
    let intermediate = chain.intermediate.clone().expect("an intermediate");
    let (seal, _dir) = seal_carrying(&[chain.leaf.clone(), intermediate, chain.root.clone()]);

    // Finland's real list rather than a second built one: `test_chain` names
    // every root it makes "Test Root CA", so a hand-built list would collide on
    // the name and report `SignatureNotFromListedCa` — a listed CA carrying that
    // name which did not sign this. That is the correct answer to a different
    // question, and it is not the one under test here.
    let verdict = qualify(&seal, &[finnish_list()], &[], Utc::now()).expect("readable seal");

    assert!(
        matches!(verdict.issuer, IssuerStanding::NotListed { .. }),
        "the chain is whole and ends at a root nobody lists: {:?}",
        verdict.issuer
    );
}

/// A seal predating the list's history is not granted, and not known either.
///
/// Art. 32(1)(b) asks about the time of sealing. A present-tense check would
/// certify a seal made before its issuer was ever qualified, so the same
/// genuinely issued certificate that passes above fails here on the date alone —
/// and it is genuinely issued, so it reaches the status check rather than
/// stopping at the path.
///
/// The status is `None` rather than a withdrawn status: the list is silent about
/// 1999, which is a different finding from a recorded refusal, and the type keeps
/// them apart.
#[test]
fn a_seal_older_than_the_lists_history_is_not_qualified() {
    let chain = test_chain(false);
    let (seal, _dir) = seal_carrying(std::slice::from_ref(&chain.leaf));

    let long_ago = "1999-01-01T00:00:00Z"
        .parse::<DateTime<Utc>>()
        .expect("a time");
    let verdict =
        qualify(&seal, &[list_naming(&chain.root)], &[], long_ago).expect("readable seal");

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
    assert!(qualify(b"not a CMS structure", &[], &[], Utc::now()).is_err());
}

/// An absence verdict says how wide the absence is.
///
/// `NotListed` is the only verdict claiming that something is **not** there, so
/// it is the only one whose truth depends on what was available to look at. The
/// three states below are three different sentences, and before this they were
/// one.
///
/// The middle case is the one that matters in practice. Germany's trusted list
/// does not verify against the mandated profile today and Germany has one of the
/// larger provider populations — so a node consulting the Union is missing it,
/// and a qualified German provider is indistinguishable from an unlisted one
/// unless the verdict says a territory was skipped. This cannot be prevented
/// from here; it can only be made visible.
#[test]
fn a_not_listed_verdict_says_how_much_was_consulted() {
    // A complete chain ending at a self-signed root that no list names — the
    // shape that reaches `NotListed` rather than `ChainIncomplete`.
    let chain = test_chain(true);
    let intermediate = chain.intermediate.clone().expect("an intermediate");
    let (seal, _dir) = seal_carrying(&[chain.leaf.clone(), intermediate, chain.root.clone()]);

    let nothing = qualify(&seal, &[], &[], Utc::now()).expect("readable seal");
    assert!(
        matches!(
            nothing.issuer,
            IssuerStanding::NotListed {
                consulted: 0,
                unchecked: 0,
                ..
            }
        ),
        "a node with no lists loaded must not imply it looked: {:?}",
        nothing.issuer
    );
    assert!(
        nothing
            .to_string()
            .contains("no Trusted List was consulted"),
        "and must say so in the sentence an operator reads: {nothing}"
    );

    let skipped = [UncheckedTerritory {
        territory: "DE".to_owned(),
        reason: "the list does not verify against the mandated signature profile".to_owned(),
    }];
    let partial = qualify(&seal, &[finnish_list()], &skipped, Utc::now()).expect("readable seal");
    assert!(
        matches!(
            partial.issuer,
            IssuerStanding::NotListed {
                consulted: 1,
                unchecked: 1,
                ..
            }
        ),
        "a skipped territory must reach the verdict: {:?}",
        partial.issuer
    );
    assert_eq!(partial.unchecked, skipped, "and carry which, and why");
    assert!(
        partial.to_string().contains("could not be consulted"),
        "the sentence has to admit the gap, or the count is decoration: {partial}"
    );

    // Nothing verified, and every named territory failed — a node whose refresher
    // is running and getting nowhere, which is not the same fact as a node that
    // never looked.
    let none_readable = qualify(&seal, &[], &skipped, Utc::now()).expect("readable seal");
    assert!(
        matches!(
            none_readable.issuer,
            IssuerStanding::NotListed {
                consulted: 0,
                unchecked: 1,
                ..
            }
        ),
        "{:?}",
        none_readable.issuer
    );
    assert!(
        none_readable.to_string().contains("none could be read"),
        "a node that looked and got nowhere must not read as one that never looked: {none_readable}"
    );

    let whole = qualify(&seal, &[finnish_list()], &[], Utc::now()).expect("readable seal");
    assert!(
        matches!(
            whole.issuer,
            IssuerStanding::NotListed {
                consulted: 1,
                unchecked: 0,
                ..
            }
        ),
        "{:?}",
        whole.issuer
    );
    assert!(
        !whole.to_string().contains("could not be consulted"),
        "and must not hedge when there is nothing to hedge about: {whole}"
    );
}
