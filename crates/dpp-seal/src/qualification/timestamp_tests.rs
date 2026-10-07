//! Who stamped a seal's time, and what that makes the time worth.
//!
//! It shares the real Finnish list, `name_signer` and `reencode` with the
//! issuer tests through `test_support`, rather than copying them.

use super::*;
use base64::Engine as _;
use der::Decode as _;

use chrono::Utc;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

use crate::qualification::test_support::{finnish_list, local_seal, name_signer, reencode};

use dpp_domain::seal::{SealConformanceLevel, SealFormat, SealedEnvelope};
use dpp_domain::trusted_list::{TrustServiceHistory, TrustServiceStatusPeriod};
use dpp_types::{
    CertificateStanding, SealBinding, SealInspector as _, SealValidationStatus,
    ValidationIndication, ValidationSubIndication,
};

use crate::inspect::CadesInspector;

/// A timestamping identity: its key, and a certificate for it.
struct Authority {
    key_der: Vec<u8>,
    cert_der: Vec<u8>,
}

fn authority_key() -> rcgen::KeyPair {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key")
}

fn authority_params(name: &str, is_ca: bool) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    if is_ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    }
    params
}

/// A certificate authority named `name`. Two calls with one name are two
/// different keys under one name — which is what a relabelling needs.
fn timestamp_ca(name: &str) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
    rcgen::CertifiedIssuer::self_signed(authority_params(name, true), authority_key())
        .expect("a self-signed CA")
}

/// A timestamping unit's identity, issued by `ca`.
fn authority_issued_by(ca: &rcgen::CertifiedIssuer<'static, rcgen::KeyPair>) -> Authority {
    let key = authority_key();
    let mut params = authority_params("Test Timestamp Unit", false);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::TimeStamping];
    let cert = params
        .signed_by(&key, &**ca)
        .expect("a unit certificate signed by its CA");
    Authority {
        key_der: key.serialize_der(),
        cert_der: cert.der().to_vec(),
    }
}

/// A seal at `level` whose timestamps are made by `authority`.
///
/// The local sealer loads its timestamping identity from the directory it is
/// pointed at when the files are there, so writing them first hands it an
/// authority of the test's choosing — the real sealer and the real token builder,
/// with nothing in production code made injectable for the purpose.
fn seal_stamped_by(
    authority: &Authority,
    level: SealConformanceLevel,
) -> (Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("tsa-key.pkcs8.der"), &authority.key_der).expect("key");
    std::fs::write(dir.path().join("tsa-cert.der"), &authority.cert_der).expect("certificate");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id.sign_detached_at(&[0x11; 32], level).expect("sign");
    (seal, dir)
}

/// A list naming `certificate_der` as a `TSA/QTST` service with this history.
fn list_naming_authority(
    certificate_der: &[u8],
    history: Vec<TrustServiceStatusPeriod>,
) -> VerifiedTrustedList {
    let service = crate::trustlist::ListedService {
        service_type: TrustServiceType::new(TrustServiceType::QUALIFIED_TIMESTAMP_AUTHORITY),
        name: Some("Test Qualified Timestamp".to_owned()),
        history: TrustServiceHistory::new(history),
        certificates: vec![base64::engine::general_purpose::STANDARD.encode(certificate_der)],
    };
    VerifiedTrustedList::asserted_for_tests(
        crate::trustlist::UnverifiedTrustedList {
            territory: Some("FI".to_owned()),
            providers: vec![crate::trustlist::ListedProvider {
                name: Some("Test Timestamp Oy".to_owned()),
                services: vec![service],
            }],
        },
        "test",
    )
}

fn granted_since(date: &str) -> TrustServiceStatusPeriod {
    TrustServiceStatusPeriod {
        status: TrustServiceStatus::Granted,
        starting_at: date.parse().expect("a time"),
    }
}

fn withdrawn_since(date: &str) -> TrustServiceStatusPeriod {
    TrustServiceStatusPeriod {
        status: TrustServiceStatus::Withdrawn,
        starting_at: date.parse().expect("a time"),
    }
}

/// **A `B-B` seal has no time to ask a list about, and says so.**
///
/// A finding, not a failure to read: the seal parsed, and carries nothing a
/// timestamp authority vouched for. `NoAttestedTime` is what a reader needs to tell
/// this apart from a seal nobody could open.
#[test]
fn a_seal_with_no_timestamp_has_no_attested_time() {
    let (seal, _dir) = local_seal();

    assert_eq!(
        qualify_timestamp(&seal, &[finnish_list()], &[]).expect("readable seal"),
        TimestampStanding::NoAttestedTime
    );
}

/// The local development authority is self-issued, with or without any list.
///
/// Decided from the certificate alone, so a node with no network still knows its
/// seals' times are the signer's own word — the same property
/// `a_locally_signed_seal_needs_no_trusted_list_to_be_recognised` pins for the
/// seal's issuer.
#[test]
fn the_local_development_authority_is_self_issued_with_or_without_lists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineT)
        .expect("sign");

    for lists in [vec![], vec![finnish_list()]] {
        let standing = qualify_timestamp(&seal, &lists, &[]).expect("readable seal");
        assert!(
            matches!(standing, TimestampStanding::SelfIssued { .. }),
            "{} lists: {standing:?}",
            lists.len()
        );
        assert!(!standing.counts_as_proof_of_existence());
    }
}

/// An authority the list names **directly** is qualified, with no path at all.
///
/// A `TSA/QTST` entry's service identity is usually the unit's own certificate,
/// which is why a seal's issuer logic — CA-only — would have missed this.
#[test]
fn an_authority_the_list_names_directly_is_qualified() {
    let ca = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&ca);
    let (seal, _dir) = seal_stamped_by(&authority, SealConformanceLevel::BaselineT);

    let list = list_naming_authority(
        &authority.cert_der,
        vec![granted_since("2000-01-01T00:00:00Z")],
    );
    let standing = qualify_timestamp(&seal, &[list], &[]).expect("readable seal");

    let TimestampStanding::QualifiedAtStamping { provider, .. } = &standing else {
        panic!("the unit's own certificate is listed: {standing:?}");
    };
    assert_eq!(provider.as_deref(), Some("Test Timestamp Oy"));
    assert!(standing.counts_as_proof_of_existence());
}

/// An authority issued by a **listed CA** is qualified once the path verifies.
#[test]
fn an_authority_issued_by_a_listed_ca_is_qualified_through_the_path() {
    let ca = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&ca);
    let (seal, _dir) = seal_stamped_by(&authority, SealConformanceLevel::BaselineT);

    let list = list_naming_authority(ca.der(), vec![granted_since("2000-01-01T00:00:00Z")]);
    let standing = qualify_timestamp(&seal, &[list], &[]).expect("readable seal");

    assert!(
        matches!(standing, TimestampStanding::QualifiedAtStamping { .. }),
        "the CA is listed and really issued this unit: {standing:?}"
    );
}

/// Qualified is judged **at the stamp's own time**, not at some other moment.
///
/// The service is granted in 2000 and withdrawn in 2001, and the token says it was
/// made today, so it is not qualified at stamping. The converse is the half that
/// bites: the same list with the withdrawal in the *future* must qualify, because
/// a withdrawal that has not happened does not unmake a stamp.
#[test]
fn an_authority_is_judged_at_the_moment_it_stamped() {
    let ca = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&ca);
    let (seal, _dir) = seal_stamped_by(&authority, SealConformanceLevel::BaselineT);

    let withdrawn = list_naming_authority(
        &authority.cert_der,
        vec![
            granted_since("2000-01-01T00:00:00Z"),
            withdrawn_since("2001-01-01T00:00:00Z"),
        ],
    );
    let standing = qualify_timestamp(&seal, &[withdrawn], &[]).expect("readable seal");
    let TimestampStanding::NotQualifiedAtStamping { status, .. } = &standing else {
        panic!("it was withdrawn long before it stamped: {standing:?}");
    };
    assert_eq!(status, &Some(TrustServiceStatus::Withdrawn));
    assert!(!standing.counts_as_proof_of_existence());

    let not_yet = list_naming_authority(
        &authority.cert_der,
        vec![
            granted_since("2000-01-01T00:00:00Z"),
            withdrawn_since("2999-01-01T00:00:00Z"),
        ],
    );
    assert!(
        matches!(
            qualify_timestamp(&seal, &[not_yet], &[]).expect("readable seal"),
            TimestampStanding::QualifiedAtStamping { .. }
        ),
        "a withdrawal that has not happened yet does not unmake a stamp"
    );
}

/// **A unit relabelled with a listed CA's name is caught, not believed.**
///
/// The name matches a listed CA; the signature does not. Without the path check
/// this is the one-line forgery that reaches the top verdict.
#[test]
fn an_authority_relabelled_with_a_listed_cas_name_is_caught() {
    let real = timestamp_ca("Test Timestamp CA");
    let impostor = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&impostor);
    let (seal, _dir) = seal_stamped_by(&authority, SealConformanceLevel::BaselineT);

    let list = list_naming_authority(real.der(), vec![granted_since("2000-01-01T00:00:00Z")]);
    let standing = qualify_timestamp(&seal, &[list], &[]).expect("readable seal");

    assert!(
        matches!(
            standing,
            TimestampStanding::SignatureNotFromListedAuthority { .. }
        ),
        "the name is a listed CA's and the signature is not: {standing:?}"
    );
    assert!(!standing.counts_as_proof_of_existence());
}

/// A token that does not carry its CA cannot be followed, and says that — not
/// that the authority is unlisted.
#[test]
fn an_authority_whose_ca_is_not_carried_reports_an_incomplete_chain() {
    let ca = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&ca);
    let (seal, _dir) = seal_stamped_by(&authority, SealConformanceLevel::BaselineT);

    // Finland's real list names nothing this test made, and the token carries only
    // the unit's own certificate.
    let standing = qualify_timestamp(&seal, &[finnish_list()], &[]).expect("readable seal");

    let TimestampStanding::ChainIncomplete { missing_issuer, .. } = &standing else {
        panic!("the CA is neither listed nor carried: {standing:?}");
    };
    assert!(
        missing_issuer.contains("Test Timestamp CA"),
        "{missing_issuer}"
    );
}

// ─── What the time is worth to a verdict ─────────────────────────────────────

/// A `B-T` seal whose **signing certificate had expired**, stamped by `authority`.
///
/// The signature is untouched, so the timestamp still binds to it; only the
/// certificate beside it is swapped for one whose window ended 30 days ago. That is
/// the case the window check exists to catch — and the case a forged time would be
/// used to disguise.
fn expired_seal_stamped_by(authority: &Authority) -> (Vec<u8>, tempfile::TempDir) {
    fn at(offset_days: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() + offset_days * 86_400)
            .expect("a representable date")
    }

    let (seal, dir) = seal_stamped_by(authority, SealConformanceLevel::BaselineT);

    let signing_ca = timestamp_ca("Test Sealing CA");
    let mut params = authority_params("Test Expired Sealing Certificate", false);
    params.not_before = at(-400);
    params.not_after = at(-30);
    let key = authority_key();
    let leaf = params
        .signed_by(&key, &*signing_ca)
        .expect("an expired leaf");
    let leaf = x509_cert::Certificate::from_der(leaf.der()).expect("a certificate");

    let info = ContentInfo::from_der(&seal).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");
    let mut set = der::asn1::SetOfVec::new();
    set.insert(cms::cert::CertificateChoices::Certificate(leaf.clone()))
        .expect("certificate");
    sd.certificates = Some(cms::signed_data::CertificateSet(set));
    name_signer(&mut sd, &leaf);
    (reencode(sd), dir)
}

fn stored(seal: &[u8]) -> SealedEnvelope {
    SealedEnvelope {
        format: SealFormat::Cades,
        seal_value: base64::engine::general_purpose::STANDARD.encode(seal),
        signing_cert_ref: None,
        conformance_level: Some(SealConformanceLevel::BaselineT),
        sealed_at: Utc::now(),
        placeholder: false,
    }
}

fn verdict_of(
    inspector: &CadesInspector,
    envelope: &SealedEnvelope,
) -> (CertificateStanding, SealValidationStatus) {
    let standing = inspector
        .certificate_standing(envelope, Utc::now())
        .expect("a readable seal");
    let status = SealValidationStatus::of(&SealBinding::CoversThisSignature, Some(&standing));
    (standing, status)
}

/// **A qualified authority's time proves the certificate had expired.**
///
/// The settled case: the window is outside and the time that says so is believed,
/// so this is `TOTAL-FAILED` / `EXPIRED`. The control for the test below, and what
/// shows the gate lets a believed time through rather than blocking every one.
#[test]
fn a_qualified_authoritys_time_makes_an_expired_certificate_a_failure() {
    let ca = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&ca);
    let (seal, _dir) = expired_seal_stamped_by(&authority);
    let list = list_naming_authority(
        &authority.cert_der,
        vec![granted_since("2000-01-01T00:00:00Z")],
    );
    let inspector = CadesInspector::new().with_trusted_lists(vec![list], vec![]);

    let (standing, status) = verdict_of(&inspector, &stored(&seal));

    assert!(standing.judged_at.attested, "{standing:?}");
    assert_eq!(status.indication, ValidationIndication::TotalFailed);
    assert_eq!(
        status.sub_indication,
        Some(ValidationSubIndication::Expired)
    );
}

/// 🚨 **A time nobody lists cannot settle a certificate finding.**
///
/// The escalation the issue describes. The seal's certificate had expired when it
/// was made; the token is genuine — real signature, real imprint, inside its own
/// certificate's window — and its authority is one the lists do not name. Before
/// the gate that time was believed, and the verdict was whatever the seal's own
/// holder arranged. Now the certificate is judged against this node's clock and
/// reported as **unproven**: `INDETERMINATE` / `OUT_OF_BOUNDS_NO_POE`.
///
/// And the time itself is still there to be read — what is withheld is what it is
/// *worth*, not whether it is shown.
#[test]
fn an_unlisted_authoritys_time_cannot_settle_a_certificate_finding() {
    let ca = timestamp_ca("Test Timestamp CA");
    let authority = authority_issued_by(&ca);
    let (seal, _dir) = expired_seal_stamped_by(&authority);
    let envelope = stored(&seal);

    // No lists at all: the weakest position a node can be in, and the one every
    // fresh deployment starts from.
    let inspector = CadesInspector::new();
    let (standing, status) = verdict_of(&inspector, &envelope);

    assert!(
        !standing.judged_at.attested,
        "an authority nobody lists must not make the moment a proof of existence: {standing:?}"
    );
    assert_eq!(status.indication, ValidationIndication::Indeterminate);
    assert_eq!(
        status.sub_indication,
        Some(ValidationSubIndication::OutOfBoundsNoPoe)
    );

    assert!(
        inspector.attested_sealing_time(&envelope).is_some(),
        "the time stays visible; only its weight is withheld"
    );
    assert!(
        inspector
            .timestamp_authority(&envelope)
            .is_some_and(|s| !s.counts_as_proof_of_existence()),
        "and the standing says why it carries no weight"
    );
}

// ─── Who may renew ───────────────────────────────────────────────────────────

/// A CA-issued timestamping unit whose certificate ends in `ends_in_days`.
fn authority_ending_in(
    ca: &rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    ends_in_days: i64,
) -> Authority {
    let key = authority_key();
    let mut params = authority_params("Test Timestamp Unit", false);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::TimeStamping];
    params.not_before =
        time::OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() - 86_400).expect("a date");
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() + ends_in_days * 86_400)
            .expect("a date");
    let cert = params.signed_by(&key, &**ca).expect("a unit certificate");
    Authority {
        key_der: key.serialize_der(),
        cert_der: cert.der().to_vec(),
    }
}

/// A source stamping as `authority`, at the moment `when`.
fn source_for(
    authority: &Authority,
    when: chrono::DateTime<Utc>,
) -> (crate::local::LocalTimestampSource, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("tsa-key.pkcs8.der"), &authority.key_der).expect("key");
    std::fs::write(dir.path().join("tsa-cert.der"), &authority.cert_der).expect("certificate");
    let source = crate::local::LocalTimestampSource::load_or_create(dir.path())
        .expect("an authority")
        .with_clock(move || when);
    (source, dir)
}

/// **Production renews only from an authority the lists name; development from
/// any.**
///
/// An archive timestamp keeps a retention-locked seal verifiable for years. One
/// from an authority nobody can vouch for protects nothing while *looking* like
/// protection — a seal that reads as freshly renewed and is not — so a node that
/// requires qualification must refuse it, and a node holding no lists, which can
/// vouch for nobody, must therefore renew nothing. The same renewal from an
/// authority a list names goes through, and a development node needs neither.
#[tokio::test]
async fn production_renews_only_from_an_authority_the_lists_name() {
    use crate::timestamp::renewal::RenewalError;

    let now = Utc::now() + chrono::Duration::hours(1);
    let ca = timestamp_ca("Test Timestamp CA");
    let (seal, _dir) = seal_stamped_by(
        &authority_ending_in(&ca, 30),
        SealConformanceLevel::BaselineLta,
    );
    let mut envelope = stored(&seal);
    envelope.conformance_level = Some(SealConformanceLevel::BaselineLta);

    let renewing = authority_ending_in(&ca, 5 * 365);
    let (source, _src) = source_for(&renewing, now);

    // Production, no lists: nobody can be vouched for, so nothing is renewed.
    let err = CadesInspector::new()
        .renew_archive_timestamp(&envelope, &source, now, true)
        .await
        .expect_err("a node that can vouch for nobody must not renew");
    assert!(
        matches!(
            err,
            RenewalError::AuthorityRefused(TimestampStanding::ChainIncomplete { .. })
        ),
        "{err}"
    );

    // Production, and a list that names the renewing authority: renewed.
    let list = list_naming_authority(
        &renewing.cert_der,
        vec![granted_since("2000-01-01T00:00:00Z")],
    );
    let listed = CadesInspector::new().with_trusted_lists(vec![list], vec![]);
    let renewed = listed
        .renew_archive_timestamp(&envelope, &source, now, true)
        .await
        .expect("a qualified authority may renew");
    assert!(renewed.expires > renewed.previous_expires);
    assert_ne!(
        renewed.envelope.seal_value, envelope.seal_value,
        "the stored seal carries the new archive timestamp"
    );
    assert_eq!(renewed.envelope.sealed_at, envelope.sealed_at);
    assert_eq!(renewed.envelope.signing_cert_ref, envelope.signing_cert_ref);
    assert_eq!(
        renewed.envelope.conformance_level,
        envelope.conformance_level
    );

    // Development: no lists and no qualification required.
    CadesInspector::new()
        .renew_archive_timestamp(&envelope, &source, now, false)
        .await
        .expect("a development node accepts an authority nobody lists");
}
