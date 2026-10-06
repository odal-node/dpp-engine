//! Renewing an archive timestamp, against real seals and real authorities.
//!
//! The local sealer is pointed at a timestamping identity whose certificate window
//! the test chooses, so a seal can be made whose archive timestamp is **already
//! near its end** — which is the only state worth renewing, and one the real local
//! authority (valid to the year 4096) can never be in.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use dpp_domain::seal::SealConformanceLevel;

use super::*;
use crate::cades::{self, ArchivalFreshness};
use crate::local::{LocalIdentity, LocalTimestampSource};

const DIGEST: [u8; 32] = [0x44; 32];

fn at(offset_days: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() + offset_days * 86_400)
        .expect("a representable date")
}

/// Write a timestamping identity into `dir` whose certificate ends in
/// `ends_in_days`, for the local sealer or a local source to load.
fn tsa_identity(dir: &Path, name: &str, ends_in_days: i64) {
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "NOT A QUALIFIED TIMESTAMP");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::TimeStamping];
    params.not_before = at(-1);
    params.not_after = at(ends_in_days);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    let cert = params.self_signed(&key).expect("a certificate");
    std::fs::write(dir.join("tsa-key.pkcs8.der"), key.serialize_der()).expect("key");
    std::fs::write(dir.join("tsa-cert.der"), cert.der()).expect("certificate");
}

/// A `B-LTA` seal whose archive timestamp's authority ends in `ends_in_days`.
fn seal_ending_in(ends_in_days: i64) -> (Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    tsa_identity(dir.path(), "Expiring TSA", ends_in_days);
    let seal = LocalIdentity::load_or_create(dir.path())
        .expect("identity")
        .sign_detached_at(&DIGEST, SealConformanceLevel::BaselineLta)
        .expect("sign");
    (seal, dir)
}

/// A source for an authority whose certificate ends in `ends_in_days`, stamping
/// the moment `when` says.
fn source_ending_in(
    ends_in_days: i64,
    when: DateTime<Utc>,
) -> (LocalTimestampSource, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    tsa_identity(dir.path(), "Renewing TSA", ends_in_days);
    let source = LocalTimestampSource::load_or_create(dir.path())
        .expect("an authority")
        .with_clock(move || when);
    (source, dir)
}

fn expires_of(seal: &[u8], now: DateTime<Utc>) -> DateTime<Utc> {
    match cades::archival_freshness(seal, now).expect("readable") {
        ArchivalFreshness::Current { expires } | ArchivalFreshness::Lapsed { expires } => expires,
        other => panic!("expected an archive timestamp: {other:?}"),
    }
}

fn accept_anyone(_: &TimestampToken) -> Result<(), TimestampStanding> {
    Ok(())
}

/// **A seal due for renewal is renewed by a later authority, and nothing else
/// about it changes.**
///
/// The old protection ends in 30 days; the new authority's certificate runs five
/// years. After the renewal the seal reads as protected until the later date — and
/// its signature, the digest it covers, its level and its signature timestamp are
/// exactly as they were, which is the difference between renewing and re-sealing.
#[tokio::test]
async fn a_due_seal_is_renewed_and_nothing_else_about_it_changes() {
    let now = Utc::now() + Duration::hours(1);
    let (old, _old_dir) = seal_ending_in(30);
    let (source, _src_dir) = source_ending_in(5 * 365, now);

    assert!(
        matches!(
            cades::archival_freshness(&old, now).expect("readable"),
            ArchivalFreshness::Current { expires } if expires < now + Duration::days(40)
        ),
        "the fixture must start near the end of its protection"
    );

    let renewed = renew_archive_timestamp(&old, &source, now, accept_anyone)
        .await
        .expect("a due seal is renewable");

    assert!(
        renewed.expires > now + Duration::days(4 * 365),
        "protected until the new authority's certificate ends: {}",
        renewed.expires
    );
    assert!(renewed.previous_expires < renewed.expires);
    assert_eq!(
        expires_of(&renewed.seal_der, now),
        renewed.expires,
        "and the reader the audit uses agrees"
    );

    // Nothing but the archive timestamp moved.
    assert_eq!(
        cades::covered_digest(&renewed.seal_der).expect("readable"),
        cades::covered_digest(&old).expect("readable"),
        "it covers the same digest"
    );
    assert!(
        cades::verify_against_embedded_certificate(&renewed.seal_der).expect("readable"),
        "its own signature still holds"
    );
    assert_eq!(
        cades::evidenced_level(&renewed.seal_der).expect("readable"),
        Some(SealConformanceLevel::BaselineLta)
    );
    assert_eq!(
        cades::attested_sealing_time(&renewed.seal_der).expect("readable"),
        cades::attested_sealing_time(&old).expect("readable"),
        "the signature timestamp is untouched"
    );
    assert!(
        cades::signer_certificate_thumbprint(&renewed.seal_der).expect("readable")
            == cades::signer_certificate_thumbprint(&old).expect("readable"),
        "the same signing certificate"
    );
}

/// A seal whose protection has **already lapsed** is renewed too.
///
/// Not worth less to try: a stamp now at least protects it from now on, and the
/// alternative is a seal that never will be protected again.
#[tokio::test]
async fn a_lapsed_seal_is_renewed() {
    let now = Utc::now() + Duration::days(100);
    let (old, _old_dir) = seal_ending_in(30);
    let (source, _src_dir) = source_ending_in(5 * 365, now);
    assert!(matches!(
        cades::archival_freshness(&old, now).expect("readable"),
        ArchivalFreshness::Lapsed { .. }
    ));

    let renewed = renew_archive_timestamp(&old, &source, now, accept_anyone)
        .await
        .expect("a lapsed seal is renewable");

    assert!(matches!(
        cades::archival_freshness(&renewed.seal_der, now).expect("readable"),
        ArchivalFreshness::Current { .. }
    ));
}

/// **A renewal can itself be renewed, and each stamp covers the one before.**
///
/// The chain property that makes long-term preservation work. The second renewal
/// is accepted only if its imprint is the clause 5.5.3 value over a seal that now
/// *carries the first renewal*, so it passing is the proof the index names the
/// earlier archive timestamp.
#[tokio::test]
async fn a_renewal_can_be_renewed_again() {
    let now = Utc::now() + Duration::hours(1);
    let (old, _old_dir) = seal_ending_in(30);
    let (first_source, _a) = source_ending_in(2 * 365, now);
    let first = renew_archive_timestamp(&old, &first_source, now, accept_anyone)
        .await
        .expect("the first renewal");

    let later = now + Duration::hours(2);
    let (second_source, _b) = source_ending_in(10 * 365, later);
    let second = renew_archive_timestamp(&first.seal_der, &second_source, later, accept_anyone)
        .await
        .expect("a renewed seal is renewable");

    assert!(second.expires > first.expires);
    assert_eq!(second.previous_expires, first.expires);
    assert_eq!(expires_of(&second.seal_der, later), second.expires);
}

/// **A renewal from an authority that does not outlast the one it replaces is
/// refused.**
///
/// The same certificate cannot renew itself: the new stamp would protect the seal
/// no longer than the old one, the seal would stay due, and a renewing node would
/// buy another stamp on every pass for ever.
#[tokio::test]
async fn a_renewal_that_gains_nothing_is_refused() {
    let now = Utc::now() + Duration::hours(1);
    let dir = tempfile::tempdir().expect("tempdir");
    tsa_identity(dir.path(), "Only TSA", 30);
    let seal = LocalIdentity::load_or_create(dir.path())
        .expect("identity")
        .sign_detached_at(&DIGEST, SealConformanceLevel::BaselineLta)
        .expect("sign");
    // The very authority that made the seal's archive timestamp.
    let source = LocalTimestampSource::load_or_create(dir.path())
        .expect("an authority")
        .with_clock(move || now);

    let err = renew_archive_timestamp(&seal, &source, now, accept_anyone)
        .await
        .expect_err("it protects nothing extra");

    assert!(matches!(err, RenewalError::NoGain { .. }), "{err}");
    assert_eq!(err.outcome(), "no_gain");
}

/// A seal with no archive timestamp has nothing to renew from.
///
/// `B-LT` never promised long-term protection, so creating the first archive
/// timestamp is not a renewal and is not this function's job.
#[tokio::test]
async fn a_seal_with_no_archive_timestamp_is_not_renewable() {
    let now = Utc::now();
    let dir = tempfile::tempdir().expect("tempdir");
    let seal = LocalIdentity::load_or_create(dir.path())
        .expect("identity")
        .sign_detached_at(&DIGEST, SealConformanceLevel::BaselineLt)
        .expect("sign");
    let (source, _src) = source_ending_in(365, now);

    let err = renew_archive_timestamp(&seal, &source, now, accept_anyone)
        .await
        .expect_err("there is nothing to carry forward");

    assert!(matches!(err, RenewalError::NotRenewable(_)), "{err}");
}

/// **An authority whose clock is far from this node's is refused.**
///
/// A stamp is believed because of its time, and one a day away is a finding about
/// a clock — not something to write into a retention-locked document.
#[tokio::test]
async fn a_stamp_from_a_skewed_clock_is_refused() {
    let now = Utc::now() + Duration::hours(1);
    let (old, _old_dir) = seal_ending_in(30);
    let (source, _src) = source_ending_in(5 * 365, now + Duration::days(1));

    let err = renew_archive_timestamp(&old, &source, now, accept_anyone)
        .await
        .expect_err("the authority's clock is a day out");

    assert!(matches!(err, RenewalError::Unusable(_)), "{err}");
    assert!(err.to_string().contains("clock"), "{err}");
}

/// **An authority the policy refuses is refused, and the seal is not returned.**
///
/// The caller's policy decides who is acceptable — a production node must not
/// store a stamp from an authority no list names — and it gets to see the verified
/// token before anything is built from it.
#[tokio::test]
async fn an_authority_the_policy_refuses_is_refused() {
    let now = Utc::now() + Duration::hours(1);
    let (old, _old_dir) = seal_ending_in(30);
    let (source, _src) = source_ending_in(5 * 365, now);

    let err = renew_archive_timestamp(&old, &source, now, |token| {
        Err(TimestampStanding::SelfIssued {
            subject: token.subject(),
        })
    })
    .await
    .expect_err("the policy says no");

    assert!(matches!(err, RenewalError::AuthorityRefused(_)), "{err}");
    assert_eq!(err.outcome(), "authority_refused");
}

/// A source that fails is a source failure, and the seal is untouched.
#[tokio::test]
async fn a_source_that_fails_is_reported_as_such() {
    struct Down;
    #[async_trait::async_trait]
    impl TimestampSource for Down {
        async fn stamp(&self, _: &[u8; 32]) -> Result<Vec<u8>, SealError> {
            Err(SealError::Transport("connection refused".to_owned()))
        }
        fn name(&self) -> &'static str {
            "down"
        }
    }
    let (old, _old_dir) = seal_ending_in(30);

    let err = renew_archive_timestamp(&old, &Down, Utc::now(), accept_anyone)
        .await
        .expect_err("nothing answered");

    assert!(matches!(err, RenewalError::Source(_)), "{err}");
    assert_eq!(err.outcome(), "source_failed");
}

/// **A genuine token over another seal's imprint cannot renew this one.**
///
/// The authority is real, the token is sound and its time is right — and it is a
/// stamp of something else. Attaching it would make this seal report protection
/// that is somebody else's, which is exactly the lifted-token hole the archive
/// timestamp's imprint check exists to close.
#[tokio::test]
async fn a_token_over_another_seals_imprint_cannot_renew_this_one() {
    let now = Utc::now() + Duration::hours(1);
    let (old, _old_dir) = seal_ending_in(30);
    let (honest, _src) = source_ending_in(5 * 365, now);
    // A perfectly good token, over an imprint that is not this seal's.
    let foreign = honest.stamp(&[0xEE; 32]).await.expect("a token");

    struct Replays(Vec<u8>);
    #[async_trait::async_trait]
    impl TimestampSource for Replays {
        async fn stamp(&self, _: &[u8; 32]) -> Result<Vec<u8>, SealError> {
            Ok(self.0.clone())
        }
        fn name(&self) -> &'static str {
            "replays"
        }
    }

    let err = renew_archive_timestamp(&old, &Replays(foreign), now, accept_anyone)
        .await
        .expect_err("it stamps something else");

    assert!(matches!(err, RenewalError::Unusable(_)), "{err}");
}

/// A renewal stamped in the **same second** as the stamp it renews is still the
/// newest.
///
/// Two stamps with one `genTime` — the old authority's and its replacement's — are
/// ordered by which outlasts the other, not by whichever the `SET` happened to
/// encode first. Without that, the audit would read the old stamp as the live one
/// and report the seal due again straight after it was renewed.
#[tokio::test]
async fn a_renewal_stamped_in_the_same_second_is_still_the_newest() {
    let (old, _old_dir) = seal_ending_in(30);
    let same_second = cades::newest_archive_timestamp(&old)
        .expect("readable")
        .expect("an archive timestamp")
        .gen_time();
    let (source, _src) = source_ending_in(5 * 365, same_second);

    let renewed = renew_archive_timestamp(&old, &source, same_second, accept_anyone)
        .await
        .expect("renewable");

    assert_eq!(
        expires_of(&renewed.seal_der, same_second),
        renewed.expires,
        "the later-expiring stamp must win the tie"
    );
}
