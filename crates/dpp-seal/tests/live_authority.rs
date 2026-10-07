//! A real timestamp authority, by hand.
//!
//! Everything under `src/` that exercises timestamping runs against a double, and a
//! double can only ever return tokens this crate's own writer produced. That is how
//! the reader came to parse every token it had ever seen and **none** that a real
//! authority sends: it assumed SHA-256 throughout, accepted only the combined
//! `…WithRSAEncryption` signature identifier, and stopped reading a `TSTInfo` at
//! `genTime`. Two public authorities, asked once each, found all three.
//!
//! These are `#[ignore]`d — they contact a third party — and driven by one
//! variable, so they can be pointed at any anonymous `https` RFC 3161 endpoint:
//!
//! ```text
//! ODAL_LIVE_TSA_URL=https://timestamp.sectigo.com \
//!   cargo test -p dpp-seal --test live_authority -- --ignored --nocapture
//! ```
//!
//! Imprints are random, so nothing of ours is sent: the authority stamps a hash of
//! nothing. Be sparing — these are free public services, and FreeTSA in particular
//! asks for light use.
//!
//! Last run 2026-10-06 against Sectigo (SHA-384 over RSA, naming only
//! `rsaEncryption`) and FreeTSA (SHA-512 over ECDSA P-384): both stamp, both verify,
//! and both renew a due seal end to end.

use std::time::Duration;

use chrono::Utc;
use dpp_domain::seal::SealConformanceLevel;
use dpp_seal::TimestampSource as _;
use dpp_seal::cades::{self, ArchivalFreshness};
use dpp_seal::local::LocalIdentity;
use dpp_seal::renewal::renew_archive_timestamp;
use dpp_seal::rfc3161::Rfc3161Source;
use rand::Rng as _;

fn live_source() -> (String, Rfc3161Source) {
    let url = std::env::var("ODAL_LIVE_TSA_URL")
        .expect("set ODAL_LIVE_TSA_URL to an anonymous https RFC 3161 endpoint");
    let source = Rfc3161Source::new(&url, Duration::from_secs(30)).expect("an acceptable address");
    (url, source)
}

/// **A real authority answers, and its token verifies.**
///
/// `stamp` already requires the token's own signature, the digest binding it to its
/// `TSTInfo`, the imprint that was sent and the nonce that was sent — so an `Ok` is
/// all four holding against something this crate did not write.
#[tokio::test]
#[ignore = "contacts a real timestamp authority; run by hand with ODAL_LIVE_TSA_URL"]
async fn a_live_authority_answers_and_its_token_verifies() {
    let (url, source) = live_source();

    let mut imprint = [0u8; 32];
    rand::rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut imprint);

    let token = source
        .stamp(&imprint)
        .await
        .expect("a real authority's token must verify");

    println!("{url}: a token of {} bytes verified", token.len());
}

/// A timestamping identity whose certificate ends in `days`, written where the
/// local sealer looks for it — so the seal's archive timestamp is genuinely near its
/// end, which the real local authority (valid to the year 4096) can never be.
fn seal_ending_in(days: i64) -> (Vec<u8>, tempfile::TempDir) {
    let at = |offset_days: i64| {
        time::OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() + offset_days * 86_400)
            .expect("a date")
    };
    let dir = tempfile::tempdir().expect("tempdir");

    let mut params =
        rcgen::CertificateParams::new(vec!["expiring-tsa".to_owned()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Expiring test authority");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::TimeStamping];
    params.not_before = at(-1);
    params.not_after = at(days);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    let cert = params.self_signed(&key).expect("a certificate");
    std::fs::write(dir.path().join("tsa-key.pkcs8.der"), key.serialize_der()).expect("key");
    std::fs::write(dir.path().join("tsa-cert.der"), cert.der()).expect("certificate");

    let seal = LocalIdentity::load_or_create(dir.path())
        .expect("identity")
        .sign_detached_at(&[0x44; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");
    (seal, dir)
}

/// **A real authority renews a due seal, end to end.**
///
/// The whole path against something that is not this crate's own writer: a seal whose
/// archive timestamp ends in a month, renewed by a real authority's token — verified
/// as an archive timestamp of *this* seal (imprint, signature, window), attached, and
/// read back.
#[tokio::test]
#[ignore = "contacts a real timestamp authority; run by hand with ODAL_LIVE_TSA_URL"]
async fn a_live_authority_renews_a_due_seal() {
    let (url, source) = live_source();
    let (old, _dir) = seal_ending_in(30);

    // A real renewal comes months after the stamp it renews. Left at seconds, an
    // authority whose clock reads a second behind this machine's stamps *before* the
    // one it renews — which is refused, correctly, and is not what this checks.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let now = Utc::now();

    let renewed = renew_archive_timestamp(&old, &source, now, |_| Ok(()))
        .await
        .expect("a real authority must be able to renew a due seal");

    assert!(renewed.expires > renewed.previous_expires);
    assert!(
        matches!(
            cades::archival_freshness(&renewed.seal_der, now).expect("readable"),
            ArchivalFreshness::Current { expires } if expires == renewed.expires
        ),
        "the reader the audit uses agrees the seal is renewed"
    );
    assert!(
        cades::verify_against_embedded_certificate(&renewed.seal_der).expect("readable"),
        "the seal's own signature still holds"
    );
    println!(
        "{url}: renewed — protection now runs to {} (was {})",
        renewed.expires, renewed.previous_expires
    );
}
