//! Unit tests for `timestamp.rs`: the attested sealing time.

use super::*;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use dpp_domain::seal::SealConformanceLevel;

use crate::cades::certificate_standing;

/// **A timestamp minted under a certificate that could not have made it is
/// not a time.**
///
/// The token's own signature verifies for ever and `genTime` is whatever the
/// signer wrote, so the authority's validity window is the only thing in the
/// token that limits when it could have been made. Without the check, anyone
/// able to edit a stored seal can attach a timestamp of their own choosing —
/// they cannot steal someone else's, because the imprint binds it to this
/// signature, but they can mint one — and an attested moment is what turns a
/// certificate finding from an open question into a failure, or from a
/// failure into nothing at all.
///
/// The tamper here is the cheapest possible: the authority's certificate is
/// relabelled with a window that ended before the token's own `genTime`.
/// Nothing about the token's signature breaks, for the same reason
/// relabelling a seal certificate's issuer does not break the seal — a CMS
/// signature covers the signed attributes, not the certificate beside them.
#[test]
fn a_token_stamped_outside_its_authoritys_window_is_not_a_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id
        .sign_detached_at(&[0x44; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");
    assert!(
        attested_sealing_time(&seal).expect("readable").is_some(),
        "the fixture must start with a time, or this proves nothing"
    );

    let tampered = with_backdated_tsa_certificate(&seal);

    assert_eq!(
        attested_sealing_time(&tampered).expect("readable"),
        None,
        "a token its authority's certificate could not have made is not a time"
    );
    // And the consequence, which is the reason this matters: with no
    // attested moment the certificate is judged against this clock and every
    // finding drawn from it is reported as unproven rather than as a
    // failure.
    let standing = certificate_standing(
        &tampered,
        Utc::now(),
        attested_sealing_time(&tampered).expect("readable"),
    )
    .expect("readable");
    assert!(!standing.judged_at.attested);
}

/// The same seal with the timestamp authority's certificate given a window
/// that closed before the token was stamped.
fn with_backdated_tsa_certificate(seal_der: &[u8]) -> Vec<u8> {
    let info = ContentInfo::from_der(seal_der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");

    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    let attrs = signers[0]
        .unsigned_attrs
        .as_ref()
        .expect("an LTA seal carries unsigned attributes");
    let mut rebuilt = der::asn1::SetOfVec::new();
    for attr in attrs.iter() {
        if attr.oid != ID_AA_SIGNATURE_TIME_STAMP_TOKEN {
            rebuilt.insert(attr.clone()).expect("attribute");
            continue;
        }

        let token_der = attr.values.as_slice()[0].to_der().expect("token DER");
        let token_info = ContentInfo::from_der(&token_der).expect("token CMS");
        let mut token: SignedData = token_info.content.decode_as().expect("token SignedData");

        // A window that ended a year ago, so `genTime` (now) falls outside
        // it however the clock is read.
        let long_ago = std::time::Duration::from_secs(
            u64::try_from(Utc::now().timestamp()).expect("after 1970") - 730 * 86_400,
        );
        let until = std::time::Duration::from_secs(
            u64::try_from(Utc::now().timestamp()).expect("after 1970") - 365 * 86_400,
        );
        let certs = token
            .certificates
            .as_ref()
            .expect("the token's certificate");
        let mut choices = certs.0.as_slice().to_vec();
        let cms::cert::CertificateChoices::Certificate(cert) = &mut choices[0] else {
            panic!("the local TSA embeds an X.509 certificate");
        };
        cert.tbs_certificate.validity = x509_cert::time::Validity {
            not_before: x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(long_ago).expect("a date"),
            ),
            not_after: x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(until).expect("a date"),
            ),
        };
        let mut set = der::asn1::SetOfVec::new();
        set.insert(choices.remove(0)).expect("certificate");
        token.certificates = Some(cms::signed_data::CertificateSet(set));

        let mut values = der::asn1::SetOfVec::new();
        values
            .insert(
                der::Any::encode_from(&ContentInfo {
                    content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
                    content: der::Any::encode_from(&token).expect("encode token"),
                })
                .expect("wrap token"),
            )
            .expect("value");
        rebuilt
            .insert(x509_cert::attr::Attribute {
                oid: attr.oid,
                values,
            })
            .expect("attribute");
    }
    signers[0].unsigned_attrs = Some(x509_cert::attr::Attributes::from(rebuilt));

    let mut set = der::asn1::SetOfVec::new();
    set.insert(signers.remove(0)).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(set);

    ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode")
}

/// A timestamped seal reports a time a third party attests, not our clock.
#[test]
fn a_timestamped_seal_reports_an_attested_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineT)
        .expect("sign");

    let attested = attested_sealing_time(&der)
        .expect("readable")
        .expect("a B-T seal carries a timestamp");

    let drift = (chrono::Utc::now() - attested).num_seconds().abs();
    assert!(
        drift < 300,
        "the attested time should be about now: {attested}"
    );
}

/// A `B-B` seal carries no timestamp, and reports none rather than a guess.
///
/// The distinction the whole function exists for: no attested time is a
/// different answer from the node's own clock, and `SealedEnvelope::sealed_at`
/// is the latter.
#[test]
fn a_seal_with_no_timestamp_attests_no_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x11; 32]).expect("sign");

    assert_eq!(attested_sealing_time(&der).expect("readable"), None);
}

/// **A genuine token lifted from another seal is refused.**
///
/// The attack the imprint check exists for, and the reason verifying the
/// token's own signature is not enough on its own. `signature-time-stamp` is
/// an *unsigned* attribute — the seal's signature does not cover it — so
/// swapping the whole token costs nothing. The token moved here is perfectly
/// valid: real authority, sound signature, real `genTime`. It is simply a
/// timestamp of a *different* signature.
///
/// EN 319 122-1 clause 5.3 says the imprint is over this `SignerInfo`'s
/// signature value, so checking it is what ties the time to this seal.
#[test]
fn a_timestamp_token_from_another_seal_is_refused() {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let mine = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineT)
        .expect("sign");
    // A second seal over different content, so its timestamp covers a
    // different signature value.
    let theirs = id
        .sign_detached_at(&[0x22; 32], SealConformanceLevel::BaselineT)
        .expect("sign");

    let borrowed = {
        let info = ContentInfo::from_der(&theirs).expect("CMS");
        let sd: SignedData = info.content.decode_as().expect("SignedData");
        sd.signer_infos.0.as_slice()[0]
            .unsigned_attrs
            .as_ref()
            .expect("a B-T seal has unsigned attributes")
            .iter()
            .find(|a| a.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN)
            .expect("a signature timestamp")
            .clone()
    };

    let info = ContentInfo::from_der(&mine).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");
    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    let mut attrs = der::asn1::SetOfVec::new();
    attrs.insert(borrowed).expect("attribute");
    signers[0].unsigned_attrs = Some(attrs);
    let mut set = der::asn1::SetOfVec::new();
    set.insert(signers.remove(0)).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(set);

    let swapped = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode");

    assert_eq!(
        attested_sealing_time(&swapped).expect("readable"),
        None,
        "a valid token over someone else's signature must not become this seal's time"
    );
}
