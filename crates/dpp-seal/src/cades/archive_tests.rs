//! Unit tests for `archive.rs`: archival freshness.

use super::*;
use cms::cert::CertificateChoices;
use dpp_domain::seal::SealConformanceLevel;

use crate::cades::evidenced_level;
use crate::cades::signed::signer_certificate_of;

/// A `B-LTA` seal reports when its archival protection has to be renewed.
#[test]
fn an_archived_seal_reports_a_renewal_date() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");

    let ArchivalFreshness::Current { expires: renew_by } =
        archival_freshness(&der, chrono::Utc::now()).expect("readable")
    else {
        panic!("a fresh LTA seal is current");
    };
    assert!(
        renew_by > chrono::Utc::now(),
        "the renewal date must be in the future: {renew_by}"
    );
}

/// The same seal, read from far enough in the future, reports the lapse.
///
/// The whole point of the signal. Nothing about the seal changes — only the
/// clock — which is exactly how this failure arrives in practice: on a date
/// nobody has in a calendar, years after the passport was locked.
#[test]
fn the_same_seal_read_later_reports_that_it_lapsed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");

    let ArchivalFreshness::Current { expires: renew_by } =
        archival_freshness(&der, chrono::Utc::now()).expect("readable")
    else {
        panic!("current now");
    };
    let after = renew_by + chrono::Duration::seconds(1);

    assert_eq!(
        archival_freshness(&der, after).expect("readable"),
        ArchivalFreshness::Lapsed { expires: renew_by },
        "past its authority's certificate, the archival protection is gone"
    );
}

/// A seal with no archival timestamp has nothing to renew, and says so.
///
/// `NotArchived` is not `Lapsed`: a `B-LT` seal was never promised long-term
/// protection, and reporting it as lapsed would raise an alarm about a
/// commitment nobody made.
#[test]
fn a_seal_below_lta_has_nothing_to_renew() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLt)
        .expect("sign");

    assert_eq!(
        archival_freshness(&der, chrono::Utc::now()).expect("readable"),
        ArchivalFreshness::NotArchived
    );
}

/// The level says `BaselineLta` either way — which is why this exists.
///
/// `evidenced_level` reports the *presence* of the archival material, and is
/// right to: the material is there. The two answers together are the finding
/// — a seal that still evidences LTA and whose archival protection has gone.
#[test]
fn a_lapsed_seal_still_evidences_lta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");

    // Past the local authority's certificate, which runs to 4096.
    let far_future = "9999-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect("a representable instant");
    assert!(matches!(
        archival_freshness(&der, far_future).expect("readable"),
        ArchivalFreshness::Lapsed { .. }
    ));
    assert_eq!(
        evidenced_level(&der).expect("readable"),
        Some(SealConformanceLevel::BaselineLta),
        "the level is unchanged, which is exactly how this goes unnoticed"
    );
}

/// Removing material the index names makes the archive timestamp invalid.
///
/// This isolates the index check, which the borrowed-token case above does
/// **not**: that token's imprint differs on the signer's own fields, so it
/// would be refused even if index validation always returned true. Here
/// everything else is untouched and only an indexed certificate is dropped,
/// so the containment rule is the only thing that can catch it.
///
/// It is also the direction the clause cares about. An index may name less
/// than is present — later additions are unprotected, not fatal — but it may
/// never name **more**, because that is how an index would go on claiming to
/// protect validation material somebody removed after stamping.
#[test]
fn an_archive_timestamp_whose_indexed_material_is_gone_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id
        .sign_detached_at(&[0x33; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");

    // The control: untouched, this seal is archived.
    assert!(
        matches!(
            archival_freshness(&der, chrono::Utc::now()).expect("readable"),
            ArchivalFreshness::Current { .. }
        ),
        "the seal is archived before anything is removed"
    );

    // Drop one certificate from `SignedData.certificates`. An LTA seal
    // carries the signing certificate and the authority's, and the index
    // names both — so removing either leaves an entry with nothing behind
    // it. The signer's own certificate has to stay, or the seal stops
    // parsing for an unrelated reason and the test proves nothing.
    let info = ContentInfo::from_der(&der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");
    let signer_cert = signer_certificate_of(
        &sd.signer_infos.0.as_slice()[0],
        &sd.certificates
            .as_ref()
            .expect("certificates")
            .0
            .as_slice()
            .iter()
            .filter_map(|c| match c {
                CertificateChoices::Certificate(c) => Some(c.clone()),
                _ => None,
            })
            .collect::<Vec<_>>(),
    )
    .expect("the seal names its signer")
    .clone();

    let mut kept = der::asn1::SetOfVec::new();
    kept.insert(CertificateChoices::Certificate(signer_cert))
        .expect("keep the signer certificate");
    let before = sd.certificates.as_ref().expect("certificates").0.len();
    sd.certificates = Some(cms::signed_data::CertificateSet::from(kept));
    assert!(
        before > 1,
        "the seal has to carry more than the signer certificate for this to remove one"
    );

    let stripped = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode");

    assert_eq!(
        archival_freshness(&stripped, chrono::Utc::now()).expect("readable"),
        ArchivalFreshness::Unknown,
        "an index naming a certificate the seal no longer carries must not still report \
         archival protection"
    );
}

/// An archive timestamp taken from another seal does not archive this one.
///
/// The defect this whole computation exists to close. The borrowed token is
/// **entirely genuine** — real authority, real signature, internally
/// consistent, and its own certificate perfectly valid — so every check that
/// existed before this one passes on it. What it is not is a timestamp of
/// *this* signature, and nothing said so.
///
/// Unsigned attributes are where this is free to do: they sit inside
/// `SignerInfo` and the signature covers none of them, so pasting one in
/// disturbs nothing. The seal still verifies, still binds to the passport,
/// and reports archival protection until somebody else's authority
/// certificate expires.
///
/// Both seals are made by the **same** node here, which makes the case
/// harder rather than easier: same signing key, same authority, same
/// certificates in `SignedData`. Everything is shared except the signature
/// being archived — so only the concatenation can tell them apart.
#[test]
fn an_archive_timestamp_from_another_seal_does_not_archive_this_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let mine = id
        .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");
    let theirs = id
        .sign_detached_at(&[0x22; 32], SealConformanceLevel::BaselineLta)
        .expect("sign");

    // The positive control. Without it a mistake that made *every* seal
    // report unarchived would pass the assertion below and prove nothing.
    assert!(
        matches!(
            archival_freshness(&theirs, chrono::Utc::now()).expect("readable"),
            ArchivalFreshness::Current { .. }
        ),
        "the donor seal is genuinely archived, or the swap proves nothing"
    );

    let borrowed = {
        let info = ContentInfo::from_der(&theirs).expect("CMS");
        let sd: SignedData = info.content.decode_as().expect("SignedData");
        sd.signer_infos.0.as_slice()[0]
            .unsigned_attrs
            .as_ref()
            .expect("an LTA seal has unsigned attributes")
            .iter()
            .find(|a| a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V3)
            .expect("an archive timestamp")
            .clone()
    };

    // Replace this seal's archive timestamp with the other seal's, leaving
    // its signature timestamp in place — the shape a tampered envelope
    // actually takes, rather than a seal stripped of everything else.
    let info = ContentInfo::from_der(&mine).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");
    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    let kept: Vec<_> = signers[0]
        .unsigned_attrs
        .as_ref()
        .expect("unsigned attributes")
        .iter()
        .filter(|a| a.oid != ID_AA_ETS_ARCHIVE_TIMESTAMP_V3)
        .cloned()
        .collect();
    let mut attrs = der::asn1::SetOfVec::new();
    for a in kept {
        attrs.insert(a).expect("attribute");
    }
    attrs.insert(borrowed).expect("the borrowed timestamp");
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
        archival_freshness(&swapped, chrono::Utc::now()).expect("readable"),
        ArchivalFreshness::Unknown,
        "a genuine archive timestamp over someone else's signature must not report this \
         seal as archived — it is present and unreadable *as this seal's*, which is what \
         Unknown means and is deliberately not Current"
    );
}
