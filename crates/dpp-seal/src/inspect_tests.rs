//! Unit tests for `inspect.rs`.

use super::*;
use dpp_domain::seal::SealConformanceLevel;

/// An envelope carrying `seal_value`, with everything else plausible.
fn envelope(seal_value: String, format: SealFormat, placeholder: bool) -> SealedEnvelope {
    SealedEnvelope {
        format,
        seal_value,
        signing_cert_ref: None,
        conformance_level: Some(SealConformanceLevel::BaselineB),
        sealed_at: chrono::Utc::now(),
        placeholder,
    }
}

/// A real local seal reads back as self-issued.
///
/// The whole point of the adapter, over genuine bytes rather than a fixture:
/// the local backend is the only source of real CMS in this crate.
#[test]
fn a_real_local_seal_reads_as_self_issued() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x11; 32]).expect("sign");
    let value = base64::engine::general_purpose::STANDARD.encode(&der);

    let origin = CadesInspector::new()
        .origin(&envelope(value, SealFormat::Cades, false))
        .expect("a readable seal");

    assert!(origin.self_issued, "the local backend is self-signed");
    assert_eq!(origin.issuer, origin.subject);
    assert_eq!(
        origin.creation_device,
        dpp_types::CreationDevice::NotAQualifiedCertificate
    );
}

/// A placeholder is never read, and never reported as self-issued.
///
/// The trap this guards: a ghost envelope carries no certificate, and the
/// cheapest wrong answer — "no issuer, so self-issued" — would report the
/// most alarming finding about a seal that does not exist. Absent is the
/// only honest answer.
#[test]
fn a_placeholder_yields_no_origin_rather_than_a_finding() {
    let e = envelope("Z2hvc3Q=".to_owned(), SealFormat::Cades, true);
    assert!(CadesInspector::new().origin(&e).is_none());
}

/// Unreadable bytes yield no origin either, for the same reason.
#[test]
fn unreadable_bytes_yield_no_origin() {
    let junk = base64::engine::general_purpose::STANDARD.encode(b"not a CMS structure");
    assert!(
        CadesInspector::new()
            .origin(&envelope(junk, SealFormat::Cades, false))
            .is_none()
    );
    assert!(
        CadesInspector::new()
            .origin(&envelope(
                "not base64 at all!!".to_owned(),
                SealFormat::Cades,
                false
            ))
            .is_none()
    );
}

// ─── What the seal says it covers ────────────────────────────────────────

/// The digest a local seal was taken over, hex-encoded.
fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// A seal reports the signature it actually covers.
///
/// The whole point: this comes out of the seal's own `messageDigest`
/// attribute, not out of any record this node keeps, so it holds for a seal
/// restored from a backup or produced somewhere else entirely.
#[test]
fn a_seal_reports_the_signature_it_actually_covers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let digest = [0x11; 32];
    let der = id.sign_detached(&digest).expect("sign");
    let e = envelope(
        base64::engine::general_purpose::STANDARD.encode(&der),
        SealFormat::Cades,
        false,
    );

    assert_eq!(
        CadesInspector::new().binding(&e, &digest_hex(&digest)),
        SealBinding::CoversThisSignature
    );
}

/// Asked about a different signature, the same seal says so.
///
/// What a re-published passport looks like: the passport re-signed, so its
/// current signature is not the one sealed. The digest the seal *does* cover
/// is reported, because a caller holding it can go and find which version it
/// belongs to.
#[test]
fn a_seal_asked_about_another_signature_reports_the_one_it_covers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let digest = [0x11; 32];
    let der = id.sign_detached(&digest).expect("sign");
    let e = envelope(
        base64::engine::general_purpose::STANDARD.encode(&der),
        SealFormat::Cades,
        false,
    );

    let SealBinding::CoversAnotherDigest { covered } =
        CadesInspector::new().binding(&e, &digest_hex(&[0x22; 32]))
    else {
        panic!("this seal covers a different digest");
    };
    assert_eq!(covered, digest_hex(&digest));
}

/// **A seal cannot be retargeted by editing what it says it covers.**
///
/// The attack this check exists to stop, and the reason the signature is
/// verified before the digest is read. Rewriting the `messageDigest`
/// attribute to name another passport's signature is trivial — the attribute
/// is plain DER — but it sits *inside* the signature, so the edit breaks it.
///
/// Note what is reported: `NotIntact`, with **no digest**. Reporting the
/// forged value would hand a caller a number that nothing vouches for, and
/// reporting `CoversAnotherDigest` would describe a broken seal as merely
/// out of date.
#[test]
fn a_seal_cannot_be_retargeted_by_editing_the_digest_it_names() {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode as _, Encode as _};

    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x11; 32]).expect("sign");

    let target = [0x22; 32];
    let info = ContentInfo::from_der(&der).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");
    let mut signers = sd.signer_infos.0.as_slice().to_vec();

    let attrs = signers[0].signed_attrs.as_ref().expect("signed attributes");
    let mut rebuilt = der::asn1::SetOfVec::new();
    for a in attrs.iter() {
        let a = if a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST {
            let mut values = der::asn1::SetOfVec::new();
            values
                .insert(
                    der::Any::encode_from(
                        &der::asn1::OctetString::new(target.as_slice()).expect("octets"),
                    )
                    .expect("any"),
                )
                .expect("value");
            x509_cert::attr::Attribute { oid: a.oid, values }
        } else {
            a.clone()
        };
        rebuilt.insert(a).expect("attribute");
    }
    signers[0].signed_attrs = Some(rebuilt);

    let mut set = der::asn1::SetOfVec::new();
    set.insert(signers.remove(0)).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(set);
    let forged = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode");

    let e = envelope(
        base64::engine::general_purpose::STANDARD.encode(&forged),
        SealFormat::Cades,
        false,
    );

    assert_eq!(
        CadesInspector::new().binding(&e, &digest_hex(&target)),
        SealBinding::NotIntact,
        "the edit must break the signature rather than succeed in retargeting the seal"
    );
}

/// A placeholder binds to nothing, and says so rather than denying.
#[test]
fn a_placeholder_binds_to_nothing_rather_than_mismatching() {
    let e = envelope("Z2hvc3Q=".to_owned(), SealFormat::Cades, true);
    assert_eq!(
        CadesInspector::new().binding(&e, &digest_hex(&[0x11; 32])),
        SealBinding::Unknown,
        "an unread seal must never report as covering something else"
    );
}

/// A format this adapter does not parse is skipped, not guessed at.
#[test]
fn a_non_cades_format_is_not_parsed_as_cms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x11; 32]).expect("sign");
    let value = base64::engine::general_purpose::STANDARD.encode(&der);

    // The very bytes that read fine as CAdES, labelled otherwise.
    assert!(
        CadesInspector::new()
            .origin(&envelope(value, SealFormat::Jades, false))
            .is_none(),
        "the declared format decides, not what the bytes happen to be"
    );
}

/// 🚨 A published set reaches a verdict taken through a **clone** of the
/// inspector, without rebuilding it.
///
/// This is the property the composition root depends on and that a
/// boot-time read alone cannot provide. `main` keeps one handle for the read
/// path and hands another to the refresh task; the two are clones of each
/// other, so a pass that completes has to be visible through the first one
/// or the node answers `consulted: 0` until it is restarted.
///
/// Observed through `unchecked` rather than `consulted` deliberately: the
/// local backend is self-signed, so `standing` returns `SelfIssued` without
/// consulting anything, while `qualify` copies the unchecked territories
/// onto every verdict whatever the standing. That makes the swap observable
/// with a real seal and no network.
#[test]
fn a_published_set_reaches_a_verdict_through_a_clone_of_the_inspector() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let der = id.sign_detached(&[0x11; 32]).expect("sign");
    let value = base64::engine::general_purpose::STANDARD.encode(&der);
    let seal = envelope(value, SealFormat::Cades, false);

    // The read path's handle, and the refresh task's — as `main` wires them.
    let read_path = CadesInspector::new();
    let refresher = read_path.clone();

    let before = read_path
        .qualification(&seal)
        .expect("a readable seal yields a verdict");
    assert!(
        before.unchecked.is_empty(),
        "a node that has not refreshed admits no territories: {:?}",
        before.unchecked
    );

    assert_eq!(
        read_path.held_counts(),
        (0, 0),
        "nothing held before a pass publishes"
    );

    // 🚨 **Both halves, populated.** Publishing an empty `lists` beside a
    // populated `unchecked` would pass even if `publish` swapped only the
    // half the verdict happens to expose — which is exactly the failure
    // `TrustedListSet` exists to make unrepresentable.
    let parsed: crate::trustlist::UnverifiedTrustedList =
        serde_json::from_value(serde_json::json!({ "territory": "FI", "providers": [] }))
            .expect("a minimal parsed list");
    let fi = crate::trustlist::VerifiedTrustedList::from_store(parsed, "a digest".to_owned());

    refresher.publish(
        vec![fi],
        vec![dpp_types::qualification::UncheckedTerritory {
            territory: "DE".to_owned(),
            reason: "over the parser ceiling".to_owned(),
        }],
    );

    assert_eq!(
        read_path.held_counts(),
        (1, 1),
        "both halves of the published set must reach the read path's handle"
    );

    let after = read_path
        .qualification(&seal)
        .expect("a readable seal yields a verdict");
    assert_eq!(
        after.unchecked.len(),
        1,
        "the pass published by the refresher must reach the read path without a restart"
    );
    assert_eq!(after.unchecked[0].territory, "DE");
    assert_eq!(
        after.unchecked[0].reason, "over the parser ceiling",
        "and the reason travels with it, so the verdict can say why it is narrow"
    );
}
