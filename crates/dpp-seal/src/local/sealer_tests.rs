//! Unit tests for `sealer.rs`.

use super::*;
use cms::content_info::ContentInfo;
use dpp_domain::seal::SealIndication;

fn identity() -> (LocalIdentity, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = LocalIdentity::load_or_create(dir.path()).expect("identity");
    (id, dir)
}

/// The seal is a real CMS `ContentInfo` carrying `SignedData`, not a stub.
///
/// Parsing it back with the same library a provider's output would be parsed
/// with is the check that matters: a structure that only this code can read
/// would prove nothing about the pipeline.
#[test]
fn the_seal_parses_back_as_cms_signed_data() {
    let (id, _dir) = identity();
    let der = id.sign_detached(&[0x42; 32]).expect("sign");

    let info = ContentInfo::from_der(&der).expect("a CMS ContentInfo");
    assert_eq!(info.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    let sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData inside");
    assert_eq!(sd.signer_infos.0.len(), 1, "exactly one signer");
    assert!(
        sd.certificates.is_some(),
        "the signing certificate travels with the seal, as a provider's does"
    );
}

/// The signature in the seal verifies against the certificate it carries.
///
/// This is the test the whole backend exists for. Everything else here
/// checks structure; without this one, a seal could be well-formed CMS
/// carrying bytes that verify against nothing — which is precisely what
/// `GhostSeal` already produces, and what this backend is meant to stop
/// being.
#[test]
fn the_signature_verifies_against_the_embedded_certificate() {
    let (id, _dir) = identity();
    let der = id.sign_detached(&[0x7u8; 32]).expect("sign");

    // Checked through the same function production uses, which is handed
    // bytes and nothing else — the identity in memory is not consulted.
    assert!(
        crate::cades::verify_against_embedded_certificate(&der).expect("the seal is well-formed"),
        "the seal must verify against the certificate it ships"
    );
}

/// The seal commits to the digest it was asked to seal, not to some other.
///
/// `cades::verify_against_embedded_certificate` proves the signature covers the signed attributes; this
/// proves the signed attributes carry the right value. Without it the
/// backend could sign a constant attribute set perfectly and attest nothing
/// about the passport — internally valid, externally meaningless.
#[test]
fn the_signed_attributes_carry_the_requested_digest() {
    use der::asn1::OctetString;

    let (id, _dir) = identity();
    let digest = [0x5u8; 32];
    let der = id.sign_detached(&digest).expect("sign");

    let info = ContentInfo::from_der(&der).expect("ContentInfo");
    let sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
    let si = sd.signer_infos.0.as_slice().first().expect("one signer");
    let attrs = si.signed_attrs.as_ref().expect("signed attributes present");

    let found = attrs
        .as_slice()
        .iter()
        .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
        .expect("a messageDigest attribute");
    let carried: OctetString = found
        .values
        .as_slice()
        .first()
        .expect("one value")
        .decode_as()
        .expect("an OCTET STRING");

    assert_eq!(
        carried.as_bytes(),
        digest,
        "the seal must commit to the digest it was handed"
    );
}

/// A tampered seal does not verify.
///
/// The check that makes the others mean something: if flipping a byte of the
/// signature still verified, `cades::verify_against_embedded_certificate` would be reporting a constant
/// rather than performing a check.
#[test]
fn a_tampered_signature_does_not_verify() {
    let (id, _dir) = identity();
    let der = id.sign_detached(&[0x9u8; 32]).expect("sign");

    // Flip a byte deep inside the structure. Some positions corrupt the DER
    // and produce a parse error rather than `false`; both are refusals, and
    // neither may be a pass.
    let mut tampered = der.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    assert!(
        !matches!(
            crate::cades::verify_against_embedded_certificate(&tampered),
            Ok(true)
        ),
        "a tampered seal must never verify"
    );
}

/// A seal with no signed attributes is refused, not called invalid.
///
/// The digest is not inside such a seal, so nothing can be checked from the
/// envelope alone. Reporting `valid: false` would brand it broken on the
/// strength of a check that never ran — the distinction this crate exists to
/// keep.
#[test]
fn a_seal_without_signed_attributes_is_refused() {
    let (id, _dir) = identity();
    let der = id.sign_detached(&[0x1u8; 32]).expect("sign");

    let info = ContentInfo::from_der(&der).expect("ContentInfo");
    let mut sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    signers[0].signed_attrs = None;
    let mut rebuilt = der::asn1::SetOfVec::new();
    rebuilt.insert(signers.remove(0)).expect("one signer");
    sd.signer_infos = SignerInfos::from(rebuilt);

    let stripped = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&sd).expect("re-encode"),
    }
    .to_der()
    .expect("DER");

    let err = crate::cades::verify_against_embedded_certificate(&stripped)
        .expect_err("must refuse rather than answer");
    assert!(err.to_string().contains("signed attributes"), "{err}");
}

/// Two different digests produce two different seals.
///
/// Guards the failure that would make every other test here vacuous: a
/// backend that returns a constant would satisfy "parses as CMS" and still
/// attest nothing.
#[test]
fn a_different_digest_produces_a_different_seal() {
    let (id, _dir) = identity();
    let a = id.sign_detached(&[0x01; 32]).expect("sign a");
    let b = id.sign_detached(&[0x02; 32]).expect("sign b");
    assert_ne!(a, b, "the seal must depend on what it covers");
}

fn seal_request(payload_hash: &str) -> SealRequest {
    SealRequest {
        payload_hash: payload_hash.to_owned(),
        mode: SealMode::OperatorSeal,
        key_ref: dpp_domain::seal::SealCredentialRef {
            qtsp_id: "local".into(),
            credential_id: "dev".into(),
        },
        sig_format: SealFormat::Cades,
        // The only level this backend claims: a bare signature, detached.
        conformance_level: SealConformanceLevel::BaselineB,
        envelope: SealEnvelope::Detached,
    }
}

/// The envelope this backend hands the port carries the real signature and
/// says so.
///
/// `placeholder: false` is the load-bearing field: the drain, the trust
/// report and the passport all read it, and marking these bytes as a
/// placeholder would hide a seal that genuinely verifies — while marking a
/// ghost's bytes as real would do far worse.
#[tokio::test]
async fn the_envelope_carries_the_signature_and_the_certificate() {
    use base64::engine::general_purpose::STANDARD as BASE64;

    let (id, _dir) = identity();
    let digest = [0x33u8; 32];
    let env = SealBackend::seal(&id, seal_request(&hex::encode(digest)))
        .await
        .expect("the local backend seals");

    assert_eq!(env.format, SealFormat::Cades);
    assert!(!env.placeholder, "these bytes verify — they are not a stub");
    assert_eq!(
        env.conformance_level,
        Some(SealConformanceLevel::BaselineB),
        "the envelope must record the level that was requested — and for this \n             backend that is also the level the bytes carry"
    );
    assert_eq!(
        env.signing_cert_ref.as_deref(),
        Some(id.cert_thumbprint().as_str()),
        "the envelope must name the certificate that signed it"
    );

    // The seal value is the base64 of the same CMS the direct path produces.
    let der = BASE64.decode(&env.seal_value).expect("base64 seal value");
    ContentInfo::from_der(&der).expect("a CMS ContentInfo");
    assert_eq!(der, id.sign_detached(&digest).expect("sign"));
}

/// Seal, then verify, through the port — the round trip an operator gets.
///
/// Every other test here reaches into the structure. This one only uses what
/// a caller has: a request in, an envelope out, and that envelope back in.
/// It is the whole point of a development backend — the pipeline is
/// exercised end to end without a provider account.
#[tokio::test]
async fn a_sealed_envelope_verifies_through_the_port() {
    let (id, _dir) = identity();
    let digest = hex::encode([0x2Au8; 32]);

    let env = SealBackend::seal(&id, seal_request(&digest))
        .await
        .expect("seal");
    let verdict = SealBackend::verify(&id, &env).await.expect("verify");

    assert_eq!(
        verdict.indication,
        SealIndication::TotalPassed,
        "a seal this backend just produced must verify"
    );
    assert_eq!(
        verdict.checks,
        SealChecks::SignatureOnly,
        "and must say that a signature check is all it rests on"
    );
    assert!(
        !verdict.placeholder,
        "these bytes are real; only the trust behind them is absent"
    );
    assert!(
        !verdict.is_qualified_pass(),
        "a self-signed development seal is never a qualified pass"
    );
}

/// A seal whose value was altered in storage fails the round trip.
///
/// Without this, `a_sealed_envelope_verifies_through_the_port` would pass
/// against a `verify` that returned `true` unconditionally.
#[tokio::test]
async fn a_corrupted_envelope_does_not_verify_through_the_port() {
    use base64::engine::general_purpose::STANDARD as BASE64;

    let (id, _dir) = identity();
    let mut env = SealBackend::seal(&id, seal_request(&hex::encode([0x2Au8; 32])))
        .await
        .expect("seal");

    let mut raw = BASE64.decode(&env.seal_value).expect("base64");
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    env.seal_value = BASE64.encode(&raw);

    let verdict = SealBackend::verify(&id, &env).await;
    assert!(
        !matches!(
            verdict.map(|v| v.indication),
            Ok(SealIndication::TotalPassed)
        ),
        "a corrupted seal must never verify"
    );
}

/// A digest that is not hex fails before any signing happens.
#[tokio::test]
async fn a_payload_hash_that_is_not_hex_is_refused() {
    let (id, _dir) = identity();
    let err = SealBackend::seal(&id, seal_request("not-a-digest"))
        .await
        .expect_err("a malformed digest must not be signed over");
    assert!(err.to_string().contains("not hex"), "{err}");
}

/// The identity survives a restart.
///
/// A seal produced before a restart must still verify against the same
/// certificate after one.
#[test]
fn the_identity_is_stable_across_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = LocalIdentity::load_or_create(dir.path()).expect("first");
    let second = LocalIdentity::load_or_create(dir.path()).expect("second");
    assert_eq!(
        first.cert_thumbprint(),
        second.cert_thumbprint(),
        "reloading must not mint a new certificate"
    );
}
