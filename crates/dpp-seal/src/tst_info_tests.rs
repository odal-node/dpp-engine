//! A `TSTInfo` as a real timestamp authority emits it.
//!
//! The reader began as the other half of this crate's own writer, so it only ever
//! saw tokens that writer made: a 64-bit serial, no `accuracy`, no `nonce`,
//! whole-second `genTime`. RFC 3161 allows — and real authorities send — much
//! more, and a token this reader cannot parse is a token whose time and expiry
//! nothing here can read. That is a safe direction to fail in, but it makes the
//! reader useless against the one population that matters.

use super::*;
use chrono::TimeZone as _;
use der::{
    Tag,
    asn1::{Any, Uint},
};

/// The shape of a real token's `TSTInfo`, assembled by hand so the test does not
/// depend on the type under test to build its own input.
#[derive(der::Sequence)]
struct RealWorldTstInfo {
    version: u8,
    policy: const_oid::ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Uint,
    gen_time: Any,
    accuracy: RealWorldAccuracy,
    nonce: Uint,
}

#[derive(der::Sequence)]
struct RealWorldAccuracy {
    seconds: u8,
}

fn sha256_imprint() -> MessageImprint {
    MessageImprint {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        },
        hashed_message: der::asn1::OctetString::new([0x42u8; 32].as_slice()).expect("32 bytes"),
    }
}

/// A token as an authority that sends everything RFC 3161 allows would send it:
/// a 160-bit serial, `accuracy`, a client's `nonce`, and a `genTime` with
/// fractional seconds.
fn real_world_tst_info() -> Vec<u8> {
    RealWorldTstInfo {
        version: 1,
        policy: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.601.10.3.1"),
        message_imprint: sha256_imprint(),
        // 20 bytes with the high bit set: a serial no `u64` can hold.
        serial_number: Uint::new(&[0xAB; 20]).expect("a serial"),
        gen_time: Any::new(Tag::GeneralizedTime, b"20261006123456.789Z".as_slice())
            .expect("a time"),
        accuracy: RealWorldAccuracy { seconds: 1 },
        nonce: Uint::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).expect("a nonce"),
    }
    .to_der()
    .expect("encode")
}

/// A token a **real** timestamp authority made, kept as bytes.
///
/// Sectigo's public authority, asked on 2026-10-06 to stamp a hash of 64 random
/// bytes — so it stamps nothing of ours, and its certificates are public. It
/// signs with **SHA-384 over RSA**, carries a 160-bit serial, echoes a nonce, names
/// itself in `tsa`, and ships a four-certificate chain. None of that is what this
/// crate's own writer produces, which is why a fixture made by that writer could
/// never have found what this one did.
///
/// A second authority — FreeTSA, SHA-512 over ECDSA P-384 — is exercised by the
/// `#[ignore]`d live tests rather than kept here: its certificate embeds a
/// person's email address, which has no business in this repository.
const REAL_TOKEN: &[u8] = include_bytes!("../tests/fixtures/real-timestamp-token-sectigo.der");

/// The imprint that token stamps: SHA-256 of the 64 random bytes it was asked for.
const REAL_TOKEN_IMPRINT: &str = "f48fb2955f8bdc8a32a38fd592bd89630e83d83c98c642f11647cd7feb115f05";

/// **A real authority's token is parsed and verified, stage by stage.**
///
/// Staged rather than one `expect`, because the first time this ran the reader
/// refused the token with a single message that said nothing about *where* — and
/// the answer was not the one anybody expected.
#[test]
fn a_real_authoritys_token_parses_and_verifies() {
    let token = parse(REAL_TOKEN).expect("1. the CMS structure parses");

    assert!(
        signature_holds(&token).expect("2. the signature can be checked"),
        "2. the token's own signature does not verify"
    );

    let content = token.econtent.as_ref().expect("3. an attached TSTInfo");
    assert!(
        digest_matches(&token, content),
        "3. the signed messageDigest does not match the TSTInfo under the signer's digest"
    );

    let info = TstInfo::from_der(content).expect("4. the TSTInfo parses");
    assert_eq!(
        hex::encode(info.message_imprint.hashed_message.as_bytes()),
        REAL_TOKEN_IMPRINT
    );
    assert!(
        info.nonce.is_some(),
        "5. the authority echoed the request's nonce"
    );
    assert!(
        info.serial_number.as_bytes().len() > 8,
        "6. a real serial is wider than a u64: {} bytes",
        info.serial_number.as_bytes().len()
    );
    assert!(
        stamped_within_its_certificate(&token, info.gen_time.0),
        "7. the stamp falls inside its authority's certificate window"
    );
}

/// **A real authority's token reads as a timestamp, end to end.**
#[test]
fn a_real_authoritys_token_yields_its_facts() {
    let facts = token_facts(REAL_TOKEN).expect("a real token is self-consistent");

    assert_eq!(facts.hash_algorithm, const_oid::db::rfc5912::ID_SHA_256);
    assert_eq!(hex::encode(&facts.imprint), REAL_TOKEN_IMPRINT);
    assert!(facts.nonce.is_some());
}

/// **A token carrying what real authorities send is readable.**
///
/// Pinned because the reader's own documentation claimed the opposite — that
/// the optional tail "still parses, since DER decoding of a SEQUENCE ignores
/// what it was not asked for" — and DER decoding does not ignore trailing
/// fields: it refuses them.
#[test]
fn a_token_carrying_what_real_authorities_send_is_readable() {
    let der = real_world_tst_info();

    let info = TstInfo::from_der(&der).expect("a TSTInfo as a real authority emits it");

    assert_eq!(
        info.gen_time.0,
        chrono::Utc
            .with_ymd_and_hms(2026, 10, 6, 12, 34, 56)
            .single()
            .expect("a date")
            + chrono::Duration::milliseconds(789),
        "fractional seconds are part of the time, not a reason to refuse it"
    );
}
