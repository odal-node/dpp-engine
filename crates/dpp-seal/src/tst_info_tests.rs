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
