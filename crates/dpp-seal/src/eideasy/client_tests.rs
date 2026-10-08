//! Unit tests for `client.rs`.

use super::*;

/// The two profile mappings are inverses, and must stay so.
///
/// They are a pair used in opposite directions: one decides what this
/// adapter *advertises* it can produce, the other what the node *asks* the
/// provider for. Drift between them would have the node request `LT`,
/// receive `T`, and record the request — the exact downgrade
/// `cades::evidenced_level` exists to catch after the fact, arriving on a
/// retention-locked passport that cannot be re-sealed.
#[test]
fn the_profile_mappings_are_inverses() {
    for level in [
        SealConformanceLevel::BaselineB,
        SealConformanceLevel::BaselineT,
        SealConformanceLevel::BaselineLt,
        SealConformanceLevel::BaselineLta,
    ] {
        let profile = profile_for_level(level).expect("this adapter names every current level");
        assert_eq!(
            level_for_profile(profile),
            Some(level),
            "{profile} must round-trip to the level it was derived from"
        );
    }
}

#[test]
fn hmac_message_matches_documented_example() {
    // From eID Easy docs (POST, the e-seal path, ts, exact body).
    let body = r#"{"client_id":"client-id","files":[{"fileName":"document.pdf","fileContent":"rxr4oMRqMAjrAdhgXjjYeLlh285M9UU1wxj+ksg3efY=","mimeType":"application/pdf"}],"signature_form":"CAdES","signature_profile":"CAdES_BASELINE_T"}"#;
    let msg = hmac_message("POST", ESEAL_PATH, 1710000000, body);
    assert!(msg.starts_with("POST/api/signatures/e-seal1710000000{"));
    // The body must appear verbatim and last — no separator, no re-encoding.
    assert!(msg.ends_with(body));
}

fn example_request() -> EsealRequest {
    EsealRequest::single(
        "client-id",
        EsealFile::from_hex_digest("dpp-123", &"ab".repeat(32)).unwrap(),
        EsealRequest::PROFILE_CADES_BASELINE_T,
    )
}

/// The pairing the module is shaped around: the carried signature must verify
/// against the carried body. If anything ever re-serializes in between, this
/// is what catches it.
#[test]
fn the_signature_verifies_against_the_body_it_carries() {
    let signed = SignedBody::new(&example_request(), "test-key", 1710000000).unwrap();

    let message = hmac_message(METHOD, ESEAL_PATH, signed.timestamp, &signed.body);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(b"test-key").unwrap();
    mac.update(message.as_bytes());
    let expected = BASE64.encode(mac.finalize().into_bytes());

    assert_eq!(signed.signature, expected);
}

#[test]
fn a_different_key_produces_a_different_signature() {
    let a = SignedBody::new(&example_request(), "key-a", 1710000000).unwrap();
    let b = SignedBody::new(&example_request(), "key-b", 1710000000).unwrap();
    assert_eq!(a.body, b.body);
    assert_ne!(a.signature, b.signature);
}

#[test]
fn a_clock_inside_the_window_is_not_blamed() {
    use super::super::error::AuthHint;
    // Inside the tolerance, the timestamp was fine — the 401 means something
    // else, and blaming the clock would misdirect exactly as badly.
    assert_eq!(clock_hint(1710000000, Some(1710000000)), AuthHint::None);
    assert_eq!(clock_hint(1710000000, Some(1710000299)), AuthHint::None);
    // No `Date` header: nothing to compare, so claim nothing.
    assert_eq!(clock_hint(1710000000, None), AuthHint::None);
}

#[test]
fn a_drifted_clock_is_named_in_the_error() {
    use super::super::error::AuthHint;
    let hint = clock_hint(1710000000, Some(1710000901));
    assert!(matches!(hint, AuthHint::ClockSkew { .. }));
    // Drift in either direction counts.
    assert!(matches!(
        clock_hint(1710000901, Some(1710000000)),
        AuthHint::ClockSkew { .. }
    ));

    let rendered = EideasyError::Auth { status: 401, hint }.to_string();
    assert!(rendered.contains("clock"), "{rendered}");
    assert!(
        rendered.contains("before rotating"),
        "the message must steer away from rotating a good key: {rendered}"
    );
}

#[test]
fn the_date_header_is_parsed_as_the_provider_clock() {
    // IMF-fixdate, the form HTTP senders are required to use.
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::DATE,
        "Sat, 09 Mar 2024 16:00:00 GMT".parse().unwrap(),
    );
    assert_eq!(server_unix_time(&headers), Some(1710000000));

    // A numeric-offset sender still parses, via the RFC 2822 fallback.
    let mut rfc2822 = reqwest::header::HeaderMap::new();
    rfc2822.insert(
        reqwest::header::DATE,
        "Sat, 09 Mar 2024 16:00:00 +0000".parse().unwrap(),
    );
    assert_eq!(server_unix_time(&rfc2822), Some(1710000000));

    // Absent or unparseable yields nothing rather than a wrong number.
    assert_eq!(server_unix_time(&reqwest::header::HeaderMap::new()), None);
    let mut bad = reqwest::header::HeaderMap::new();
    bad.insert(reqwest::header::DATE, "not a date".parse().unwrap());
    assert_eq!(server_unix_time(&bad), None);
}

#[test]
fn the_timestamp_is_bound_into_the_signature() {
    let a = SignedBody::new(&example_request(), "test-key", 1710000000).unwrap();
    let b = SignedBody::new(&example_request(), "test-key", 1710000001).unwrap();
    assert_ne!(
        a.signature, b.signature,
        "a replayed signature would verify"
    );
}
