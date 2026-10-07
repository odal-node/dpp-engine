//! Unit tests for `types.rs`.

use super::*;

/// The digest eID Easy's own example uses.
const EXAMPLE_B64: &str = "rxr4oMRqMAjrAdhgXjjYeLlh285M9UU1wxj+ksg3efY=";

#[test]
fn request_serializes_to_expected_shape() {
    let req = EsealRequest::single(
        "client-id",
        EsealFile {
            file_name: "dpp-123".into(),
            file_content: EXAMPLE_B64.into(),
            mime_type: MIME_PDF.into(),
        },
        EsealRequest::PROFILE_CADES_BASELINE_T,
    );
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"signature_form\":\"CAdES\""));
    assert!(json.contains(&format!("\"fileContent\":\"{EXAMPLE_B64}\"")));
    // fileName/fileContent/mimeType must be camelCase on the wire.
    assert!(json.contains("\"fileName\":\"dpp-123\""));
    assert!(json.contains("\"mimeType\":\"application/pdf\""));
}

#[test]
fn hex_digest_becomes_base64_of_the_raw_32_bytes() {
    let hex_digest = hex::encode(BASE64.decode(EXAMPLE_B64).unwrap());
    let file = EsealFile::from_hex_digest("dpp-123", &hex_digest).unwrap();
    assert_eq!(file.file_content, EXAMPLE_B64);
    assert_eq!(file.mime_type, MIME_PDF);
    // No extension — nothing to contradict the declared mimeType.
    assert!(!file.file_name.contains('.'));
}

#[test]
fn a_digest_that_is_not_sha256_is_refused() {
    // Short, long, and non-hex all fail before anything is billed.
    assert!(EsealFile::from_hex_digest("dpp-123", "deadbeef").is_err());
    assert!(EsealFile::from_hex_digest("dpp-123", &"ab".repeat(33)).is_err());
    assert!(EsealFile::from_hex_digest("dpp-123", &"zz".repeat(32)).is_err());
}

#[test]
fn response_ok_parses() {
    let body = r#"{"status":"OK","signatures":[{"fileName":"dpp-123.p7s","mimeType":"application/pkcs7-signature","fileContent":"YmFzZTY0"}]}"#;
    let resp: EsealResponse = serde_json::from_str(body).unwrap();
    assert!(resp.is_ok());
    let sig = resp.single_signature().unwrap();
    assert_eq!(sig.mime_type, "application/pkcs7-signature");
    assert_eq!(sig.file_content, "YmFzZTY0");
}

#[test]
fn a_non_ok_status_is_not_read_as_a_signature() {
    let body = r#"{"status":"ERROR","signatures":[]}"#;
    let resp: EsealResponse = serde_json::from_str(body).unwrap();
    assert!(resp.single_signature().is_err());
}

#[test]
fn a_signature_count_mismatch_is_a_protocol_fault() {
    let body = r#"{"status":"OK","signatures":[]}"#;
    let resp: EsealResponse = serde_json::from_str(body).unwrap();
    assert!(resp.single_signature().is_err());
}
