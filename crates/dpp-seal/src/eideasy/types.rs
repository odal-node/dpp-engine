//! eID Easy "Cloud Direct e-Sealing" API wire types.
//!
//! Server-to-server sealing: submit base64 SHA-256 digest(s), receive detached
//! signatures. HMAC-authenticated (no OAuth, no SAD token). The wire contract,
//! including the critical "sign the exact raw bytes" rule, is eID Easy's
//! published Cloud Direct e-Sealing API; [`crate::eideasy::client`] is where that
//! rule is enforced.
//!
//! COMPLIANCE-PIN PENDING: `signature_profile` must match a value eID Easy has
//! enabled for our client — confirm before production.
//! Endpoint: sandbox `https://test.eideasy.com/api/signatures/e-seal`,
//! production `https://id.eideasy.com/api/signatures/e-seal`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use super::error::EideasyError;

/// The `mimeType` we declare. eID Easy built Direct e-Sealing for PDF, and both
/// their docs and their support answer use this value; it is what we send.
///
/// It is a label, not a fact about the seal. eID Easy receives only the base64
/// SHA-256 digest — never the payload — so it cannot inspect the original content,
/// and for a detached CMS over an external hash the declared type is not part of
/// what the signature covers. The eIDAS Art. 35 weight comes from the qualified
/// certificate signing the digest, independent of this string.
pub const MIME_PDF: &str = "application/pdf";

/// The truthful type of what we actually seal — a JSON passport payload.
///
/// **Unused.** Declared so the accurate value is already in place if eID Easy
/// confirms their validation accepts it; sending it is not worth an empirical
/// gamble against an endpoint whose error shapes are undocumented. Open with the
/// provider.
pub const MIME_JSON: &str = "application/json";

/// One file (by digest) to be sealed.
#[derive(Debug, Clone, Serialize)]
pub struct EsealFile {
    /// Original file name (≥ 3 chars, unique within the request).
    ///
    /// Carries **no extension** deliberately: with [`MIME_PDF`] declared beside
    /// it, a `.json` name would contradict the declared type, and a `.pdf` name
    /// would put an untruth into the key we correlate the response by. eID Easy
    /// echoes it back as `<fileName>.p7s`.
    #[serde(rename = "fileName")]
    pub file_name: String,
    /// Base64-encoded **SHA-256 digest** of the payload. The payload itself is
    /// never sent — only the hash (proof-bound).
    #[serde(rename = "fileContent")]
    pub file_content: String,
    /// MIME type of the *original* file. See [`MIME_PDF`].
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

impl EsealFile {
    /// Build a file entry from a hex SHA-256 digest.
    ///
    /// `SealRequest::payload_hash` is hex by contract; eID Easy wants base64 of
    /// the raw 32 digest bytes (their own example decodes to exactly 32). This is
    /// the only re-encoding between the two, and it lives here so the adapter
    /// never hand-rolls it.
    pub fn from_hex_digest(
        file_name: impl Into<String>,
        hex_digest: &str,
    ) -> Result<Self, EideasyError> {
        let raw = hex::decode(hex_digest)
            .map_err(|e| EideasyError::Protocol(format!("payload hash is not hex: {e}")))?;
        if raw.len() != 32 {
            return Err(EideasyError::Protocol(format!(
                "payload hash must be a 32-byte SHA-256 digest, got {} bytes",
                raw.len()
            )));
        }
        Ok(Self {
            file_name: file_name.into(),
            file_content: BASE64.encode(raw),
            mime_type: MIME_PDF.to_owned(),
        })
    }
}

/// `POST /api/signatures/e-seal` request body.
///
/// IMPORTANT: this struct is only for constructing the body. The HMAC must be
/// computed over the **exact serialized bytes that are sent** — serialize once,
/// HMAC those bytes, send those same bytes. Do not re-serialize.
/// [`crate::eideasy::client`] is the only caller and does this; `reqwest`'s
/// `.json()` would re-serialize and silently break the HMAC.
#[derive(Debug, Clone, Serialize)]
pub struct EsealRequest {
    pub client_id: String,
    /// 1–30 files.
    pub files: Vec<EsealFile>,
    /// AdES form. We use `"CAdES"` (not JAdES — eID Easy does not emit JAdES).
    pub signature_form: String,
    /// e.g. `"CAdES_BASELINE_T"` — must be enabled for our client.
    pub signature_profile: String,
}

impl EsealRequest {
    /// The CAdES form string eID Easy expects.
    pub const FORM_CADES: &'static str = "CAdES";
    /// Default profile (confirm enabled for our client before production).
    pub const PROFILE_CADES_BASELINE_T: &'static str = "CAdES_BASELINE_T";

    /// Build a single-digest request — the only shape this adapter sends, since
    /// `SealPort::seal` takes one payload hash at a time.
    pub fn single(
        client_id: impl Into<String>,
        file: EsealFile,
        signature_profile: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            files: vec![file],
            signature_form: Self::FORM_CADES.to_owned(),
            signature_profile: signature_profile.into(),
        }
    }
}

/// One returned signature (detached CAdES, i.e. a `.p7s` / PKCS#7).
#[derive(Debug, Clone, Deserialize)]
pub struct EsealSignatureOut {
    #[serde(rename = "fileName")]
    pub file_name: String,
    /// e.g. `application/pkcs7-signature`.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Base64-encoded detached CAdES signature — this is the seal value we
    /// persist on the passport.
    #[serde(rename = "fileContent")]
    pub file_content: String,
}

/// `POST /api/signatures/e-seal` response body.
#[derive(Debug, Clone, Deserialize)]
pub struct EsealResponse {
    /// `"OK"` on success.
    pub status: String,
    /// One signature per input file digest.
    pub signatures: Vec<EsealSignatureOut>,
}

impl EsealResponse {
    pub fn is_ok(&self) -> bool {
        self.status == "OK"
    }

    /// The single signature this adapter always expects back.
    ///
    /// A non-`OK` status, or a count other than one, means the response does not
    /// answer the request we made — a protocol fault, rather than something to
    /// reach into `signatures[0]` and hope about.
    pub fn single_signature(&self) -> Result<&EsealSignatureOut, EideasyError> {
        if !self.is_ok() {
            return Err(EideasyError::Protocol(format!(
                "status was {:?}, expected \"OK\"",
                self.status
            )));
        }
        match self.signatures.as_slice() {
            [one] => Ok(one),
            other => Err(EideasyError::Protocol(format!(
                "expected exactly 1 signature for 1 digest, got {}",
                other.len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
