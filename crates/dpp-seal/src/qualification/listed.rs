//! Reading the certificates a Trusted List publishes, shared by both questions.

use base64::Engine as _;
use der::{Decode as _, Encode as _};

/// A base64 certificate's DER, or `None` if it will not decode.
///
/// A list entry that cannot be read is skipped rather than fatal. One
/// unparseable certificate among hundreds must not stop the others being
/// searched, and the consequence of skipping is a miss — the safe direction.
pub(super) fn decoded(base64_certificate: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(base64_certificate.trim())
        .ok()
}

/// A certificate's subject name, DER-encoded.
pub(super) fn subject_der(der: &[u8]) -> Option<Vec<u8>> {
    x509_cert::Certificate::from_der(der)
        .ok()?
        .tbs_certificate
        .subject
        .to_der()
        .ok()
}
