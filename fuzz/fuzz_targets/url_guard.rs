#![no_main]
//! Fuzz the create-time SSRF guards — a webhook target goes through
//! `validate_webhook_url`, and a passport's cross-operator references and a
//! transfer counterparty's DID document URL through `validate_public_https_url`.
//! Each is a URL a caller writes.
//! Property: both guards return `Ok`/`Err` for any string, never panic, and
//! accept the normalised URL they return, unchanged. The webhook service stores
//! that form and the delivery drain parses it again, so a URL that read
//! differently the second time would be delivered to a host the check never saw.

use dpp_common::url_guard::{validate_public_https_url, validate_webhook_url};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    for allow_private in [false, true] {
        if let Ok(stored) = validate_webhook_url(raw, allow_private) {
            assert_eq!(
                validate_webhook_url(&stored, allow_private).as_ref(),
                Ok(&stored),
                "webhook URL {raw:?} was stored as {stored:?}, which does not check the same"
            );
        }
    }
    if let Ok(stored) = validate_public_https_url(raw) {
        assert_eq!(
            validate_public_https_url(&stored).as_ref(),
            Ok(&stored),
            "public URL {raw:?} was stored as {stored:?}, which does not check the same"
        );
    }
});
