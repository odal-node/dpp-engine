//! Passport id validation.

/// Whether `id` is a syntactically valid passport id (a canonical UUID).
///
/// The resolver validates this at its own edge — it must not depend on the
/// upstream vault rejecting malformed ids for its *own* output safety. A rejected
/// id never reaches a server-to-server URL, a Redis cache key, or the rendered
/// SVG/HTML, closing a latent SSRF / cache-key / XSS surface.
pub fn is_valid_dpp_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

/// Whether `gtin` is a syntactically valid GTIN for resolution: 8–14 ASCII
/// digits and nothing else.
///
/// Validated at the resolver edge for the same reason as [`is_valid_dpp_id`]:
/// a value like `../admin` (from a percent-encoded `/01/{gtin}` path segment,
/// which Axum decodes after routing) must never reach the server-to-server
/// vault URL, closing a path-traversal / SSRF surface.
pub fn is_valid_gtin(gtin: &str) -> bool {
    (8..=14).contains(&gtin.len()) && gtin.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::is_valid_dpp_id;

    #[test]
    fn accepts_canonical_uuid() {
        assert!(is_valid_dpp_id("0190a9f0-1234-7abc-8def-0123456789ab"));
    }

    #[test]
    fn rejects_injection_shaped_ids() {
        // Anything that could alter a URL, a cache key, or break out of an
        // SVG/HTML context must be rejected at the edge.
        for bad in [
            "../admin",
            "x?admin=1",
            "</title><script>alert(1)</script>",
            "a:b\nc",
            "",
            "not-a-uuid",
        ] {
            assert!(!is_valid_dpp_id(bad), "should reject: {bad}");
        }
    }

    #[test]
    fn gtin_accepts_digits_rejects_traversal() {
        use super::is_valid_gtin;
        assert!(is_valid_gtin("09506000134352")); // GTIN-14
        assert!(is_valid_gtin("12345678")); // GTIN-8
        for bad in [
            "../admin",
            "%2E%2E",
            "0950/6000",
            "abc",
            "",
            "1234567",
            "123456789012345",
        ] {
            assert!(!is_valid_gtin(bad), "should reject: {bad}");
        }
    }
}
