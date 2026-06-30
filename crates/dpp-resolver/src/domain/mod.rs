//! Domain types and re-exports for the resolver.
pub mod jws;

/// Whether `id` is a syntactically valid passport id (a canonical UUID).
///
/// The resolver validates this at its own edge — N-4: it must not depend on the
/// upstream vault rejecting malformed ids for its *own* output safety. A rejected
/// id never reaches a server-to-server URL, a Redis cache key, or the rendered
/// SVG/HTML, closing a latent SSRF / cache-key / XSS surface.
pub fn is_valid_dpp_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
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
        // N-4: anything that could alter a URL, a cache key, or break out of an
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
}
