//! `did:web` DID-to-URL resolution (W3C did:web method spec), used by the
//! evidence exporter's transfer-chain counterparty lookup. Pure string
//! transform — no I/O here, callers do their own HTTP fetch.

/// Resolve a `did:web` DID to the URL its document is published at.
///
/// `did:web:example.com` -> `https://example.com/.well-known/did.json`.
/// `did:web:example.com:path:to:id` -> `https://example.com/path/to/id/did.json`.
/// A `:port` encoded as `%3A` in the host segment is decoded back to `:`.
///
/// # Errors
/// A plain string reason if `did` is not a `did:web` DID at all.
pub fn did_web_url(did: &str) -> Result<String, String> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or_else(|| format!("not a did:web DID: {did}"))?;
    let mut segments = rest.split(':');
    let host = segments
        .next()
        .ok_or_else(|| format!("empty did:web host in {did}"))?;
    let host = host.replace("%3A", ":");
    let path_segments: Vec<&str> = segments.collect();
    if path_segments.is_empty() {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        Ok(format!(
            "https://{host}/{}/did.json",
            path_segments.join("/")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathless_did_resolves_to_well_known() {
        assert_eq!(
            did_web_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn path_did_resolves_to_path_plus_did_json() {
        assert_eq!(
            did_web_url("did:web:example.com:operators:acme").unwrap(),
            "https://example.com/operators/acme/did.json"
        );
    }

    #[test]
    fn encoded_port_is_decoded() {
        assert_eq!(
            did_web_url("did:web:example.com%3A8443").unwrap(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn non_did_web_is_an_error() {
        assert!(did_web_url("did:key:z6Mk").is_err());
        assert!(did_web_url("https://example.com").is_err());
    }
}
