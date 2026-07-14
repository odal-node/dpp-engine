//! SSRF guard for operator-configured outbound URLs (webhooks).
//!
//! Two layers, shared by both the create handler and the delivery drain:
//!
//! - [`validate_webhook_url`] — synchronous, create-time. Requires `https`,
//!   rejects IP-literal hosts in non-public ranges. Fast-fails obvious mistakes.
//! - [`ip_is_disallowed`] — the range predicate the drain reuses after
//!   **re-resolving** the host at delivery time, which is the authoritative
//!   check (it catches a hostname that resolves to an internal address, and
//!   DNS-rebinding between create and delivery).
//!
//! `allow_private` opts out of the range check: this node is single-tenant, so a
//! self-hosting operator may legitimately deliver to their *own* internal
//! receiver. It defaults off (the Odal-hosted tier must never proxy into the
//! metadata endpoint or Odal's network); operators enable it explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

/// Validate an operator-supplied webhook URL at creation time. Returns the
/// normalised URL string on success, or a human-readable rejection reason.
///
/// When `allow_private` is true the address-range check is skipped (see module
/// docs) — `https` is still required.
pub fn validate_webhook_url(raw: &str, allow_private: bool) -> Result<String, String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    // `Host` parses IP literals correctly (including bracketed IPv6 like `[::1]`,
    // which `host_str()` returns with brackets and so would never parse as an IP).
    let host = url.host().ok_or("webhook URL has no host")?;
    // Trust opt-in: a self-hoster delivering to their own internal network may
    // use a private host and/or plain http — skip the scheme + range guard.
    if allow_private {
        return Ok(url.to_string());
    }
    if url.scheme() != "https" {
        return Err("webhook URL must use https".into());
    }
    let disallowed = match host {
        Host::Ipv4(ip) => ip_is_disallowed(IpAddr::V4(ip)),
        Host::Ipv6(ip) => ip_is_disallowed(IpAddr::V6(ip)),
        // A hostname can't be range-checked without resolving; the delivery-time
        // DNS re-check (in the node drain) is the authoritative guard for those.
        Host::Domain(_) => false,
    };
    if disallowed {
        return Err("webhook URL host is a non-public address".into());
    }
    Ok(url.to_string())
}

/// Validate a public outbound `https` URL: rejects non-`https` schemes and
/// IP-literal hosts in non-public ranges. For URLs that must be resolvable by
/// anyone (e.g. a passport's cross-operator lineage reference) — unlike
/// [`validate_webhook_url`], there is no `allow_private` opt-out.
pub fn validate_public_https_url(raw: &str) -> Result<String, String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    let host = url.host().ok_or("URL has no host")?;
    if url.scheme() != "https" {
        return Err("URL must use https".into());
    }
    let disallowed = match host {
        Host::Ipv4(ip) => ip_is_disallowed(IpAddr::V4(ip)),
        Host::Ipv6(ip) => ip_is_disallowed(IpAddr::V6(ip)),
        Host::Domain(_) => false,
    };
    if disallowed {
        return Err("URL host is a non-public address".into());
    }
    Ok(url.to_string())
}

/// True if `ip` must never be an outbound target: loopback, private, link-local,
/// unique-local, CGNAT, multicast, unspecified, or the cloud metadata address.
#[must_use]
pub fn ip_is_disallowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_disallowed(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ula_v6(v6)
                || is_link_local_v6(v6)
                // ::ffff:a.b.c.d — apply the v4 rules to the embedded address.
                || v6.to_ipv4_mapped().is_some_and(v4_is_disallowed)
        }
    }
}

fn v4_is_disallowed(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254.0.0/16 — includes the 169.254.169.254 metadata IP
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_cgnat_v4(ip)
}

/// 100.64.0.0/10 — carrier-grade NAT (RFC 6598).
fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// fc00::/7 — unique local addresses.
fn is_ula_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 — link-local unicast.
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_and_private_literals() {
        assert!(validate_webhook_url("http://example.com/hook", false).is_err());
        assert!(validate_webhook_url("https://127.0.0.1/hook", false).is_err());
        assert!(validate_webhook_url("https://10.0.0.5/hook", false).is_err());
        assert!(validate_webhook_url("https://169.254.169.254/latest/meta-data", false).is_err());
        assert!(validate_webhook_url("https://[::1]/hook", false).is_err());
        assert!(validate_webhook_url("https://example.com/hook", false).is_ok());
    }

    #[test]
    fn public_https_url_is_strict_with_no_private_opt_out() {
        assert!(validate_public_https_url("https://id.odal-node.io/dpp/x").is_ok());
        assert!(validate_public_https_url("http://id.odal-node.io/dpp/x").is_err());
        assert!(validate_public_https_url("https://127.0.0.1/dpp/x").is_err());
        assert!(validate_public_https_url("https://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_public_https_url("https://[::1]/dpp/x").is_err());
        assert!(validate_public_https_url("not a url").is_err());
    }

    #[test]
    fn allow_private_permits_internal_and_non_https_targets() {
        assert!(validate_webhook_url("https://10.0.0.5/hook", true).is_ok());
        assert!(validate_webhook_url("http://10.0.0.5/hook", true).is_ok());
        // A malformed URL is still rejected even in trust mode.
        assert!(validate_webhook_url("not a url", true).is_err());
    }

    #[test]
    fn range_predicate_covers_the_usual_suspects() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                ip_is_disallowed(ip.parse().unwrap()),
                "{ip} should be disallowed"
            );
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(
                !ip_is_disallowed(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    use proptest::prelude::*;

    proptest! {
        /// For every IPv4 literal, `validate_webhook_url` rejects iff the address
        /// is in a disallowed range — the two guards can never disagree.
        #[test]
        fn validate_agrees_with_range_predicate_v4(
            a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>()
        ) {
            let ip = std::net::Ipv4Addr::new(a, b, c, d);
            let disallowed = ip_is_disallowed(std::net::IpAddr::V4(ip));
            let rejected = validate_webhook_url(&format!("https://{ip}/hook"), false).is_err();
            prop_assert_eq!(rejected, disallowed);
        }

        /// Same invariant for IPv6 literals (the bracketed form that once slipped
        /// past a naive `host_str().parse()` check).
        #[test]
        fn validate_agrees_with_range_predicate_v6(
            segs in proptest::array::uniform8(any::<u16>())
        ) {
            let ip = std::net::Ipv6Addr::from(segs);
            let disallowed = ip_is_disallowed(std::net::IpAddr::V6(ip));
            let rejected = validate_webhook_url(&format!("https://[{ip}]/hook"), false).is_err();
            prop_assert_eq!(rejected, disallowed);
        }
    }
}
