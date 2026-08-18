//! The one way this workspace makes an outbound HTTP request to a target it did
//! not choose.
//!
//! # Why this module exists
//!
//! [`crate::url_guard`] already defines *which* targets are refused. It was
//! being applied unevenly: some call sites used the resolving, fetch-time guard
//! and a client with redirects disabled and a body cap; others used the
//! IP-literal-only check and a bare `reqwest::get`. Those are not two opinions
//! about risk — the weaker combination does not guard anything a hostname can
//! express, because [`crate::url_guard::validate_public_https_url`] passes every
//! `Host::Domain` unchecked and the default redirect policy will follow a public
//! host into the internal network on the second hop.
//!
//! So the guard is not the thing that was missing; *using it* was. This module
//! makes the correct combination the shortest path to an outbound request, and
//! `outbound-check` in the justfile keeps `reqwest::get` and `Client::new()` out
//! of service `src/` so a future call site cannot quietly reintroduce the weaker
//! one.
//!
//! # What "guarded" means here
//!
//! Four properties, and each rules out a specific bypass:
//!
//! - **[`url_guard::assert_public_target`] before the request** — requires
//!   `https` and re-resolves the host now, so a name that resolves to loopback,
//!   RFC1918, link-local or a cloud metadata address is refused. The IP-literal
//!   checks cannot do this; only the resolving one holds for a hostname.
//! - **Redirects are not followed.** The guard checks the host it was given, so
//!   a followed redirect escapes it. A public host answering `302` to
//!   `https://169.254.169.254/…` is otherwise a complete bypass of the point
//!   above.
//! - **A response body cap**, enforced by streaming rather than after the fact,
//!   so a hostile or broken target cannot make the node buffer without bound.
//! - **A request timeout**, so a target that accepts the connection and never
//!   answers cannot pin a task and a connection indefinitely.
//!
//! # What this module deliberately does not cover
//!
//! Outbound targets the **operator chose** — webhook receivers, the QTSP, the EU
//! registry — are a different trust class and keep their own clients. The
//! webhook drain in particular has a documented `allow_private` opt-out so a
//! self-hoster can deliver to their own internal receiver, and that opt-out
//! would be wrong here: these targets are named by a stranger.
//!
//! # Known residual: DNS rebinding
//!
//! [`url_guard::assert_public_target`] resolves the host, and then the client
//! resolves it again to open the connection. A zero-TTL record alternating a
//! public and an internal answer passes the first and connects to the second.
//! Closing it means resolving once and connecting to *that* address (a
//! `dns_resolver` override on the client that applies
//! [`url_guard::ip_is_disallowed`] to every answer). Not done here, and called
//! out so the gap is a known one rather than an assumed-absent one.

use std::time::Duration;

use futures::StreamExt;
use reqwest::Client;
use serde_json::Value;

use crate::url_guard;

/// Per-request timeout for a guarded fetch.
///
/// Short on purpose: every caller treats a failure as "unverifiable" and fails
/// closed, so waiting longer buys nothing and costs a held task.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default response cap. Generous for a DID document or a published passport's
/// public view, and small enough that a hostile target cannot use it as a
/// memory-growth lever.
pub const DEFAULT_MAX_BODY: usize = 256 * 1024;

/// Why a guarded fetch did not produce a document.
///
/// Callers fail closed on all of these, but they are distinguished so a log line
/// can say which — "the guard refused this target" and "the target was down" are
/// very different things to an operator reading them at 3 a.m.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The target failed [`url_guard::assert_public_target`].
    Refused(String),
    /// Transport failure, timeout, or a non-2xx status.
    Unreachable(String),
    /// The body exceeded the cap, or did not parse as JSON.
    Body(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "target refused by the outbound guard: {r}"),
            Self::Unreachable(r) => write!(f, "target unreachable: {r}"),
            Self::Body(r) => write!(f, "response body rejected: {r}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Build the client every guarded fetch uses.
///
/// Constructed here rather than accepted from a caller so the redirect and
/// timeout policy cannot be weakened by sharing a general-purpose client with
/// laxer settings — the failure mode that produced the two unguarded call sites
/// this module replaces.
///
/// Prefer [`guarded_client`], which builds this once per process.
#[must_use]
pub fn build_guarded_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(DEFAULT_TIMEOUT)
        .build()
        // A builder failure here means no TLS backend, which is a broken build
        // rather than a runtime condition. `Client::new()` panics on the same
        // condition, so falling back to it changes nothing except that the
        // fallback has no redirect policy — hence the explicit rebuild with the
        // policy still set rather than a bare `Client::new()`.
        .unwrap_or_else(|_| {
            Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client cannot be constructed")
        })
}

/// The process-wide guarded client. Cloning a `reqwest::Client` shares one
/// connection pool, so callers should clone this rather than build their own.
pub fn guarded_client() -> Client {
    static CLIENT: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(build_guarded_client).clone()
}

/// Fetch `url` as JSON with every guard in this module's docs applied.
///
/// # Errors
/// [`FetchError`] — refused by the guard, unreachable/non-2xx, or a body that
/// exceeded `max_bytes` or did not parse. Every variant is fail-closed: a caller
/// must never treat any of them as a pass.
pub async fn fetch_json(client: &Client, url: &str, max_bytes: usize) -> Result<Value, FetchError> {
    // Guard before the request, not after — and before any DNS the client would
    // do, so the refusal costs nothing.
    url_guard::assert_public_target(url)
        .await
        .map_err(FetchError::Refused)?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| FetchError::Unreachable(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(FetchError::Unreachable(format!("HTTP {}", resp.status())));
    }
    read_capped_json(resp, max_bytes).await
}

/// Read at most `max_bytes`, then parse.
///
/// Refuses rather than truncates: a truncated document would fail to parse
/// anyway, and an explicit refusal is the honest log line.
async fn read_capped_json(resp: reqwest::Response, max_bytes: usize) -> Result<Value, FetchError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FetchError::Unreachable(e.to_string()))?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(FetchError::Body(format!(
                "response exceeded the {max_bytes}-byte cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| FetchError::Body(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard runs before the request, so an internal target is refused
    /// without any network access at all — which is also why this test needs
    /// none.
    #[tokio::test]
    async fn internal_targets_are_refused_before_the_request() {
        let client = build_guarded_client();
        for url in [
            "https://127.0.0.1/.well-known/did.json",
            "https://[::1]/.well-known/did.json",
            "https://10.0.0.5/dpp/x",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost:8080/.well-known/did.json",
            "http://example.com/.well-known/did.json", // plain http
            "not a url",
        ] {
            let err = fetch_json(&client, url, DEFAULT_MAX_BODY)
                .await
                .expect_err("an internal or non-https target must be refused");
            assert!(
                matches!(err, FetchError::Refused(_)),
                "{url} must be refused by the guard, got {err:?}"
            );
        }
    }

    /// Spawn a loopback axum server and return its base URL.
    ///
    /// The two tests below drive the *client* half of the guard, so they need a
    /// server the guard never inspects — which is the point: a hostile public
    /// host is one `assert_public_target` has already approved.
    async fn spawn(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// The control a redirect defeats. Without it the guard is a first-hop
    /// check, and a public host answering `302` walks the node into its own
    /// network — which is why this asserts the client surfaces the 302 rather
    /// than resolving it.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        use axum::response::IntoResponse as _;

        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::FOUND,
                    [(
                        axum::http::header::LOCATION,
                        "http://169.254.169.254/latest",
                    )],
                )
                    .into_response()
            }),
        );
        let base = spawn(app).await;

        // The guard is bypassed deliberately here: the target is loopback, which
        // `fetch_json` would (correctly) refuse, and the behaviour under test is
        // the client policy that applies *after* a target has been approved.
        let resp = build_guarded_client()
            .get(&base)
            .send()
            .await
            .expect("the redirect response itself arrives");
        assert_eq!(
            resp.status(),
            302,
            "the client must surface the redirect, not follow it"
        );
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_refused() {
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "a".repeat(4096) }));
        let base = spawn(app).await;

        let resp = build_guarded_client()
            .get(&base)
            .send()
            .await
            .expect("response");
        let err = read_capped_json(resp, 512)
            .await
            .expect_err("a 4 KiB body must not pass a 512-byte cap");
        assert!(matches!(err, FetchError::Body(_)), "got {err:?}");
    }

    /// A body inside the cap parses normally — so the cap is a cap, not a
    /// blanket refusal.
    #[tokio::test]
    async fn a_body_within_the_cap_parses() {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "id": "did:web:x" })) }),
        );
        let base = spawn(app).await;

        let resp = build_guarded_client()
            .get(&base)
            .send()
            .await
            .expect("response");
        let doc = read_capped_json(resp, DEFAULT_MAX_BODY)
            .await
            .expect("a small JSON body parses");
        assert_eq!(doc["id"], "did:web:x");
    }

    #[test]
    fn fetch_error_displays_which_control_refused() {
        assert!(
            FetchError::Refused("host is a non-public address".into())
                .to_string()
                .contains("outbound guard")
        );
        assert!(
            FetchError::Unreachable("HTTP 500".into())
                .to_string()
                .contains("unreachable")
        );
        assert!(
            FetchError::Body("too big".into())
                .to_string()
                .contains("body")
        );
    }
}
