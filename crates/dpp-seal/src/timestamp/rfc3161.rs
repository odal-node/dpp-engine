//! Any RFC 3161 timestamp authority, reached over HTTP.
//!
//! The provider-independent way to get a fresh timestamp: a `TimeStampReq` POSTed
//! to an address the operator configures, answered with a `TimeStampResp` carrying
//! a token. Nothing here is specific to any one authority, and nothing is
//! specific to any sealing provider — a qualified timestamp is a service of a
//! qualified trust service provider (Reg. (EU) No 910/2014 Art. 42), and which
//! one an operator buys it from is theirs to decide.
//!
//! # The address is the operator's, so the client is not the guarded one
//!
//! `dpp_common::outbound` exists for targets a stranger named. This one is chosen
//! by whoever runs the node, in its environment, like the sealing provider's — and
//! the guard's own documentation lists exactly that class as the case it must not
//! be applied to, since a self-hoster's authority may well live on an internal
//! address the resolving guard would refuse. What is kept from the guard's
//! discipline is everything that does not depend on who chose the target: **no
//! redirects** (a followed redirect would leave the address the operator
//! configured), **a capped response body** and **a timeout**.
//!
//! The response is untrusted input all the same. It is parsed with the strict DER
//! reader, verified before anything is read from it, and then checked against what
//! was asked — see [`Rfc3161Source::stamp`].
//!
//! # What is not here
//!
//! **Authentication.** Some commercial authorities want credentials; this sends
//! none, and an address carrying credentials is refused rather than logged. Adding
//! it means a secret with a lifecycle, which is its own decision.

use std::time::Duration;

use async_trait::async_trait;
use der::{Decode as _, Encode as _, asn1::Uint};
use rand::Rng as _;
use url::Url;

use crate::cades::MessageImprint;
use crate::error::SealError;
use crate::timestamp::TimestampSource;

/// The most a response may be before it is refused, in bytes.
///
/// A token with a certificate chain is a few kilobytes and one carrying
/// revocation values tens of them. The cap bounds what a hostile or broken
/// authority can make this process hold, and is not meant to be tight.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// `application/timestamp-query` — RFC 3161 §3.4.
const REQUEST_CONTENT_TYPE: &str = "application/timestamp-query";

/// `TimeStampReq` — RFC 3161 §2.4.1.
#[derive(der::Sequence)]
struct TimeStampReq {
    version: u8,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    req_policy: Option<const_oid::ObjectIdentifier>,
    #[asn1(optional = "true")]
    nonce: Option<Uint>,
    #[asn1(default = "certificates_not_requested")]
    cert_req: bool,
}

fn certificates_not_requested() -> bool {
    false
}

/// `TimeStampResp` — RFC 3161 §2.4.2.
#[derive(der::Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<der::Any>,
}

/// `PKIStatusInfo` — RFC 3161 §2.4.2.
#[derive(der::Sequence)]
struct PkiStatusInfo {
    status: u8,
    #[asn1(optional = "true")]
    status_string: Option<Vec<der::Any>>,
    #[asn1(optional = "true")]
    fail_info: Option<der::asn1::BitString>,
}

/// `granted` and `grantedWithMods` — the two statuses that carry a token.
fn carries_a_token(status: u8) -> bool {
    status <= 1
}

/// An authority reached by address.
pub struct Rfc3161Source {
    http: reqwest::Client,
    url: Url,
}

impl Rfc3161Source {
    /// A source for the authority at `url`.
    ///
    /// # Which addresses are accepted
    ///
    /// `https`, always, with one exception: `http` to a **loopback** host, which
    /// is what a developer running an authority on their own machine has. A
    /// request that names the node's own digest to a remote host in the clear is
    /// not something to allow by accident. An address with credentials in it is
    /// refused outright, so a secret never reaches a log line by being part of a
    /// URL.
    ///
    /// # Errors
    ///
    /// [`SealError::Config`] when the address is not acceptable or the client
    /// cannot be built.
    pub fn new(url: &str, timeout: Duration) -> Result<Self, SealError> {
        let url = Url::parse(url)
            .map_err(|e| SealError::Config(format!("the timestamp authority address: {e}")))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(SealError::Config(
                "the timestamp authority address carries credentials, which would reach every log \
                 line that prints it — this source sends none"
                    .to_owned(),
            ));
        }
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(&url) => {}
            other => {
                return Err(SealError::Config(format!(
                    "the timestamp authority address uses `{other}`; only `https` is accepted \
                     (and `http` to a loopback host, for an authority on this machine)"
                )));
            }
        }

        let http = reqwest::Client::builder()
            .timeout(timeout)
            // A followed redirect would leave the address the operator
            // configured, which is the one thing this client is told to trust.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SealError::Config(format!("HTTP client build failed: {e}")))?;
        Ok(Self { http, url })
    }
}

/// Whether the address names this machine.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// A transport failure, without the address.
///
/// `reqwest` prints the request URL inside its error, and this error ends up in
/// the renewal's log line and outcome. The address's path or query can carry a
/// token even though userinfo is refused, so it is dropped here, the same reason
/// the boot line names only the host.
fn transport(e: reqwest::Error) -> SealError {
    SealError::Transport(format!("the timestamp authority: {}", e.without_url()))
}

/// Strip control characters from text an authority sent, for a log line.
///
/// The text is the authority's own and arrives over a network; one carrying a
/// newline could forge the line after it.
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

#[async_trait]
impl TimestampSource for Rfc3161Source {
    /// # What is checked on the way back
    ///
    /// The answer is untrusted, and "an authority answered" is not "an authority
    /// stamped this". Before the token is handed on:
    ///
    /// - the status must be `granted` or `grantedWithMods`, and carry a token;
    /// - the token's own signature must hold, and the digest tying it to its
    ///   `TSTInfo`;
    /// - its imprint must be **the one that was sent**, under SHA-256;
    /// - and it must echo the **nonce** this request carried. RFC 3161 §2.4.2
    ///   makes that the client's check, and it is what stops an old answer being
    ///   replayed to a new request.
    ///
    /// What is *not* checked here: whether the authority is one anybody lists, or
    /// whether the time is plausible. Those belong to the caller, which knows what
    /// this is for.
    async fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0u8; 8];
        rand::rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut nonce);
        let nonce = Uint::new(&nonce)
            .map_err(|e| SealError::Config(format!("cannot encode the request nonce: {e}")))?;
        let expected_nonce = nonce.as_bytes().to_vec();

        let request = TimeStampReq {
            version: 1,
            message_imprint: MessageImprint {
                hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                    oid: const_oid::db::rfc5912::ID_SHA_256,
                    parameters: None,
                },
                hashed_message: der::asn1::OctetString::new(imprint.as_slice())
                    .map_err(|e| SealError::Config(format!("cannot encode the imprint: {e}")))?,
            },
            req_policy: None,
            nonce: Some(nonce),
            // The authority's certificate, so the token is self-contained — a
            // verifier years from now cannot be expected to find it.
            cert_req: true,
        }
        .to_der()
        .map_err(|e| SealError::Config(format!("cannot encode the request: {e}")))?;

        let mut response = self
            .http
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, REQUEST_CONTENT_TYPE)
            .body(request)
            .send()
            .await
            .map_err(transport)?;
        if !response.status().is_success() {
            return Err(SealError::Backend(format!(
                "the timestamp authority answered HTTP {}",
                response.status()
            )));
        }

        // Streamed against the cap, so a hostile authority cannot make this
        // process buffer without bound by sending a long body.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(SealError::Backend(format!(
                    "the timestamp authority's answer is over {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }

        let reply = TimeStampResp::from_der(&body).map_err(|e| {
            SealError::Backend(format!(
                "the timestamp authority's answer is not a TimeStampResp: {e}"
            ))
        })?;
        if !carries_a_token(reply.status.status) {
            let why = reply
                .status
                .status_string
                .iter()
                .flatten()
                .filter_map(|s| s.decode_as::<der::asn1::Utf8StringRef<'_>>().ok())
                .map(|s| printable(s.as_ref()))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(SealError::Backend(format!(
                "the timestamp authority refused (status {}){}",
                reply.status.status,
                if why.is_empty() {
                    String::new()
                } else {
                    format!(": {why}")
                }
            )));
        }
        let token = reply
            .time_stamp_token
            .ok_or_else(|| {
                SealError::Backend(
                    "the timestamp authority granted the request and sent no token".to_owned(),
                )
            })?
            .to_der()
            .map_err(|e| SealError::Backend(format!("the token does not re-encode: {e}")))?;

        let Some(facts) = crate::cades::token_facts(&token) else {
            return Err(SealError::Backend(
                "the timestamp authority's token is not a well-formed, self-consistent time-stamp \
                 token — its signature or its content digest did not hold"
                    .to_owned(),
            ));
        };
        if facts.hash_algorithm != const_oid::db::rfc5912::ID_SHA_256
            || facts.imprint.as_slice() != imprint.as_slice()
        {
            return Err(SealError::Backend(
                "the timestamp authority's token stamps something other than the imprint that was \
                 sent"
                    .to_owned(),
            ));
        }
        if facts.nonce.as_deref() != Some(expected_nonce.as_slice()) {
            return Err(SealError::Backend(
                "the timestamp authority's token does not echo this request's nonce — it may be an \
                 earlier answer replayed"
                    .to_owned(),
            ));
        }
        Ok(token)
    }

    fn name(&self) -> &'static str {
        "rfc3161"
    }
}

#[cfg(test)]
#[path = "rfc3161_tests.rs"]
mod tests;
