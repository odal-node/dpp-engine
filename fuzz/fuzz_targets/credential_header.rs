#![no_main]
//! Fuzz the `X-DPP-Credential` header — `/credential/dpp/{dppId}` is
//! unauthenticated, so the header is the first thing an anonymous caller
//! controls, and `read_and_verify` decodes it before any signature is checked.
//! Property: `read_and_verify` never panics, and never returns `Verified` for a
//! credential nobody could have signed.
//!
//! The directory and trust registry here are the generous kind: every issuer
//! gets a DID document publishing the key below, and every issuer is trusted.
//! That leaves the signature as the only thing between the header and a
//! verified read, so a token that gets through is a forged one.
//!
//! Each input is tried twice: as the header, and as three lines (header JSON,
//! payload JSON, signature) that are base64url-encoded and joined with dots
//! here. The second form lets the fuzzer write the claims as JSON rather than
//! find base64 that also decodes to them.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use base64::Engine as _;
use dpp_domain::Audience;
use dpp_vault::middleware::credential::{
    credential_header_name, read_and_verify, CredentialDirectory, CredentialOutcome,
};
use dpp_vc::{DppAccessCredential, StatusList, TrustedIssuerRegistry};
use http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;

/// An Ed25519 public key, base64url without padding. Generated for this target
/// with `openssl genpkey -algorithm ed25519` piped straight into
/// `openssl pkey -pubout`, so the private key was never written anywhere. A real
/// point, so verification reaches the signature check rather than stopping at
/// key decoding, and one nobody can sign for.
const PUBLIC_KEY: &str = "As6EBCx1sAQHbQ_FQKhEBqGOxOwjzXJaQYWVeMikO1w";

/// Publishes [`PUBLIC_KEY`] as the assertion key of whichever DID is asked for,
/// under the fragment `#key-1`, and has no status list.
struct EveryIssuerHoldsTheKey;

#[async_trait::async_trait]
impl CredentialDirectory for EveryIssuerHoldsTheKey {
    async fn did_document(&self, issuer_did: &str) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "id": issuer_did,
            "verificationMethod": [{
                "id": "#key-1",
                "type": "JsonWebKey2020",
                "controller": issuer_did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": PUBLIC_KEY },
            }],
            "assertionMethod": ["#key-1"],
        }))
    }

    async fn status_list(&self, _credential: &DppAccessCredential) -> Option<StatusList> {
        None
    }
}

struct TrustsEveryIssuer;

impl TrustedIssuerRegistry for TrustsEveryIssuer {
    fn is_trusted_for_audience(&self, _issuer_did: &str, _audience: Audience) -> bool {
        true
    }
}

/// Run a future that never waits. Both lookups above answer at once, so the
/// first poll completes, and no runtime is needed.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("read_and_verify waited on something other than the directory"),
    }
}

fn check(token: &[u8]) {
    let Ok(value) = HeaderValue::from_bytes(token) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(credential_header_name(), value);
    let outcome = ready(read_and_verify(
        &headers,
        &EveryIssuerHoldsTheKey,
        &TrustsEveryIssuer,
    ));
    assert!(
        !matches!(outcome, CredentialOutcome::Verified(_)),
        "verified a credential the key never signed: {:?}",
        String::from_utf8_lossy(token)
    );
}

fuzz_target!(|data: &[u8]| {
    check(data);

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let token = data
        .splitn(3, |&b| b == b'\n')
        .map(|part| b64.encode(part))
        .collect::<Vec<_>>()
        .join(".");
    check(token.as_bytes());
});
