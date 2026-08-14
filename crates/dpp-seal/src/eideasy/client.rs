//! eID Easy Cloud Direct e-Sealing HTTP client.
//!
//! One call: `POST {base_url}/api/signatures/e-seal`, HMAC-authenticated, taking
//! a base64 SHA-256 digest and returning a detached CAdES `.p7s` over it.
//!
//! # The one rule this module exists to enforce
//!
//! The HMAC covers `METHOD + PATH + X-Timestamp + RAW_REQUEST_BODY`, and eID
//! Easy is explicit that the body term is the **exact bytes sent** — "do not
//! pretty-print, reorder, or reserialize". [`SignedBody`] makes that structural
//! rather than a comment someone has to notice: the body is serialized once into
//! it, the signature is derived from that same value, and nothing can take the
//! bytes without the signature that goes with them. `reqwest`'s `.json()` would
//! re-serialize between signing and sending, silently producing a 401 that looks
//! exactly like a bad key.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use dpp_domain::ports::seal::{
    SealCapabilities, SealFormat, SealMode, SealRequest, SealedEnvelope,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::config::EideasyConfig;
use super::error::EideasyError;
use crate::backend::SealBackend;
use crate::error::SealError;

use super::types::{EsealFile, EsealRequest, EsealResponse};

type HmacSha256 = Hmac<Sha256>;

/// Path component of the e-seal endpoint — used both for the URL and, verbatim,
/// as the `PATH` term in the HMAC message.
pub const ESEAL_PATH: &str = "/api/signatures/e-seal";

const METHOD: &str = "POST";

/// Compose the HMAC message string per the eID Easy contract.
///
/// `message = METHOD + PATH + X-Timestamp + RAW_REQUEST_BODY`.
/// Kept as a pure helper so it can be unit-tested against the documented example
/// without any network or crypto.
pub fn hmac_message(method: &str, path: &str, timestamp_secs: u64, raw_body: &str) -> String {
    format!("{method}{path}{timestamp_secs}{raw_body}")
}

/// A request body and the signature over those exact bytes, inseparable.
struct SignedBody {
    body: String,
    timestamp: u64,
    signature: String,
}

impl SignedBody {
    fn new(req: &EsealRequest, hmac_key: &str, timestamp: u64) -> Result<Self, EideasyError> {
        // The one and only serialization.
        let body = serde_json::to_string(req)
            .map_err(|e| EideasyError::Protocol(format!("request body serialization: {e}")))?;

        let message = hmac_message(METHOD, ESEAL_PATH, timestamp, &body);
        let mut mac =
            HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(message.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());

        Ok(Self {
            body,
            timestamp,
            signature,
        })
    }
}

/// HTTP client for eID Easy Cloud Direct e-Sealing.
pub struct EideasyClient {
    http: reqwest::Client,
    config: EideasyConfig,
}

impl EideasyClient {
    pub fn new(config: EideasyConfig) -> Result<Self, SealError> {
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| SealError::Config(format!("HTTP client build failed: {e}")))?;
        Ok(Self { http, config })
    }

    /// Seal one hex SHA-256 digest, returning the base64 detached CAdES `.p7s`.
    ///
    /// `file_name` is the correlation label eID Easy echoes back as
    /// `<file_name>.p7s`; it carries no extension (see [`EsealFile`]).
    pub async fn seal_digest(
        &self,
        file_name: &str,
        hex_digest: &str,
    ) -> Result<String, SealError> {
        let file = EsealFile::from_hex_digest(file_name, hex_digest)?;
        let req = EsealRequest::single(
            self.config.client_id.clone(),
            file,
            self.config.signature_profile.clone(),
        );
        let signed = SignedBody::new(&req, &self.config.hmac_key, unix_now()?)?;

        let response = self
            .http
            .post(format!("{}{ESEAL_PATH}", self.config.base_url))
            .header("Content-Type", "application/json")
            .header("X-Timestamp", signed.timestamp.to_string())
            .header("X-HMAC-Signature", &signed.signature)
            // `.body()`, never `.json()` — these are the bytes the HMAC covers.
            .body(signed.body)
            .send()
            .await
            // Nothing reached the far side, so there is no status and no body to
            // classify against — this is transport, not a provider answer.
            .map_err(|e| SealError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            // Read the two diagnostic headers before consuming the body: `Date`
            // is the only external clock reference we get for free, and it is
            // what separates a drifted clock from a bad key on a 401.
            let their_time = server_unix_time(response.headers());
            let retry_after_secs = response
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());

            // The body may carry a useful provider diagnostic, but it is unbounded
            // and not ours — it goes to the log, never into the returned error.
            let detail = response.text().await.unwrap_or_default();
            tracing::warn!(
                status = status.as_u16(),
                detail = %detail.chars().take(512).collect::<String>(),
                "eID Easy e-seal request failed"
            );
            return Err(match status.as_u16() {
                429 => EideasyError::RateLimited { retry_after_secs },
                s @ (401 | 403) => EideasyError::Auth {
                    status: s,
                    hint: clock_hint(signed.timestamp, their_time),
                },
                s => EideasyError::Provider { status: s },
            }
            .into());
        }

        // A body that fails to decode is a protocol fault, not a transport one:
        // the exchange completed, the bytes are just not what was promised.
        let parsed: EsealResponse = response
            .json()
            .await
            .map_err(|e| EideasyError::Protocol(e.to_string()))?;
        Ok(parsed.single_signature()?.file_content.clone())
    }
}

#[async_trait]
impl SealBackend for EideasyClient {
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, SealError> {
        // The digest doubles as the correlation label: eID Easy echoes `fileName`
        // back, so deriving it from the digest makes a mismatched response visible
        // without holding request state. No extension — see `EsealFile::file_name`.
        let file_name = format!(
            "dpp-{}",
            &req.payload_hash[..req.payload_hash.len().min(16)]
        );
        let seal_value = self.seal_digest(&file_name, &req.payload_hash).await?;

        // Which certificate the provider actually sealed with, read out of the
        // `.p7s` it returned — **as reported by the seal**, never as verified.
        // Whether that certificate was qualified, and on the EU Trusted List at
        // this moment, is the independent validator's question; recording which
        // one to ask about is what stops an auditor having to be handed the
        // bytes and parse them by hand.
        //
        // A seal that cannot be parsed still stores: the envelope is what was
        // bought, and losing it over an unfillable convenience field would
        // trade something that matters for something that does not.
        let signing_cert_ref = BASE64
            .decode(&seal_value)
            .ok()
            .and_then(|der| crate::cades::signer_certificate_thumbprint(&der).ok())
            .flatten();

        Ok(SealedEnvelope {
            format: SealFormat::Cades,
            seal_value,
            signing_cert_ref,
            sealed_at: Utc::now(),
            placeholder: false,
        })
    }

    fn capabilities(&self) -> SealCapabilities {
        // eID Easy Direct e-Sealing offers the CAdES profile only, and this node
        // holds the seal on operators' behalf, so `ProviderSeal` is the one mode.
        // `verify()` takes the trait's refusing default and no capability claims
        // otherwise.
        SealCapabilities {
            supported_formats: vec![SealFormat::Cades],
            supported_modes: vec![SealMode::ProviderSeal],
        }
    }
}

/// Current UNIX seconds for `X-Timestamp` (eID Easy allows 5 minutes of skew).
fn unix_now() -> Result<u64, SealError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        // The node's clock, not the provider's answer — nothing about eID Easy
        // classifies this one.
        .map_err(|e| SealError::Config(format!("system clock is before the UNIX epoch: {e}")))
}

/// The provider's clock, from the RFC 9110 `Date` header every response carries.
///
/// HTTP's preferred form is IMF-fixdate (`Sat, 09 Mar 2024 16:00:00 GMT`), whose
/// literal `GMT` zone chrono's RFC 2822 parser rejects — so that format is tried
/// first, with RFC 2822 as the fallback for a server sending a numeric offset.
/// An unparseable header yields `None`: a wrong clock reading would produce a
/// confidently wrong diagnosis, which is worse than no diagnosis.
fn server_unix_time(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get(reqwest::header::DATE)?.to_str().ok()?.trim();
    let secs = chrono::NaiveDateTime::parse_from_str(raw, "%a, %d %b %Y %H:%M:%S GMT")
        .map(|d| d.and_utc().timestamp())
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(raw).map(|d| d.timestamp()))
        .ok()?;
    u64::try_from(secs).ok()
}

/// eID Easy's stated tolerance on `X-Timestamp`.
const MAX_SKEW_SECS: u64 = 300;

/// Decide whether a rejection is explained by clock drift.
///
/// Only claims skew when it exceeds the provider's own window — inside it, the
/// timestamp was acceptable and the rejection means something else, so pointing
/// at the clock would send the operator down the wrong path just as surely as
/// staying silent sends them to rotate a good key.
fn clock_hint(ours: u64, theirs: Option<u64>) -> super::error::AuthHint {
    match theirs {
        Some(theirs) if ours.abs_diff(theirs) > MAX_SKEW_SECS => {
            super::error::AuthHint::ClockSkew { ours, theirs }
        }
        _ => super::error::AuthHint::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_message_matches_documented_example() {
        // From eID Easy docs (POST, the e-seal path, ts, exact body).
        let body = r#"{"client_id":"client-id","files":[{"fileName":"document.pdf","fileContent":"rxr4oMRqMAjrAdhgXjjYeLlh285M9UU1wxj+ksg3efY=","mimeType":"application/pdf"}],"signature_form":"CAdES","signature_profile":"CAdES_BASELINE_T"}"#;
        let msg = hmac_message("POST", ESEAL_PATH, 1710000000, body);
        assert!(msg.starts_with("POST/api/signatures/e-seal1710000000{"));
        // The body must appear verbatim and last — no separator, no re-encoding.
        assert!(msg.ends_with(body));
    }

    fn example_request() -> EsealRequest {
        EsealRequest::single(
            "client-id",
            EsealFile::from_hex_digest("dpp-123", &"ab".repeat(32)).unwrap(),
            EsealRequest::PROFILE_CADES_BASELINE_T,
        )
    }

    /// The pairing the module is shaped around: the carried signature must verify
    /// against the carried body. If anything ever re-serializes in between, this
    /// is what catches it.
    #[test]
    fn the_signature_verifies_against_the_body_it_carries() {
        let signed = SignedBody::new(&example_request(), "test-key", 1710000000).unwrap();

        let message = hmac_message(METHOD, ESEAL_PATH, signed.timestamp, &signed.body);
        let mut mac = HmacSha256::new_from_slice(b"test-key").unwrap();
        mac.update(message.as_bytes());
        let expected = BASE64.encode(mac.finalize().into_bytes());

        assert_eq!(signed.signature, expected);
    }

    #[test]
    fn a_different_key_produces_a_different_signature() {
        let a = SignedBody::new(&example_request(), "key-a", 1710000000).unwrap();
        let b = SignedBody::new(&example_request(), "key-b", 1710000000).unwrap();
        assert_eq!(a.body, b.body);
        assert_ne!(a.signature, b.signature);
    }

    #[test]
    fn a_clock_inside_the_window_is_not_blamed() {
        use super::super::error::AuthHint;
        // Inside the tolerance, the timestamp was fine — the 401 means something
        // else, and blaming the clock would misdirect exactly as badly.
        assert_eq!(clock_hint(1710000000, Some(1710000000)), AuthHint::None);
        assert_eq!(clock_hint(1710000000, Some(1710000299)), AuthHint::None);
        // No `Date` header: nothing to compare, so claim nothing.
        assert_eq!(clock_hint(1710000000, None), AuthHint::None);
    }

    #[test]
    fn a_drifted_clock_is_named_in_the_error() {
        use super::super::error::AuthHint;
        let hint = clock_hint(1710000000, Some(1710000901));
        assert!(matches!(hint, AuthHint::ClockSkew { .. }));
        // Drift in either direction counts.
        assert!(matches!(
            clock_hint(1710000901, Some(1710000000)),
            AuthHint::ClockSkew { .. }
        ));

        let rendered = EideasyError::Auth { status: 401, hint }.to_string();
        assert!(rendered.contains("clock"), "{rendered}");
        assert!(
            rendered.contains("before rotating"),
            "the message must steer away from rotating a good key: {rendered}"
        );
    }

    #[test]
    fn the_date_header_is_parsed_as_the_provider_clock() {
        // IMF-fixdate, the form HTTP senders are required to use.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::DATE,
            "Sat, 09 Mar 2024 16:00:00 GMT".parse().unwrap(),
        );
        assert_eq!(server_unix_time(&headers), Some(1710000000));

        // A numeric-offset sender still parses, via the RFC 2822 fallback.
        let mut rfc2822 = reqwest::header::HeaderMap::new();
        rfc2822.insert(
            reqwest::header::DATE,
            "Sat, 09 Mar 2024 16:00:00 +0000".parse().unwrap(),
        );
        assert_eq!(server_unix_time(&rfc2822), Some(1710000000));

        // Absent or unparseable yields nothing rather than a wrong number.
        assert_eq!(server_unix_time(&reqwest::header::HeaderMap::new()), None);
        let mut bad = reqwest::header::HeaderMap::new();
        bad.insert(reqwest::header::DATE, "not a date".parse().unwrap());
        assert_eq!(server_unix_time(&bad), None);
    }

    #[test]
    fn the_timestamp_is_bound_into_the_signature() {
        let a = SignedBody::new(&example_request(), "test-key", 1710000000).unwrap();
        let b = SignedBody::new(&example_request(), "test-key", 1710000001).unwrap();
        assert_ne!(
            a.signature, b.signature,
            "a replayed signature would verify"
        );
    }
}
