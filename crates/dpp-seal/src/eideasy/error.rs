//! Failures that only mean something in terms of this provider's contract.
//!
//! Each variant here encodes something eID Easy specifically does — a
//! five-minute timestamp window, an unpublished rate limit, a status field that
//! can say `ERROR` inside a 200. Classified at the HTTP boundary, where the
//! status and the response headers are still in hand, then handed to the rest of
//! the crate as [`SealError::Backend`] — a rendered message, carrying no
//! provider vocabulary onward.

use crate::error::SealError;

/// Why a 401 most likely happened, when the response gives us enough to say.
///
/// Derived by comparing our `X-Timestamp` against the provider's own `Date`
/// header — the one external clock reference we get for free on every response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHint {
    /// Nothing to add: the clock agreed, or the response carried no usable `Date`.
    None,
    /// Our clock is outside eID Easy's five-minute window, which alone explains
    /// the rejection. Rotating the key here would be chasing the wrong fault.
    ClockSkew { ours: u64, theirs: u64 },
}

impl std::fmt::Display for AuthHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::ClockSkew { ours, theirs } => write!(
                f,
                " — but this node's clock reads {ours} and the provider's reads \
                 {theirs}, a drift of {}s beyond the 5-minute window. Fix the clock \
                 (NTP) before rotating the HMAC key; a skewed timestamp fails \
                 identically to a bad key",
                ours.abs_diff(*theirs)
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EideasyError {
    /// 401/403 — the HMAC key is wrong or rotated, e-seal credentials were never
    /// enabled for this `client_id`, **or the node's clock has drifted**.
    ///
    /// The last one is why `hint` exists. `X-Timestamp` is inside the signed
    /// message and eID Easy allows five minutes of skew, so a drifted clock
    /// produces a 401 that is byte-for-byte the same as a bad key. Without a hint,
    /// the operator rotates a perfectly good credential and the failure persists.
    #[error("eID Easy rejected our credentials (HTTP {status}){hint}")]
    Auth { status: u16, hint: AuthHint },

    /// 429 — too many requests.
    ///
    /// Typed separately from [`Self::Provider`] because it is the one non-success
    /// status that is neither our fault nor a provider fault, and the operator
    /// response is different: not "check the credentials", but "the volume is
    /// above what this contract allows". eID Easy publishes no rate limits, so
    /// the drain's existing exponential backoff (to one hour) is the response;
    /// this exists so the cause is nameable in the logs rather than buried in a
    /// generic provider error.
    #[error("eID Easy rate-limited us (HTTP 429){}", retry_after_secs.map(|s| format!("; Retry-After: {s}s")).unwrap_or_default())]
    RateLimited { retry_after_secs: Option<u64> },

    /// The call completed but the answer was not one we can act on — a non-`OK`
    /// status field, an unparseable body, or a signature count that does not
    /// match the digests we sent.
    #[error("eID Easy protocol: {0}")]
    Protocol(String),

    /// Any other non-success HTTP status.
    #[error("eID Easy returned HTTP {status}")]
    Provider { status: u16 },
}

impl From<EideasyError> for SealError {
    fn from(e: EideasyError) -> Self {
        SealError::Backend(e.to_string())
    }
}
