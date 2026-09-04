//! The idempotency-key port and the records that travel across it.

use std::time::Duration;

use async_trait::async_trait;

/// How long a completed key is honoured.
///
/// The window must cover a client's whole retry budget, including an operator
/// restarting an integration the morning after an outage — which is the case
/// this feature exists for. A caller that has not retried within a day is not
/// retrying, and a longer window buys nothing but rows.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// How long an `in_flight` claim is believed before it may be reclaimed.
///
/// A middleware cannot commit its row in the same transaction as the handler's
/// write, so a crash mid-request leaves a claim nothing will ever finish. Past
/// this, the claim is reclaimable and the request runs again; before it, a
/// concurrent duplicate is told to retry rather than allowed to double-execute.
///
/// Sixty seconds is above the longest legitimate keyed request (the 5 MiB bulk
/// import) and below any human's retry patience.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(60);

/// The four-part identity of a keyed request.
///
/// `path` is the matched **route template** (`/dpp/{dppId}/evidence`), not the
/// concrete URI. Two reasons: the template is the identity of the *operation*,
/// and it is drawn from a bounded set, so a caller cannot mint unbounded
/// distinct rows by varying a path parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestKey {
    /// Which caller. The API key's `user_id`, or `mtls:<CN>` for the internal
    /// certificate-gated routes that carry no `AuthContext`. Single-tenant:
    /// this is not a tenant discriminator.
    pub principal: String,
    /// Uppercase HTTP method.
    pub method: String,
    /// The matched route template.
    pub path: String,
    /// The client's opaque `Idempotency-Key` value.
    pub key: String,
}

/// A response held for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredResponse {
    /// The status the first attempt answered with.
    pub status: u16,
    /// Its body, verbatim — except where [`super::RoutePolicy`] redacted a
    /// member before storage.
    pub body: Vec<u8>,
    /// Its `Content-Type`, so the replay is byte-equivalent and not merely
    /// semantically equal.
    pub content_type: Option<String>,
}

/// What the store says about a key the middleware is trying to claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The claim is ours; run the handler and then record the outcome.
    Claimed,
    /// This exact request already completed. Replay this and run nothing.
    Replay(StoredResponse),
    /// Another attempt holds an unexpired claim. Tell the caller to retry.
    InFlight,
    /// The key exists against a **different** request body. The caller asked
    /// for something other than what this key already stands for, so neither
    /// executing nor replaying is right.
    FingerprintMismatch,
}

/// Failures the store itself can raise. Deliberately not a domain error type:
/// this crate has no domain dependency, and the middleware maps these to a
/// problem document.
#[derive(Debug, thiserror::Error)]
pub enum IdempotencyError {
    /// The backing store could not be reached or refused the statement.
    #[error("idempotency store unavailable: {0}")]
    Unavailable(String),
}

/// Persistence port for idempotency keys.
///
/// The three methods are deliberately not one transaction: a middleware cannot
/// enlist in the handler's transaction, because the repository ports beneath it
/// are per-operation. That is the whole reason [`Claim::InFlight`] and the
/// lease exist — see `DEFAULT_LEASE`, and the module docs for the residual
/// window this leaves open.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Claim `key` for a request whose body hashes to `fingerprint`, or report
    /// what already stands there.
    ///
    /// Implementations must make the claim atomic against a concurrent caller:
    /// exactly one of two simultaneous first attempts may receive
    /// [`Claim::Claimed`].
    ///
    /// # Errors
    /// [`IdempotencyError::Unavailable`] if the store cannot be reached.
    async fn claim(
        &self,
        key: &RequestKey,
        fingerprint: &str,
        lease: Duration,
        retention: Duration,
    ) -> Result<Claim, IdempotencyError>;

    /// Record the outcome of a claimed request, making it replayable.
    ///
    /// # Errors
    /// [`IdempotencyError::Unavailable`] if the store cannot be reached.
    async fn complete(
        &self,
        key: &RequestKey,
        response: &StoredResponse,
    ) -> Result<(), IdempotencyError>;

    /// Release a claim without recording an outcome, so the same key may be
    /// tried again. Used when the handler failed in a way the client should be
    /// able to retry.
    ///
    /// # Errors
    /// [`IdempotencyError::Unavailable`] if the store cannot be reached.
    async fn release(&self, key: &RequestKey) -> Result<(), IdempotencyError>;

    /// Delete every key past its retention horizon. Returns how many went.
    ///
    /// # Errors
    /// [`IdempotencyError::Unavailable`] if the store cannot be reached.
    async fn purge_expired(&self) -> Result<u64, IdempotencyError>;
}

/// Hex SHA-256 of the raw request body bytes.
///
/// **Raw, not canonicalised.** Canonicalising the JSON would invent a
/// normalisation this API does not otherwise have, and a client that
/// re-serialises its body with different member order on retry has changed its
/// request — calling that "the same request" is a guess dressed as a
/// convenience. The API description states that retries must resend
/// byte-identical bodies.
#[must_use]
pub fn fingerprint(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_lowercase_hex_sha256() {
        let f = fingerprint(b"");
        assert_eq!(
            f,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // The migration pins the column to this shape; a digest that did not
        // match would be refused at the database rather than here.
        assert_eq!(f.len(), 64);
        assert!(
            f.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    /// The property the whole mismatch rule rests on: whitespace and member
    /// order are content, because the digest is over bytes.
    #[test]
    fn re_serialised_json_is_a_different_request() {
        assert_ne!(
            fingerprint(br#"{"a":1,"b":2}"#),
            fingerprint(br#"{"b":2,"a":1}"#)
        );
        assert_ne!(fingerprint(br#"{"a":1}"#), fingerprint(br#"{ "a": 1 }"#));
    }
}
