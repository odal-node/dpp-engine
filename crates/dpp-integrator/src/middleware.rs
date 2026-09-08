//! Binds `dpp-common`'s idempotency middleware to this service's notion of a
//! caller.
//!
//! # Why this differs from the vault's binding
//!
//! The integrator does not authenticate at the router. Its handlers forward the
//! caller's `Bearer` token to the vault and let *that* resolve it, so there is
//! no `AuthContext` in the request extensions to read a `user_id` out of.
//!
//! The principal is therefore derived from the token itself. A truncated
//! SHA-256, never the token: the value becomes a primary-key column, and a
//! bearer credential in plaintext in a table is exactly the disclosure the
//! secret-redaction rule elsewhere in this feature exists to prevent. The
//! digest is stable for the life of a key, which is all the scoping needs.
//!
//! Two consequences worth stating rather than discovering. Rotating an API key
//! changes the principal, so an in-flight retry across a rotation will
//! re-execute — correct, if surprising: it is a different credential. And the
//! same caller has a different principal here than in the vault, which is
//! harmless because keys are scoped by route as well.

use std::sync::Arc;

use dpp_common::idempotency::{IdempotencyLayerState, IdempotencyStore};

/// Build the middleware state, deriving the principal from the caller's bearer
/// token.
///
/// Returns `None` as the principal for a request with no usable
/// `Authorization` header, which the middleware turns into a refusal rather
/// than a key scoped to nobody.
#[must_use]
pub fn idempotency_state(store: Arc<dyn IdempotencyStore>) -> IdempotencyLayerState {
    IdempotencyLayerState {
        store,
        principal: Arc::new(|request| {
            request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(bearer_principal)
        }),
    }
}

/// `bearer:<first 32 hex of SHA-256(token)>`.
///
/// Truncated because the full digest buys nothing here — this is a scoping
/// label, not a credential check — and 128 bits is far past any collision
/// concern for the number of API keys one node has.
fn bearer_principal(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    format!("bearer:{}", &digest[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request};

    fn principal_of(request: &Request) -> Option<String> {
        (idempotency_state(Arc::new(NoStore)).principal)(request)
    }

    struct NoStore;

    #[async_trait::async_trait]
    impl IdempotencyStore for NoStore {
        async fn claim(
            &self,
            _: &dpp_common::idempotency::RequestKey,
            _: &str,
            _: std::time::Duration,
            _: std::time::Duration,
        ) -> Result<dpp_common::idempotency::Claim, dpp_common::idempotency::IdempotencyError>
        {
            unreachable!("this suite only exercises principal resolution")
        }
        async fn complete(
            &self,
            _: &dpp_common::idempotency::RequestKey,
            _: &dpp_common::idempotency::StoredResponse,
        ) -> Result<(), dpp_common::idempotency::IdempotencyError> {
            unreachable!()
        }
        async fn release(
            &self,
            _: &dpp_common::idempotency::RequestKey,
        ) -> Result<(), dpp_common::idempotency::IdempotencyError> {
            unreachable!()
        }
        async fn purge_expired(&self) -> Result<u64, dpp_common::idempotency::IdempotencyError> {
            unreachable!()
        }
    }

    #[test]
    fn the_token_never_appears_in_the_principal() {
        let token = "odal_ab_averysecrettokenvalue";
        let principal = bearer_principal(token);
        assert!(principal.starts_with("bearer:"));
        assert!(
            !principal.contains("averysecrettoken"),
            "the principal is stored as a primary key; it must not carry the credential"
        );
        assert_eq!(principal.len(), "bearer:".len() + 32);
    }

    #[test]
    fn the_same_token_always_gives_the_same_principal() {
        assert_eq!(bearer_principal("t"), bearer_principal("t"));
        assert_ne!(bearer_principal("t"), bearer_principal("u"));
    }

    #[test]
    fn a_bearer_token_resolves_and_anything_else_does_not() {
        let with = Request::post("/")
            .header("authorization", "Bearer odal_ab_token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            principal_of(&with).as_deref(),
            Some(bearer_principal("odal_ab_token").as_str())
        );

        let without = Request::post("/").body(Body::empty()).unwrap();
        assert_eq!(principal_of(&without), None);

        // Basic auth is not a bearer token, and guessing at one would key the
        // request to a principal the vault would never agree with.
        let basic = Request::post("/")
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(principal_of(&basic), None);

        let empty = Request::post("/")
            .header("authorization", "Bearer   ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(principal_of(&empty), None);
    }
}
