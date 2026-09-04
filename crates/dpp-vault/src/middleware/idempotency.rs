//! Binds `dpp-common`'s idempotency middleware to this service's notion of a
//! caller.
//!
//! The middleware itself is generic because two crates mount keyed routes and
//! neither knows the other's auth model. All this supplies is the one thing it
//! cannot know: how to name the principal a key is scoped to.

use std::sync::Arc;

use dpp_common::idempotency::{IdempotencyLayerState, IdempotencyStore};

use crate::middleware::auth::AuthContext;

/// Build the middleware state, resolving the principal from the `AuthContext`
/// that `auth_middleware` inserted into the request.
///
/// Reading the extension rather than re-parsing the `Authorization` header is
/// deliberate: it makes the layer ordering load-bearing and visible. If this
/// ever runs before auth, the extension is absent, the middleware refuses the
/// request rather than silently keying it to nobody, and the mistake surfaces
/// on the first keyed call instead of as a cross-caller key collision later.
///
/// `user_id`, not the key id: a caller that rotates its API key mid-retry is
/// the same caller, and its retry must still find its own key. Single-tenant,
/// so there is no operator to fold in — see ADR-005.
#[must_use]
pub fn idempotency_state(store: Arc<dyn IdempotencyStore>) -> IdempotencyLayerState {
    IdempotencyLayerState {
        store,
        principal: Arc::new(|request| {
            request
                .extensions()
                .get::<AuthContext>()
                .map(|ctx| ctx.user_id.clone())
        }),
    }
}

/// The principal for the internal, certificate-gated tree.
///
/// A constant, not something read off the request. The route is wrapped by
/// `scan_ingest_mtls`, which has already refused anything not presenting
/// `CN=odal-resolver` from the internal CA — so by the time this runs the
/// caller's identity is settled, and there is exactly one of them.
///
/// Deriving it from a header instead would be strictly worse: it would let a
/// value the gate does not check decide which key namespace a request lands in.
pub const RESOLVER_PRINCIPAL: &str = "mtls:odal-resolver";

/// Build the middleware state for the internal scan-ingest route.
#[must_use]
pub fn resolver_idempotency_state(store: Arc<dyn IdempotencyStore>) -> IdempotencyLayerState {
    IdempotencyLayerState {
        store,
        principal: Arc::new(|_| Some(RESOLVER_PRINCIPAL.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request};
    use dpp_types::api_key::ApiKeyScope;

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
    fn the_principal_is_the_authenticated_user_id() {
        let state = idempotency_state(Arc::new(NoStore));
        let mut request = Request::post("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(AuthContext {
            user_id: "operator@example.com".into(),
            scope: ApiKeyScope::default(),
            key_id: Some(uuid::Uuid::now_v7()),
        });

        assert_eq!(
            (state.principal)(&request).as_deref(),
            Some("operator@example.com")
        );
    }

    /// The ordering guard. An unauthenticated request yields no principal, and
    /// the middleware turns that into a refusal — never a key scoped to nobody.
    #[test]
    fn an_unauthenticated_request_has_no_principal() {
        let state = idempotency_state(Arc::new(NoStore));
        let request = Request::post("/").body(Body::empty()).unwrap();
        assert_eq!((state.principal)(&request), None);
    }
}
