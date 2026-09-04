//! An [`AuditRepository`] decorator that stamps the ambient request id.
//!
//! # Why a decorator and not eleven call sites
//!
//! `PassportAuditEntry` is constructed in eleven places across the service
//! layer — create, publish, the four lifecycle transitions, EOL, the three
//! transfer legs, and the credentialed read. Stamping the id at each of them
//! means eleven identical lines, and a twelfth call site added later silently
//! writes `NULL` with nothing to catch it.
//!
//! Every one of those paths funnels through [`AuditRepository::append`], so
//! wrapping the port stamps all of them at once and cannot be forgotten. The
//! service layer keeps its signatures, and the composition root is the only
//! place that knows this exists.
//!
//! # Why it lives in `dpp-vault`
//!
//! It needs `dpp-types` (the port) and `dpp-common` (the task-local), and the
//! documented dependency direction has `dpp-common` consumed by `dpp-vault` and
//! `dpp-node` only — `dpp-dal`, the other obvious home, may not reach it. See
//! `CLAUDE.md`, "Dependency direction".

use std::sync::Arc;

use async_trait::async_trait;
use dpp_domain::DppError;
use dpp_types::audit::{AuditRepository, PassportAuditEntry};

/// Wraps an [`AuditRepository`], stamping each entry with the `x-request-id` of
/// the request being served before handing it to the inner repository.
///
/// An entry written outside a request — a background sweep, or a service called
/// directly from a test — is passed through unstamped. That is the honest
/// answer: there was no request, so there is no id, and a synthesised one would
/// correlate to nothing.
pub struct RequestStampedAudit {
    inner: Arc<dyn AuditRepository>,
}

impl RequestStampedAudit {
    /// Wrap `inner` so every appended entry carries the ambient request id.
    #[must_use]
    pub fn new(inner: Arc<dyn AuditRepository>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl AuditRepository for RequestStampedAudit {
    async fn append(&self, entry: PassportAuditEntry) -> Result<(), DppError> {
        self.inner
            .append(entry.with_request_id(dpp_common::request_id::current()))
            .await
    }

    async fn list_by_passport(
        &self,
        passport_id: &str,
    ) -> Result<Vec<PassportAuditEntry>, DppError> {
        self.inner.list_by_passport(passport_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Captures what reached the inner repository.
    #[derive(Default)]
    struct Spy(Mutex<Vec<PassportAuditEntry>>);

    #[async_trait]
    impl AuditRepository for Spy {
        async fn append(&self, entry: PassportAuditEntry) -> Result<(), DppError> {
            self.0.lock().unwrap().push(entry);
            Ok(())
        }
        async fn list_by_passport(&self, _: &str) -> Result<Vec<PassportAuditEntry>, DppError> {
            Ok(Vec::new())
        }
    }

    fn entry() -> PassportAuditEntry {
        PassportAuditEntry::new("p1", "created", "actor", None, Some("draft"))
    }

    #[tokio::test]
    async fn an_entry_written_outside_a_request_is_left_unstamped() {
        let spy = Arc::new(Spy::default());
        RequestStampedAudit::new(spy.clone())
            .append(entry())
            .await
            .unwrap();

        assert_eq!(spy.0.lock().unwrap()[0].request_id, None);
    }

    /// The behaviour the decorator exists for. Driven through the real
    /// middleware rather than by setting the task-local here, so the test fails
    /// if the middleware stops scoping it.
    #[tokio::test]
    async fn an_entry_written_during_a_request_carries_its_id() {
        use axum::{Router, body::Body, http::Request, routing::post};
        use tower::ServiceExt;

        let spy = Arc::new(Spy::default());
        let stamped = Arc::new(RequestStampedAudit::new(spy.clone()));

        let app = Router::new()
            .route(
                "/",
                post(move || {
                    let stamped = stamped.clone();
                    async move {
                        stamped.append(entry()).await.unwrap();
                        "ok"
                    }
                }),
            )
            // Same three layers, in the same order, as `router::build` — the
            // propagate layer is what puts the id on the *response*, and
            // without it the assertion below would compare against nothing.
            .layer(axum::middleware::from_fn(
                dpp_common::request_id::inject_request_id,
            ))
            .layer(tower_http::request_id::PropagateRequestIdLayer::x_request_id())
            .layer(tower_http::request_id::SetRequestIdLayer::x_request_id(
                dpp_common::request_id::UuidRequestId,
            ));

        let response = app
            .oneshot(Request::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let header = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let stamped_id = spy.0.lock().unwrap()[0].request_id.clone();
        assert!(stamped_id.is_some(), "the entry must carry an id");
        // Same id the caller was told to quote in a support conversation —
        // correlating the two is the entire point of the column.
        assert_eq!(stamped_id, header);
    }
}
