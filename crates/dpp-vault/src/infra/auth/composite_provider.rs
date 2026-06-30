//! `CompositeAuthProvider` — chains multiple providers; first success or `Suspended` wins.

use async_trait::async_trait;
use tracing;

use dpp_types::auth::{AuthContext, AuthError, AuthProvider};

/// Auth provider that delegates to an ordered list of inner providers.
///
/// Returns the first `Ok(AuthContext)` or short-circuits immediately on
/// `AuthError::Suspended` (operator blocked — never let another provider override
/// a suspension). If all providers fail, returns the last error.
pub struct CompositeAuthProvider {
    providers: Vec<Box<dyn AuthProvider>>,
}

impl CompositeAuthProvider {
    /// Construct with an ordered list of providers tried in sequence.
    pub fn new(providers: Vec<Box<dyn AuthProvider>>) -> Self {
        Self { providers }
    }
}

#[async_trait]
impl AuthProvider for CompositeAuthProvider {
    #[tracing::instrument(skip(self, token))]
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let mut last_err = AuthError::Missing;
        for provider in &self.providers {
            match provider.authenticate(token).await {
                Ok(ctx) => return Ok(ctx),
                Err(AuthError::Suspended) => return Err(AuthError::Suspended),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysOk;
    struct AlwaysFail;
    struct AlwaysSuspended;

    #[async_trait::async_trait]
    impl AuthProvider for AlwaysOk {
        async fn authenticate(&self, _: &str) -> Result<AuthContext, AuthError> {
            Ok(AuthContext {
                user_id: "u1".into(),
                scope: Default::default(),
                key_id: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl AuthProvider for AlwaysFail {
        async fn authenticate(&self, _: &str) -> Result<AuthContext, AuthError> {
            Err(AuthError::Invalid("nope".into()))
        }
    }

    #[async_trait::async_trait]
    impl AuthProvider for AlwaysSuspended {
        async fn authenticate(&self, _: &str) -> Result<AuthContext, AuthError> {
            Err(AuthError::Suspended)
        }
    }

    #[tokio::test]
    async fn first_provider_success_short_circuits() {
        let c = CompositeAuthProvider::new(vec![Box::new(AlwaysOk), Box::new(AlwaysFail)]);
        let ctx = c.authenticate("x").await.unwrap();
        assert_eq!(ctx.user_id, "u1");
    }

    #[tokio::test]
    async fn first_fails_second_succeeds() {
        let c = CompositeAuthProvider::new(vec![Box::new(AlwaysFail), Box::new(AlwaysOk)]);
        assert!(c.authenticate("x").await.is_ok());
    }

    #[tokio::test]
    async fn all_fail_returns_last_error() {
        let c = CompositeAuthProvider::new(vec![Box::new(AlwaysFail), Box::new(AlwaysFail)]);
        assert!(matches!(
            c.authenticate("x").await,
            Err(AuthError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn suspended_propagates_immediately() {
        let c = CompositeAuthProvider::new(vec![Box::new(AlwaysSuspended), Box::new(AlwaysOk)]);
        assert!(matches!(
            c.authenticate("x").await,
            Err(AuthError::Suspended)
        ));
    }

    #[tokio::test]
    async fn empty_providers_returns_missing() {
        let c = CompositeAuthProvider::new(vec![]);
        assert!(matches!(c.authenticate("x").await, Err(AuthError::Missing)));
    }
}
