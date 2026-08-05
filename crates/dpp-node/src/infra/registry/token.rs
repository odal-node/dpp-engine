//! OAuth2 client-credentials token cache.

use std::time::{Duration, Instant};

use serde::Deserialize;

/// `Debug` is hand-written on both types below. A bearer token is a credential
/// for as long as it lives, and the token path is precisely where a failed
/// refresh gets debug-printed into an error context.
#[derive(Clone, Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    pub(super) expires_in: u64,
    #[allow(dead_code)]
    pub(super) token_type: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &dpp_common::config::REDACTED)
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

pub(super) struct CachedToken {
    pub(super) access_token: String,
    pub(super) expires_at: Instant,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &dpp_common::config::REDACTED)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CachedToken {
    pub(super) fn is_expired(&self) -> bool {
        // Refresh 30 seconds before actual expiry. Compare additively
        // (`now + 30s >= expires_at`) rather than subtracting from an `Instant`,
        // which panics on underflow when the token expires in under ~30s (a fresh
        // restart racing a short-lived token refresh).
        Instant::now() + Duration::from_secs(30) >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_immediate_expiry_reports_expired_without_panicking() {
        // Expiry within the 30s refresh window must not underflow-panic.
        let t = CachedToken {
            access_token: "x".into(),
            expires_at: Instant::now(),
        };
        assert!(t.is_expired());
    }

    #[test]
    fn far_future_token_is_not_expired() {
        let t = CachedToken {
            access_token: "x".into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        assert!(!t.is_expired());
    }

    #[test]
    fn debug_does_not_print_bearer_tokens() {
        let cached = CachedToken {
            access_token: "bearer-must-not-leak".into(),
            expires_at: Instant::now(),
        };
        let rendered = format!("{cached:?}");
        assert!(
            !rendered.contains("bearer-must-not-leak"),
            "CachedToken Debug leaked the token: {rendered}"
        );

        let response: TokenResponse = serde_json::from_str(
            r#"{"access_token":"response-must-not-leak","expires_in":3600,"token_type":"Bearer"}"#,
        )
        .expect("parses");
        let rendered = format!("{response:?}");
        assert!(
            !rendered.contains("response-must-not-leak"),
            "TokenResponse Debug leaked the token: {rendered}"
        );
        // Non-secret fields survive, so the type stays diagnosable.
        assert!(rendered.contains("3600"), "{rendered}");
    }
}
