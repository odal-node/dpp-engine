//! OAuth2 client-credentials token cache.

use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    pub(super) expires_in: u64,
    #[allow(dead_code)]
    pub(super) token_type: String,
}

#[derive(Debug)]
pub(super) struct CachedToken {
    pub(super) access_token: String,
    pub(super) expires_at: Instant,
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
}
