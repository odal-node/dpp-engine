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
        // Refresh 30 seconds before actual expiry to avoid edge-case failures.
        Instant::now() >= self.expires_at - Duration::from_secs(30)
    }
}
