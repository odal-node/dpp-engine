//! Redis-backed response cache for the resolver.

use std::sync::Arc;

use anyhow::{Context, Result};
use deadpool_redis::{Config as RedisConfig, Pool, Runtime, redis::AsyncCommands};
use metrics;

/// Redis-backed response cache, keyed by resolver route + DPP id.
///
/// Cache misses and Redis errors are treated identically — the request falls
/// through to the vault. Write errors are logged and swallowed; the vault DB
/// is always the source of truth.
pub struct Cache {
    pool: Pool,
    ttl_secs: u64,
}

impl Cache {
    /// Connect to Redis and return a pooled cache handle.
    ///
    /// # Errors
    /// Returns an error if the pool cannot be created (bad URL format, etc.).
    /// Connection failures are deferred to first use.
    pub fn new(redis_url: &str, ttl_secs: u64) -> Result<Arc<Self>> {
        let cfg = RedisConfig::from_url(redis_url);
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .context("Failed to create Redis pool")?;
        Ok(Arc::new(Self { pool, ttl_secs }))
    }

    /// Get a cached value by key. Returns `None` if not found or on Redis error.
    pub async fn get(&self, key: &str) -> Option<String> {
        let mut conn = self.pool.get().await.ok()?;
        let result = conn.get::<_, Option<String>>(key).await.ok().flatten();
        let label = if result.is_some() { "hit" } else { "miss" };
        metrics::counter!("cache_requests_total", "result" => label).increment(1);
        result
    }

    /// Store a value with the configured TTL. Logs and swallows errors.
    pub async fn set(&self, key: &str, value: &str) {
        let Ok(mut conn) = self.pool.get().await else {
            tracing::warn!(key, "Redis pool exhausted, skipping cache set");
            return;
        };
        let ttl = self.ttl_secs;
        if let Err(e) = conn.set_ex::<_, _, ()>(key, value, ttl).await {
            tracing::warn!(key, error = %e, "Failed to set cache entry");
        }
    }

    /// No-op cache for unit tests — always misses on get, silently drops on set.
    ///
    /// Uses an unreachable Redis URL so the pool creation succeeds (lazy connections)
    /// but every connection attempt fails gracefully.
    ///
    /// Test-only helper; not part of the supported public API.
    #[doc(hidden)]
    pub fn new_noop() -> Arc<Self> {
        let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("noop pool");
        Arc::new(Self { pool, ttl_secs: 0 })
    }
}
