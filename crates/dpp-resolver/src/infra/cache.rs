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

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips against a real Redis when one is reachable, and skips when
    /// it is not. This crate has no container harness, and adding one for a
    /// 68-line adapter is not worth a new dev-dependency in every build.
    ///
    /// It exists because the `redis`/`deadpool-redis` pair is the only
    /// production dependency here that a version bump can break *silently*:
    /// `Config::from_url`, `pool.get()` and the `AsyncCommands` methods all
    /// keep compiling across majors while their behaviour moves underneath,
    /// and `set` swallows its errors by design. Run it after bumping either:
    ///
    /// ```text
    /// docker run -d --rm -p 6379:6379 redis:7-alpine
    /// REDIS_URL=redis://127.0.0.1:6379 cargo test -p dpp-resolver cache::
    /// ```
    ///
    /// Reachability is probed rather than inferred from `REDIS_URL` being set:
    /// `.env` ships a `REDIS_URL` and the justfile has `set dotenv-load`, so
    /// under `just check` the variable is always present whether or not a
    /// server is listening. Skipping on an unset variable alone would fail the
    /// gate for every developer who followed the setup guide without starting
    /// Redis. Once a connection *is* established, the round-trip must hold —
    /// that is the regression this guards.
    #[tokio::test]
    async fn round_trips_through_a_real_redis() {
        // Skips silently rather than announcing it: the debug-print tripwire
        // bans stdout/stderr macros anywhere under a service crate's src/, and
        // this test lives inline rather than in tests/.
        let Ok(url) = std::env::var("REDIS_URL") else {
            return;
        };
        let cache = Cache::new(&url, 60).expect("pool");
        let Ok(mut probe) = cache.pool.get().await else {
            return; // nothing listening — not a failure of this adapter
        };
        if deadpool_redis::redis::cmd("PING")
            .query_async::<String>(&mut probe)
            .await
            .is_err()
        {
            return;
        }
        drop(probe);

        let key = format!("odal:test:{}", uuid::Uuid::now_v7());
        assert_eq!(cache.get(&key).await, None, "unset key must miss");
        cache.set(&key, "cached-body").await;
        assert_eq!(
            cache.get(&key).await,
            Some("cached-body".to_owned()),
            "value set through the pool must read back"
        );
    }

    /// The no-op handle points at an unreachable port: every call must fall
    /// through to a miss rather than error, because the resolver treats cache
    /// failure and cache miss identically and the vault stays authoritative.
    #[tokio::test]
    async fn unreachable_redis_degrades_to_a_miss() {
        let cache = Cache::new_noop();
        assert_eq!(cache.get("anything").await, None);
        cache.set("anything", "value").await; // must not panic
    }
}
