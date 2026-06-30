//! Entry point for the standalone `dpp-resolver` binary.
//!
//! Sets up per-IP rate limiting, Redis cache, Prometheus metrics, and the
//! Axum router, then binds and serves on `0.0.0.0:{PORT}`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};

use dpp_resolver::{config::Config, infra::cache::Cache, router, state::AppState};

/// Minimal per-IP fixed-window rate limiter for the public resolver. Lives in
/// the native binary only (the WASM/edge target relies on the edge platform's
/// own rate limiting), so the shared router and `AppState` stay untouched.
/// Hard cap on the number of per-IP buckets. Spoofed `X-Forwarded-For` floods
/// produce a fresh, never-expiring bucket per request; the expiry-only `retain`
/// can't bound that, so once the map exceeds this size it is cleared outright to
/// keep memory bounded regardless of input.
const MAX_BUCKETS: usize = 50_000;

struct RateLimiter {
    max: u32,
    window: Duration,
    /// Whether to trust the `X-Forwarded-For` header (only safe behind a proxy
    /// that sets it and strips inbound copies). Off by default.
    trust_forwarded_for: bool,
    buckets: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    fn new(max: u32, window: Duration, trust_forwarded_for: bool) -> Self {
        Self {
            max,
            window,
            trust_forwarded_for,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request from `ip` is within the limit.
    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        // Bound memory: drop expired buckets once the map grows large.
        if buckets.len() > 10_000 {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        // Hard cap: under a flood of fresh (spoofed) IPs none are expired, so the
        // expiry retain above can't shrink the map. Clear it to stay bounded.
        if buckets.len() > MAX_BUCKETS {
            buckets.clear();
        }
        let entry = buckets.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

fn client_ip(req: &Request, trust_forwarded_for: bool) -> IpAddr {
    // Only honour `X-Forwarded-For` when explicitly enabled (the resolver binds
    // 0.0.0.0 and may be directly reachable; an attacker can otherwise rotate the
    // header to mint a fresh bucket per request and bypass the limiter).
    if trust_forwarded_for
        && let Some(first) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return first;
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

async fn rate_limit_mw(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    // Never rate-limit health/readiness probes.
    let path = req.uri().path();
    if path == "/health" || path == "/ready" {
        return next.run(req).await;
    }
    if !limiter.check(client_ip(&req, limiter.trust_forwarded_for)) {
        metrics::counter!("rate_limit_rejections_total").increment(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "rate limit exceeded",
        )
            .into_response();
    }
    next.run(req).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = Config::from_env().context("Failed to load configuration")?;

    fmt().with_env_filter(EnvFilter::new(&cfg.log_level)).init();

    // Install the Prometheus recorder so the resolver's own counters
    // (`jws_verify_total`, `cache_requests_total`, …) are actually collected.
    // Without this they are silent no-ops — the public-facing tamper signal would
    // be lost (RT2-6). Served on a dedicated private listener (RT2-7).
    let prometheus_handle = std::sync::Arc::new(
        PrometheusBuilder::new()
            .install_recorder()
            .context("Failed to install Prometheus metrics recorder")?,
    );
    spawn_metrics_server(cfg.metrics_addr.clone(), prometheus_handle);

    tracing::info!(redis_url = %redact_url_credentials(&cfg.redis_url), "connecting to Redis");

    let cache =
        Cache::new(&cfg.redis_url, cfg.cache_ttl_secs).context("Failed to create Redis pool")?;

    // N-5: SSRF hardening. The DID-fetch target is operator-config-bound today,
    // but disabling redirect-following means even a future change that lets
    // passport data influence the DID URL — or a malicious operator DID host —
    // cannot bounce the resolver into an internal service via a 30x redirect.
    // (Private-IP blocking is deliberately NOT applied: the self-hosted/dev model
    // legitimately resolves the vault and DID over localhost.)
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")?;

    let vault_base_url =
        std::env::var("VAULT_BASE_URL").unwrap_or_else(|_| "http://vault:8001".into());

    // The operator's did:web document (the signer's public key). Defaults to the
    // identity service co-located with the vault: `<host>/identity/.well-known/did.json`.
    let operator_did_url = std::env::var("OPERATOR_DID_URL").unwrap_or_else(|_| {
        let host = vault_base_url
            .strip_suffix("/vault")
            .unwrap_or(&vault_base_url);
        format!("{host}/identity/.well-known/did.json")
    });
    tracing::info!(
        operator_did_url,
        "verifying passport signatures against operator DID"
    );

    let state = AppState {
        vault_base_url,
        operator_did_url,
        cache,
        http,
    };

    // Per-IP rate limit (default 120 requests/minute; override with RATE_LIMIT_RPM).
    let rpm: u32 = std::env::var("RATE_LIMIT_RPM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    // Only trust X-Forwarded-For when running behind a known proxy that sets and
    // sanitises it. Off by default — the resolver binds 0.0.0.0 and may be
    // directly reachable, where the header is fully attacker-controlled.
    let trust_forwarded_for = std::env::var("TRUST_FORWARDED_FOR")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    let limiter = Arc::new(RateLimiter::new(
        rpm,
        Duration::from_secs(60),
        trust_forwarded_for,
    ));
    tracing::info!(
        rpm,
        trust_forwarded_for,
        "resolver rate limit (requests/min per IP)"
    );

    let app =
        router::build(state).layer(axum::middleware::from_fn_with_state(limiter, rate_limit_mw));
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;

    tracing::info!(addr, "dpp-resolver listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("Server error")?;

    Ok(())
}

/// Strip embedded credentials from a connection URL before logging.
/// `redis://:s3cr3t@host:6379` → `redis://host:6379`
fn redact_url_credentials(url: &str) -> String {
    if let Some(at_pos) = url.rfind('@') {
        let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
        return format!("{}{}", &url[..scheme_end], &url[at_pos + 1..]);
    }
    url.to_owned()
}

/// Spawn the Prometheus `/metrics` server on a dedicated private listener.
/// A bind/serve failure is logged but never takes the resolver down; `None` disables.
fn spawn_metrics_server(addr: Option<String>, handle: Arc<PrometheusHandle>) {
    match addr {
        Some(addr) => {
            tokio::spawn(async move {
                if let Err(e) = serve_metrics(&addr, handle).await {
                    tracing::error!(error = %e, "metrics server stopped");
                }
            });
        }
        None => tracing::info!("metrics endpoint disabled (METRICS_ADDR empty)"),
    }
}

async fn serve_metrics(addr: &str, handle: Arc<PrometheusHandle>) -> anyhow::Result<()> {
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let h = handle.clone();
            async move { h.render() }
        }),
    );
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("metrics: failed to bind {addr}"))?;
    tracing::info!(addr, "metrics endpoint listening (private)");
    axum::serve(listener, app)
        .await
        .context("metrics server error")?;
    Ok(())
}

#[cfg(test)]
mod security_regression {
    //! **RT2-3**: the resolver rate limiter must not be bypassable, nor grow
    //! memory without bound, via a rotating/spoofed `X-Forwarded-For` header.
    use super::*;
    use axum::body::Body;

    fn req_with_xff(xff: &str, socket: SocketAddr) -> Request {
        let mut req = Request::builder()
            .uri("/dpp/x")
            .header("x-forwarded-for", xff)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(socket));
        req
    }

    #[test]
    fn xff_ignored_when_not_trusted() {
        let socket: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let req = req_with_xff("10.0.0.1", socket);
        // Default (untrusted): the spoofed header is ignored, socket IP wins.
        assert_eq!(client_ip(&req, false), socket.ip());
    }

    #[test]
    fn xff_honoured_when_trusted() {
        let socket: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let req = req_with_xff("10.0.0.1", socket);
        assert_eq!(client_ip(&req, true), "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn bucket_map_stays_bounded_under_fresh_ip_flood() {
        // A flood of distinct, never-expiring IPs must not grow the map without
        // bound; the hard cap clears it well before it can exhaust memory.
        let limiter = RateLimiter::new(1, Duration::from_secs(3600), false);
        for i in 0u32..(MAX_BUCKETS as u32 + 5_000) {
            let ip = IpAddr::from((0x0a00_0000u32 + i).to_be_bytes());
            limiter.check(ip);
        }
        let len = limiter.buckets.lock().unwrap().len();
        assert!(
            len <= MAX_BUCKETS,
            "bucket map grew to {len}, cap {MAX_BUCKETS}"
        );
    }
}
