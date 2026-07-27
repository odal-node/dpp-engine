//! Passport JWS verification against the operator's `did:web` document.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::Engine;
use dpp_common::event_codes;
use metrics;
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing;

use dpp_crypto::jws::verifier as jws;

/// How long a fetched operator DID document is trusted before being refetched.
///
/// The document only changes on key rotation — a rare, operator-initiated
/// event — so a multi-minute TTL trades a small propagation delay for
/// eliminating a fetch on nearly every verification. Before this cache, every
/// call to `verify_passport_jws` (3 of the 4 resolver routes, every
/// cache-miss resolution) issued a fresh HTTP GET for a document that is
/// identical across every `dpp_id` in this single-tenant deployment — the
/// single biggest avoidable request amplification on the public hot path.
const DID_DOC_CACHE_TTL: Duration = Duration::from_secs(300);

struct CachedDid {
    doc: Value,
    fetched_at: Instant,
}

/// Keyed by URL (not just a single slot) so the cache degrades safely if this
/// ever ran against more than one operator DID url — harmless overhead for
/// the common single-tenant case where there is exactly one key.
fn did_doc_cache() -> &'static RwLock<HashMap<String, CachedDid>> {
    static CACHE: OnceLock<RwLock<HashMap<String, CachedDid>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// One lock per URL, so concurrent cache misses for the *same* URL serialize
/// onto a single fetch instead of each issuing its own request. This is the
/// exact scenario a burst of public traffic for one passport produces: many
/// concurrent resolutions racing a cold or just-expired cache entry. Same
/// unbounded-growth tradeoff as `did_doc_cache` above — harmless for the
/// single-tenant common case of one key.
fn fetch_locks() -> &'static Mutex<HashMap<String, Arc<AsyncMutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Verify a published passport's **public** signature (`publicJwsSignature`)
/// against the operator's did:web document and return the verified public view.
///
/// The signature is over the canonical public (redacted) view, so the decoded
/// payload *is* the authoritative content — the resolver renders from it rather
/// than from the separately-served JSON, removing any need for content-binding.
///
/// **Fails closed.** Any missing/unreachable/invalid input is an error, never a
/// silent pass. Returns:
/// - `Ok(view)` — signature valid; `view` is the verified public passport (or
///   the served value verbatim when verification is disabled via an empty
///   `operator_did_url`, dev/test only).
/// - `Err(CONFLICT)` (409) — missing/invalid signature, or the proof's `id` does
///   not match the requested passport.
/// - `Err(SERVICE_UNAVAILABLE)` (503) — the operator DID document could not be
///   fetched/parsed, so the passport cannot be verified right now.
#[tracing::instrument(skip(http, passport))]
pub async fn verify_passport_jws(
    http: &reqwest::Client,
    operator_did_url: &str,
    passport: &Value,
) -> Result<Value, StatusCode> {
    // Verification explicitly disabled (dev/test only): trust the served view.
    if operator_did_url.is_empty() {
        metrics::counter!("jws_verify_total", "outcome" => "disabled").increment(1);
        return Ok(passport.clone());
    }

    // The public passport carries a JWS over its *public (redacted) view*
    // (`publicJwsSignature`). We verify it and render from the signed payload, so
    // there is nothing separately-served left to tamper.
    let jws = match passport
        .get("publicJwsSignature")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(j) => j,
        // A passport served by the resolver is published and MUST be signed.
        None => {
            metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
            tracing::warn!(
                code = event_codes::JWS_TAMPER,
                "published passport has no public signature — refusing to serve as valid"
            );
            return Err(StatusCode::CONFLICT);
        }
    };

    // Fetch the operator DID document; fail closed (503) on any transport/parse error.
    let did_doc = fetch_did(http, operator_did_url).await?;

    // Select the key by kid (fingerprint) so rotation-archived keys remain usable.
    // Fall back to the primary key for old kid-less JWS tokens.
    let pub_key = {
        let kid = jws::extract_kid_from_jws(jws);
        kid.as_deref()
            .and_then(|k| jws::extract_key_by_fingerprint(&did_doc, k))
            .or_else(|| jws::extract_primary_public_key(&did_doc))
            .ok_or_else(|| {
                tracing::warn!(
                    code = event_codes::DID_UNREACHABLE,
                    operator_did_url,
                    "operator DID has no matching verification key"
                );
                StatusCode::SERVICE_UNAVAILABLE
            })?
    };

    // 1) Signature must verify against the operator key.
    match jws::verify_jws(jws, &pub_key) {
        Ok(true) => {}
        Ok(false) => {
            metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
            tracing::warn!(
                code = event_codes::JWS_TAMPER,
                "JWS signature does not verify against the operator DID"
            );
            return Err(StatusCode::CONFLICT);
        }
        Err(e) => {
            metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
            tracing::warn!(
                code = event_codes::JWS_TAMPER,
                error = %e,
                "JWS verification error"
            );
            return Err(StatusCode::CONFLICT);
        }
    }

    // The signed public view is the authoritative content the resolver renders;
    // there is no separately-served payload to bind against.
    let signed = decode_jws_payload(jws).ok_or_else(|| {
        metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
        tracing::warn!(
            code = event_codes::JWS_TAMPER,
            "could not decode the public JWS payload"
        );
        StatusCode::CONFLICT
    })?;

    // Bind the proof to the requested passport: the signed view's id must match
    // the served passport's id (fetched by the requested id). Stops a valid proof
    // for one passport being replayed under another id.
    if signed.get("id") != passport.get("id") {
        metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
        tracing::warn!(
            code = event_codes::JWS_TAMPER,
            "signed public view id does not match the served passport id"
        );
        return Err(StatusCode::CONFLICT);
    }

    metrics::counter!("jws_verify_total", "outcome" => "ok").increment(1);
    Ok(signed)
}

async fn fetch_did(http: &reqwest::Client, url: &str) -> Result<Value, StatusCode> {
    if let Some(doc) = cached_did_doc(url).await {
        return Ok(doc);
    }

    // Serialize concurrent misses for this URL onto one fetch: whoever gets
    // here first does the real work; everyone else waits on the lock and then
    // finds the cache already warm, rather than each firing its own request.
    let lock = {
        let mut locks = fetch_locks().lock().expect("fetch lock map poisoned");
        locks
            .entry(url.to_owned())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    };
    let _guard = lock.lock().await;

    // A concurrent caller may have populated the cache while this one waited.
    if let Some(doc) = cached_did_doc(url).await {
        return Ok(doc);
    }

    let resp = http.get(url).send().await.map_err(|e| {
        tracing::warn!(code = event_codes::DID_UNREACHABLE, url, error = %e, "could not fetch operator DID document");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    if !resp.status().is_success() {
        tracing::warn!(code = event_codes::DID_UNREACHABLE, url, status = %resp.status(), "operator DID endpoint returned non-2xx");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let doc: Value = resp.json().await.map_err(|e| {
        tracing::warn!(code = event_codes::DID_UNREACHABLE, url, error = %e, "operator DID document is not valid JSON");
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    did_doc_cache().write().await.insert(
        url.to_owned(),
        CachedDid {
            doc: doc.clone(),
            fetched_at: Instant::now(),
        },
    );

    Ok(doc)
}

/// The cached document for `url`, if present and still within TTL — `None`
/// on a cold cache or an expired entry, either of which falls through to a
/// real fetch in the caller.
async fn cached_did_doc(url: &str) -> Option<Value> {
    let cache = did_doc_cache().read().await;
    let entry = cache.get(url)?;
    (entry.fetched_at.elapsed() < DID_DOC_CACHE_TTL).then(|| entry.doc.clone())
}

/// Decode the (already-verified) payload segment of a compact JWS into JSON.
fn decode_jws_payload(jws: &str) -> Option<Value> {
    let payload_b64 = jws.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Router, extract::State, routing::get};
    use dpp_common::event_codes::MUTABLE_FIELDS;

    use super::fetch_did;

    async fn spawn_counting_did_server(doc: serde_json::Value) -> (String, Arc<AtomicUsize>) {
        spawn_counting_did_server_with_delay(doc, std::time::Duration::ZERO).await
    }

    /// Same as `spawn_counting_did_server`, but holds each response for `delay`
    /// before answering — wide enough to make concurrent callers reliably
    /// overlap on a cold cache, for the coalescing regression below.
    async fn spawn_counting_did_server_with_delay(
        doc: serde_json::Value,
        delay: std::time::Duration,
    ) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_for_route = hits.clone();
        let app = Router::new().route(
            "/.well-known/did.json",
            get(move |State(doc): State<serde_json::Value>| {
                let hits = hits_for_route.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    axum::Json(doc)
                }
            }),
        );
        let app = app.with_state(doc);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock DID server");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock DID serve");
        });
        (
            format!("http://127.0.0.1:{port}/.well-known/did.json"),
            hits,
        )
    }

    /// Regression for the DID-caching fix: a second `fetch_did` call for the
    /// same URL within the TTL must be served from cache, not the network —
    /// before this, every call to `verify_passport_jws` refetched the
    /// document, even though it is identical across every `dpp_id` in a
    /// single-tenant deployment.
    #[tokio::test]
    async fn a_second_fetch_within_ttl_does_not_hit_the_network() {
        let doc = serde_json::json!({"id": "did:web:cache-test.example"});
        let (url, hits) = spawn_counting_did_server(doc.clone()).await;
        let http = reqwest::Client::new();

        let first = fetch_did(&http, &url).await.expect("first fetch");
        assert_eq!(first, doc);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let second = fetch_did(&http, &url).await.expect("second fetch");
        assert_eq!(second, doc, "cached value must match what was fetched");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a cache hit must not reach the network a second time"
        );
    }

    /// Regression for the cache-stampede fix: a burst of concurrent misses for
    /// the *same* URL (a cold cache under a traffic spike — exactly the case
    /// the cache exists to help with) must coalesce onto a single network
    /// fetch, not fire one request per concurrent caller. The mock server
    /// holds its response long enough that all five callers are guaranteed to
    /// race a still-empty cache before any of them completes.
    #[tokio::test]
    async fn concurrent_misses_for_the_same_url_coalesce_to_one_fetch() {
        let doc = serde_json::json!({"id": "did:web:stampede-test.example"});
        let (url, hits) =
            spawn_counting_did_server_with_delay(doc.clone(), std::time::Duration::from_millis(50))
                .await;
        let http = reqwest::Client::new();

        let (a, b, c, d, e) = tokio::join!(
            fetch_did(&http, &url),
            fetch_did(&http, &url),
            fetch_did(&http, &url),
            fetch_did(&http, &url),
            fetch_did(&http, &url),
        );
        for result in [a, b, c, d, e] {
            assert_eq!(result.expect("fetch should succeed"), doc);
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "5 concurrent misses for the same URL must coalesce to a single network fetch"
        );
    }

    /// Two different URLs must not collide in the cache — each is fetched
    /// and cached independently.
    #[tokio::test]
    async fn different_urls_are_cached_independently() {
        let doc_a = serde_json::json!({"id": "did:web:a.example"});
        let doc_b = serde_json::json!({"id": "did:web:b.example"});
        let (url_a, hits_a) = spawn_counting_did_server(doc_a.clone()).await;
        let (url_b, hits_b) = spawn_counting_did_server(doc_b.clone()).await;
        let http = reqwest::Client::new();

        assert_eq!(fetch_did(&http, &url_a).await.unwrap(), doc_a);
        assert_eq!(fetch_did(&http, &url_b).await.unwrap(), doc_b);
        assert_eq!(hits_a.load(Ordering::SeqCst), 1);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);
    }

    // ── DAL D2: MUTABLE_FIELDS parity guard ─────────────────────────────────

    /// `MUTABLE_FIELDS` must equal the DB retention trigger's `mutable_keys`
    /// array (`0004_passport.sql`, amended by `0011_public_jws_mutable.sql`
    /// and `0018_lint_result_mutable.sql`): the fields a retention-locked
    /// passport may still change. Machine-checks the DAL D2 invariant so the
    /// two cannot silently diverge.
    #[test]
    fn mutable_fields_matches_db_trigger_mutable_keys() {
        let expected: &[&str] = &[
            "status",
            "jwsSignature",
            "publicJwsSignature",
            "qrCodeUrl",
            "publishedAt",
            "retentionLocked",
            "updatedAt",
            "lintResult",
        ];
        let mut actual = MUTABLE_FIELDS.to_vec();
        let mut want = expected.to_vec();
        actual.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            actual, want,
            "MUTABLE_FIELDS in dpp-common must match the DB trigger's mutable_keys"
        );
    }
}
