//! In-memory scan/QR-render accumulator and its periodic flush to the node.
//!
//! The resolver has no database — keeping it stateless is what lets it target an
//! edge runtime. So scan counts live in RAM: each successful resolution bumps a
//! `(dpp_id, day, variant)` counter; the QR-image endpoint bumps a separate
//! `(dpp_id, day)` counter. A background task drains the maps every interval and
//! POSTs the aggregate to the node's internal, mTLS-gated ingest endpoint.
//!
//! Loss model: a crash loses at most the un-flushed window, which only ever
//! *under*-counts — the safe direction for a number an operator may cite. A
//! transient flush failure is not a loss either: the batch is held and re-sent.
//!
//! # Why a failed window is held rather than folded back in
//!
//! It used to be folded back into the live counters (`merge_back`), and that
//! double-counted. The ingest is additive —
//! `count = odal.scan_telemetry.count + EXCLUDED.count` — so a request the node
//! **committed** whose response was then lost (a read timeout, a `5xx` from
//! anything in front of it) came back on the next tick and was added again.
//! The old code reasoned about the transaction being atomic, which it is, and
//! not about the acknowledgement being lost, which is the case that matters.
//!
//! Folding back also made the window un-identifiable: the next drain produced a
//! *superset* of the failed one, so no key minted at drain time could describe
//! two consecutive attempts, and nothing downstream could recognise the resend.
//!
//! So a failed batch is held verbatim under a stable id and re-sent byte for
//! byte as an `Idempotency-Key`, while new counts accumulate for a later batch.
//! At most one batch is ever held, because a new one is not drained until the
//! held one is resolved — so this bounds memory as well as fixing the count.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{NaiveDate, Utc};
use uuid::Uuid;

use dpp_common::scan::{QrRenderBatchEntry, ScanBatch, ScanBatchEntry, ScanVariant};

/// Cap on distinct keys held per map, so a stuck ingest endpoint or a flood of
/// distinct `dpp_id`s can't grow the resolver's memory without bound. Once at
/// capacity, increments to keys not already tracked are dropped (existing keys
/// keep counting) — an undercount, the safe direction for this number.
const MAX_TRACKED_KEYS: usize = 50_000;

/// A drained batch and the key that identifies it across attempts.
///
/// The id never appears in the payload — it travels as the `Idempotency-Key`
/// header — so re-sending is byte-identical, which is what the node's
/// fingerprint check requires.
#[derive(Clone, Debug)]
pub struct KeyedBatch {
    /// Stable across every attempt at this exact batch.
    pub id: Uuid,
    /// The counts, in the order they were drained. Re-serialising the same
    /// value yields the same bytes, which is why the batch is held as a value
    /// rather than re-drained.
    pub batch: ScanBatch,
}

/// Thread-safe accumulator of aggregate scan and QR-render counts.
#[derive(Default)]
pub struct ScanCounter {
    scans: Mutex<HashMap<(String, NaiveDate, ScanVariant), u64>>,
    qr_renders: Mutex<HashMap<(String, NaiveDate), u64>>,
    /// The one batch awaiting a confirmed delivery, if any. New counts keep
    /// landing in the maps above meanwhile; nothing new is drained until this
    /// is resolved, which is what caps the hold at one batch.
    pending: Mutex<Option<KeyedBatch>>,
}

/// Increment `key`'s count in `map`. If `key` is new and `map` is already at
/// [`MAX_TRACKED_KEYS`], the increment is dropped and a warning logged instead
/// of growing the map further; an existing key keeps counting regardless.
fn bump<K: std::hash::Hash + Eq + std::fmt::Debug>(map: &mut HashMap<K, u64>, key: K) {
    if let Some(count) = map.get_mut(&key) {
        *count += 1;
    } else if map.len() < MAX_TRACKED_KEYS {
        map.insert(key, 1);
    } else {
        tracing::warn!(
            ?key,
            "scan counter at capacity ({MAX_TRACKED_KEYS} keys) — dropping increment for new key"
        );
    }
}

impl ScanCounter {
    /// Record one successful terminal-view resolution of `dpp_id`.
    pub fn record_scan(&self, dpp_id: &str, variant: ScanVariant) {
        let day = Utc::now().date_naive();
        let mut m = self.scans.lock().unwrap();
        bump(&mut m, (dpp_id.to_owned(), day, variant));
    }

    /// Record one successful QR-image render for `dpp_id` (label production).
    pub fn record_qr_render(&self, dpp_id: &str) {
        let day = Utc::now().date_naive();
        let mut m = self.qr_renders.lock().unwrap();
        bump(&mut m, (dpp_id.to_owned(), day));
    }

    /// Take everything accumulated so far, leaving the maps empty.
    pub fn drain(&self) -> ScanBatch {
        let scans = std::mem::take(&mut *self.scans.lock().unwrap());
        let qr_renders = std::mem::take(&mut *self.qr_renders.lock().unwrap());
        ScanBatch {
            scans: scans
                .into_iter()
                .map(|((dpp_id, day, variant), count)| ScanBatchEntry {
                    dpp_id,
                    day,
                    variant,
                    count,
                })
                .collect(),
            qr_renders: qr_renders
                .into_iter()
                .map(|((dpp_id, day), count)| QrRenderBatchEntry { dpp_id, day, count })
                .collect(),
        }
    }

    /// The batch to send now: the one still awaiting confirmation if there is
    /// one, otherwise a freshly drained window under a new id.
    ///
    /// Re-sending the held batch takes priority over draining a new one. Two
    /// reasons: the held one may already have been applied, so it must go back
    /// under its own id to be recognised as a resend; and not draining while
    /// one is outstanding is what keeps the hold at a single batch.
    pub fn next_flush(&self) -> KeyedBatch {
        if let Some(held) = self.pending.lock().unwrap().clone() {
            return held;
        }
        KeyedBatch {
            id: Uuid::now_v7(),
            batch: self.drain(),
        }
    }

    /// Hold `batch` for the next tick after a flush that may or may not have
    /// been applied.
    pub fn hold(&self, batch: KeyedBatch) {
        *self.pending.lock().unwrap() = Some(batch);
    }

    /// Forget the held batch — it was confirmed, or permanently rejected.
    pub fn clear_pending(&self) {
        *self.pending.lock().unwrap() = None;
    }

    /// Whether a batch is awaiting confirmation. Diagnostics and tests only.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }
}

/// Send one batch to the node's internal ingest endpoint: the batch still
/// awaiting confirmation if there is one, otherwise a freshly drained window.
///
/// The batch's id travels as `Idempotency-Key`, so a re-send of a request the
/// node already applied is recognised and answered from its record rather than
/// added a second time. That is the whole fix — see the module docs for what
/// the previous fold-back did.
///
/// A transient failure (`5xx`, or the request itself failing) holds the batch
/// for the next tick; a `4xx` is a permanent rejection and is dropped rather
/// than retried forever. An empty window is a no-op.
///
/// Broken out from the loop so it is testable against a mock ingest server
/// without waiting on a timer.
async fn flush_once(counter: &ScanCounter, client: &reqwest::Client, ingest_url: &str) {
    let keyed = counter.next_flush();
    if keyed.batch.is_empty() {
        // Nothing to say. A held batch is never empty, so this can only be a
        // fresh drain of an idle window, and there is nothing to clear.
        return;
    }

    let result = client
        .post(ingest_url)
        .header(
            dpp_common::idempotency::IDEMPOTENCY_KEY_HEADER,
            keyed.id.to_string(),
        )
        .json(&keyed.batch)
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => counter.clear_pending(),
        Ok(resp) if resp.status().is_client_error() => {
            // A 4xx means the vault permanently rejected this payload (bad
            // shape, wrong CN, ...) — re-sending it would never succeed, so
            // holding it would just poison every future flush.
            //
            // `409` is the exception and must not be dropped: it means an
            // earlier attempt at *this* batch is still being processed, which
            // is a transient state and precisely the case the key exists for.
            if resp.status() == reqwest::StatusCode::CONFLICT {
                tracing::debug!("scan flush is already in flight at the node — holding");
                counter.hold(keyed);
                return;
            }
            tracing::error!(
                status = %resp.status(),
                "scan flush rejected as invalid — dropping window, not retrying"
            );
            counter.clear_pending();
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "scan flush rejected — holding for retry");
            counter.hold(keyed);
        }
        Err(e) => {
            // The ambiguous case, and the reason for all of this: the node may
            // have committed this batch and the acknowledgement been lost. The
            // key is what makes re-sending safe.
            tracing::warn!(error = %e, "scan flush failed — holding for retry");
            counter.hold(keyed);
        }
    }
}

/// Spawn the periodic flush loop: every `interval`, drain the counter and POST
/// it to the node's internal ingest endpoint over the given (mTLS) client. A
/// transiently rejected or failed flush is retained and retried on the next
/// tick; a permanently rejected (4xx) one is dropped — see [`flush_once`].
pub fn spawn_scan_flush(
    counter: std::sync::Arc<ScanCounter>,
    client: reqwest::Client,
    ingest_url: String,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            flush_once(&counter, &client, &ingest_url).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_and_drains() {
        let c = ScanCounter::default();
        c.record_scan("abc", ScanVariant::Html);
        c.record_scan("abc", ScanVariant::Html);
        c.record_scan("abc", ScanVariant::Json);
        c.record_qr_render("abc");

        let batch = c.drain();
        let html = batch
            .scans
            .iter()
            .find(|s| s.variant == ScanVariant::Html)
            .unwrap();
        assert_eq!(html.count, 2);
        assert_eq!(batch.qr_renders.len(), 1);
        assert_eq!(batch.qr_renders[0].count, 1);

        // Drain cleared the maps.
        assert!(c.drain().is_empty());
    }

    #[test]
    fn caps_distinct_keys_but_keeps_counting_existing_ones() {
        let mut m: HashMap<u32, u64> = HashMap::new();
        for k in 0..MAX_TRACKED_KEYS as u32 {
            bump(&mut m, k);
        }
        assert_eq!(m.len(), MAX_TRACKED_KEYS);

        // A brand-new key past capacity is dropped, not inserted.
        bump(&mut m, MAX_TRACKED_KEYS as u32);
        assert_eq!(m.len(), MAX_TRACKED_KEYS);
        assert_eq!(m.get(&(MAX_TRACKED_KEYS as u32)), None);

        // An already-tracked key keeps incrementing regardless.
        bump(&mut m, 0);
        assert_eq!(m[&0], 2);
    }

    /// The replacement for `merge_back_preserves_counts`, and the reason that
    /// test had to go: preserving the counts was never the hard part. Folding
    /// them back produced a *superset* window on the next drain, so two
    /// attempts at the same delivery carried different payloads and nothing
    /// could recognise the second as a resend.
    ///
    /// A held batch now goes back unchanged, and the counts that arrived
    /// meanwhile wait their turn.
    #[test]
    fn a_held_batch_is_resent_unchanged_and_new_counts_wait() {
        let c = ScanCounter::default();
        c.record_scan("abc", ScanVariant::Json);

        let first = c.next_flush();
        assert_eq!(first.batch.scans[0].count, 1);

        // A new count lands while the first delivery is unconfirmed.
        c.record_scan("abc", ScanVariant::Json);
        c.hold(first.clone());

        let retry = c.next_flush();
        assert_eq!(retry.id, first.id, "the same batch keeps the same key");
        assert_eq!(
            retry.batch, first.batch,
            "the resent payload must be byte-identical, or the node's \
             fingerprint check refuses it as a different request"
        );

        // Once it is confirmed, the count that arrived meanwhile goes out on
        // its own, under its own key — and exactly once.
        c.clear_pending();
        let next = c.next_flush();
        assert_ne!(next.id, first.id);
        assert_eq!(next.batch.scans[0].count, 1);
        assert!(c.next_flush().batch.is_empty());
    }

    /// Only one batch is ever held: nothing new is drained while one is
    /// outstanding, which is what bounds the memory this can occupy.
    #[test]
    fn at_most_one_batch_is_held() {
        let c = ScanCounter::default();
        c.record_scan("abc", ScanVariant::Json);
        let held = c.next_flush();
        c.hold(held.clone());

        for _ in 0..5 {
            c.record_scan("def", ScanVariant::Html);
            assert_eq!(
                c.next_flush().id,
                held.id,
                "a new window must not be drained while one is unconfirmed"
            );
        }
        assert!(c.has_pending());
    }

    use std::sync::Arc;

    use axum::{Json, Router, http::StatusCode, routing::post};

    /// Spawn a mock ingest server that records every batch it receives and
    /// replies with `reply`. Returns its base URL and the shared capture slot.
    async fn mock_ingest(reply: StatusCode) -> (String, Arc<std::sync::Mutex<Vec<ScanBatch>>>) {
        let captured = Arc::new(std::sync::Mutex::new(Vec::<ScanBatch>::new()));
        let sink = captured.clone();
        let app = Router::new().route(
            "/scan-batch",
            post(move |Json(batch): Json<ScanBatch>| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap().push(batch);
                    reply
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/scan-batch"), captured)
    }

    #[tokio::test]
    async fn flush_once_posts_the_batch_and_clears_on_success() {
        let (url, captured) = mock_ingest(StatusCode::NO_CONTENT).await;
        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Html);
        counter.record_scan("abc", ScanVariant::Html);
        counter.record_qr_render("abc");

        flush_once(&counter, &reqwest::Client::new(), &url).await;

        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 1, "exactly one flush landed");
        let batch = &got[0];
        assert_eq!(batch.scans[0].count, 2);
        assert_eq!(batch.scans[0].variant, ScanVariant::Html);
        assert_eq!(batch.qr_renders[0].count, 1);
        // A successful flush drained the counter.
        assert!(counter.drain().is_empty());
    }

    #[tokio::test]
    async fn flush_once_holds_the_window_on_server_error() {
        let (url, _captured) = mock_ingest(StatusCode::INTERNAL_SERVER_ERROR).await;
        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Json);

        flush_once(&counter, &reqwest::Client::new(), &url).await;

        // The 500 means the window is held for the next tick, not lost — and
        // held as the same batch, not folded back into the live counters.
        assert!(counter.has_pending());
        let held = counter.next_flush();
        assert_eq!(held.batch.scans.len(), 1);
        assert_eq!(held.batch.scans[0].variant, ScanVariant::Json);
    }

    #[tokio::test]
    async fn flush_once_drops_the_window_on_client_error() {
        let (url, _captured) = mock_ingest(StatusCode::BAD_REQUEST).await;
        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Json);

        flush_once(&counter, &reqwest::Client::new(), &url).await;

        // The 400 means the payload was permanently rejected — holding it
        // would just poison every future flush, so it is dropped, not retried.
        assert!(!counter.has_pending());
        assert!(counter.next_flush().batch.is_empty());
    }

    /// A `409` is the one client error that must not be dropped: it means an
    /// earlier attempt at this very batch is still being processed, which is
    /// transient and exactly what the key is for.
    #[tokio::test]
    async fn flush_once_holds_the_window_on_conflict() {
        let (url, _captured) = mock_ingest(StatusCode::CONFLICT).await;
        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Json);

        flush_once(&counter, &reqwest::Client::new(), &url).await;

        assert!(
            counter.has_pending(),
            "a 409 says 'still running', not 'never valid' — dropping the \
             window here would lose it"
        );
    }

    /// Every attempt at one batch carries the same key, and a new batch gets a
    /// new one. Without this the node cannot tell a resend from a fresh window,
    /// and the additive ingest double-counts.
    #[tokio::test]
    async fn every_attempt_at_one_batch_carries_the_same_key() {
        let keys: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = keys.clone();
        // Fails the first two attempts, then succeeds — the shape of a flaky
        // link, which is where the double-count used to happen.
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let app = Router::new().route(
            "/scan-batch",
            post(
                move |headers: axum::http::HeaderMap, Json(_): Json<ScanBatch>| {
                    let sink = sink.clone();
                    let attempts = attempts.clone();
                    async move {
                        sink.lock().unwrap().push(
                            headers
                                .get("idempotency-key")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("<none>")
                                .to_owned(),
                        );
                        if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                            StatusCode::INTERNAL_SERVER_ERROR
                        } else {
                            StatusCode::NO_CONTENT
                        }
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://{addr}/scan-batch");

        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Json);
        let client = reqwest::Client::new();
        for _ in 0..3 {
            flush_once(&counter, &client, &url).await;
        }

        let seen = keys.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "three attempts reached the ingest");
        assert_eq!(
            seen[0], seen[1],
            "a held batch must be resent under its original key"
        );
        assert_eq!(seen[1], seen[2]);
        assert_ne!(seen[0], "<none>", "the key must actually be sent");

        // Confirmed, so nothing is held and the next window is a new batch.
        assert!(!counter.has_pending());
        counter.record_scan("abc", ScanVariant::Json);
        flush_once(&counter, &client, &url).await;
        let seen = keys.lock().unwrap().clone();
        assert_ne!(
            seen[3], seen[2],
            "a genuinely new window is a new request and must not reuse the key"
        );
    }
}
