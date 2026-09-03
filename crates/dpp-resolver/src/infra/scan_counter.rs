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
//! transient flush failure is not a loss: the batch is merged back and retried.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{NaiveDate, Utc};

use dpp_common::scan::{QrRenderBatchEntry, ScanBatch, ScanBatchEntry, ScanVariant};

/// Cap on distinct keys held per map, so a stuck ingest endpoint or a flood of
/// distinct `dpp_id`s can't grow the resolver's memory without bound. Once at
/// capacity, increments to keys not already tracked are dropped (existing keys
/// keep counting) — an undercount, the safe direction for this number.
const MAX_TRACKED_KEYS: usize = 50_000;

/// Thread-safe accumulator of aggregate scan and QR-render counts.
#[derive(Default)]
pub struct ScanCounter {
    scans: Mutex<HashMap<(String, NaiveDate, ScanVariant), u64>>,
    qr_renders: Mutex<HashMap<(String, NaiveDate), u64>>,
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

    /// Fold a drained batch back in after a failed flush, so no window is lost.
    pub fn merge_back(&self, batch: ScanBatch) {
        let mut scans = self.scans.lock().unwrap();
        for s in batch.scans {
            *scans.entry((s.dpp_id, s.day, s.variant)).or_insert(0) += s.count;
        }
        drop(scans);
        let mut qr = self.qr_renders.lock().unwrap();
        for q in batch.qr_renders {
            *qr.entry((q.dpp_id, q.day)).or_insert(0) += q.count;
        }
    }
}

/// Drain the counter once and POST the batch to the node's internal ingest
/// endpoint. A transient failure (5xx, or the request itself failing) is
/// merged back so no window is lost; a 4xx is a permanent rejection of this
/// payload and is dropped rather than retried forever. Broken out from the loop
/// so it is testable against a mock ingest server without waiting on a timer.
///
/// # An empty window is still sent
///
/// It used to return early with nothing to say, which meant the node heard from
/// the resolver only when somebody had scanned something. The node cannot read
/// `SCAN_INGEST_URL` — it is this process's configuration, not the node's — so
/// silence was indistinguishable between "telemetry is switched off" (the
/// default) and "telemetry is on and nobody scanned". The node reported `0`
/// either way, and an operator could not tell a real zero from an unmeasured
/// one.
///
/// So an empty batch is a heartbeat: it costs one small request per flush
/// interval and it is the only thing that makes the node's `ingesting` flag
/// mean anything.
async fn flush_once(counter: &ScanCounter, client: &reqwest::Client, ingest_url: &str) {
    let batch = counter.drain();
    match client.post(ingest_url).json(&batch).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) if resp.status().is_client_error() => {
            // A 4xx means the vault permanently rejected this payload (bad
            // shape, wrong CN, ...) — retrying it verbatim would never
            // succeed, so retaining it would just poison every future flush.
            tracing::error!(
                status = %resp.status(),
                "scan flush rejected as invalid — dropping window, not retrying"
            );
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "scan flush rejected — retaining for retry");
            counter.merge_back(batch);
        }
        Err(e) => {
            tracing::warn!(error = %e, "scan flush failed — retaining for retry");
            counter.merge_back(batch);
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

    #[test]
    fn merge_back_preserves_counts() {
        let c = ScanCounter::default();
        c.record_scan("abc", ScanVariant::Json);
        let batch = c.drain();
        c.record_scan("abc", ScanVariant::Json); // a new count arrives mid-flight
        c.merge_back(batch); // failed flush folds back in

        let merged = c.drain();
        let json = merged
            .scans
            .iter()
            .find(|s| s.variant == ScanVariant::Json)
            .unwrap();
        assert_eq!(json.count, 2);
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
    async fn flush_once_retains_the_window_on_server_error() {
        let (url, _captured) = mock_ingest(StatusCode::INTERNAL_SERVER_ERROR).await;
        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Json);

        flush_once(&counter, &reqwest::Client::new(), &url).await;

        // The 500 means the window is retained for the next tick, not lost.
        let retained = counter.drain();
        assert_eq!(retained.scans.len(), 1);
        assert_eq!(retained.scans[0].variant, ScanVariant::Json);
    }

    #[tokio::test]
    async fn flush_once_drops_the_window_on_client_error() {
        let (url, _captured) = mock_ingest(StatusCode::BAD_REQUEST).await;
        let counter = ScanCounter::default();
        counter.record_scan("abc", ScanVariant::Json);

        flush_once(&counter, &reqwest::Client::new(), &url).await;

        // The 400 means the payload was permanently rejected — retaining it
        // would just poison every future flush, so it is dropped, not retried.
        assert!(counter.drain().is_empty());
    }
}
