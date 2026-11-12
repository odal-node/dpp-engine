//! Axum middleware for HTTP request metrics (counter + histogram).
//!
//! # Naming convention (workspace-wide, not just this middleware)
//!
//! Metric names are permanent API surface the moment something scrapes them —
//! a fleet-wide dashboard or alert rule parses them forever. The convention
//! observed across the engine: counters end in `_total` (`http_requests_total`,
//! `signing_failures_total`, `plugin_fuel_exhausted_total`), histograms end in
//! their unit (`http_request_duration_seconds`), gauges carry no suffix
//! (`trust_mode`). Follow it for any new metric.
//!
//! One existing near-miss worth knowing about rather than silently renaming:
//! `registry_outbox_rejected` (a gauge, `dpp-node::main`) and
//! `registry_outbox_rejected_total` (a counter, `dpp-node::infra::registry_drain`)
//! are two different metrics with a name that differs only by the `_total`
//! convention — easy to misread as the same series. Renaming either is a
//! breaking change for anyone already scraping it, so this is flagged, not
//! fixed, here.

use std::time::Instant;

use axum::{extract::Request, middleware::Next, response::Response};

/// Tower middleware that records `http_requests_total` (counter) and
/// `http_request_duration_seconds` (histogram) for every request.
///
/// Dimensions: `route`, `method`, `status`. The `route` is the matched path
/// template (e.g. `/vault/dpp/:dppId`), not the resolved URL, so high-cardinality
/// IDs do not explode the label space.
///
/// Add to each service router via `axum::middleware::from_fn(http_metrics_middleware)`.
/// Metrics are no-ops unless a `metrics` recorder (e.g. Prometheus) has been
/// installed at process startup.
pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let start = Instant::now();

    let response = next.run(request).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    metrics::counter!(
        "http_requests_total",
        "route"  => route.clone(),
        "method" => method.clone(),
        "status" => status
    )
    .increment(1);

    metrics::histogram!(
        "http_request_duration_seconds",
        "route"  => route,
        "method" => method
    )
    .record(duration);

    response
}

/// Count one publish refused because a passport could not be signed, on the
/// Prometheus counter `/metrics` exports. The durable count is kept beside it by
/// the publish path, see `dpp_types::node_signal`.
pub fn record_signing_failure() {
    metrics::counter!("signing_failures_total").increment(1);
}

/// Count one ruleset load that failed: the channel could not be read, or the
/// bundle it served was refused. See [`record_signing_failure`].
pub fn record_ruleset_load_failure() {
    metrics::counter!("ruleset_load_failures_total").increment(1);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    use super::*;

    /// A recorder that totals every counter by name: the exported side of a
    /// refusal, for a test to read. Gauges and histograms are not kept.
    #[derive(Clone, Default)]
    struct ExportedCounters(Arc<Mutex<HashMap<String, u64>>>);

    struct Increments {
        name: String,
        totals: Arc<Mutex<HashMap<String, u64>>>,
    }

    impl CounterFn for Increments {
        fn increment(&self, value: u64) {
            *self
                .totals
                .lock()
                .unwrap()
                .entry(self.name.clone())
                .or_default() += value;
        }

        fn absolute(&self, value: u64) {
            self.totals.lock().unwrap().insert(self.name.clone(), value);
        }
    }

    impl Recorder for ExportedCounters {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            Counter::from_arc(Arc::new(Increments {
                name: key.name().to_owned(),
                totals: Arc::clone(&self.0),
            }))
        }

        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }

        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }

    /// How far the exported counter called `name` moves while `record` runs.
    fn exported_increase(name: &str, record: fn()) -> u64 {
        let exported = ExportedCounters::default();
        metrics::with_local_recorder(&exported, record);
        exported.0.lock().unwrap().get(name).copied().unwrap_or(0)
    }

    /// A refused signature moves the counter `/metrics` exports, under the name
    /// monitors already scrape.
    #[test]
    fn a_refused_signature_moves_the_exported_counter() {
        assert_eq!(
            exported_increase("signing_failures_total", record_signing_failure),
            1
        );
    }

    #[test]
    fn a_refused_ruleset_bundle_moves_the_exported_counter() {
        assert_eq!(
            exported_increase("ruleset_load_failures_total", record_ruleset_load_failure),
            1
        );
    }
}
