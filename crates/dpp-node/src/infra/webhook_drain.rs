//! One drain pass over the webhook-delivery outbox.
//!
//! Fetches due rows and POSTs each to its receiver with an HMAC signature,
//! recording the terminal (`delivered`/`exhausted`) or transient (backoff)
//! outcome on the row. Extracted from the node's background loop so the delivery
//! semantics are unit-testable with a mock outbox + a local receiver — the loop
//! in `main` just calls this on a timer and refreshes the gauges.
//!
//! Structurally mirrors `registry_drain`: never panics, never propagates — a
//! per-row failure is recorded (`mark_*`) and the pass continues, so one bad row
//! cannot stall the queue.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use dpp_types::WebhookOutbox;

type HmacSha256 = Hmac<Sha256>;

/// Max delivery attempts before a row is terminally `exhausted`.
pub const MAX_ATTEMPTS: i32 = 8;

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Rows the receiver accepted (2xx) — terminal `delivered`.
    pub delivered: u32,
    /// Rows that failed transiently and were backed off for retry.
    pub retried: u32,
    /// Rows that reached terminal `exhausted` (attempt cap hit, or a target that
    /// resolved to a non-public address).
    pub exhausted: u32,
}

/// Signature header value: `t=<unix>,v1=<hex(HMAC-SHA256(secret, "<t>.<body>"))>`.
/// Binding the timestamp into the signed string gives receivers replay
/// protection (reject stale `t`); the raw `body` is signed verbatim so the
/// receiver signs exactly the bytes it received.
fn signature_header(secret: &str, timestamp: i64, body: &str) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let digest = hex::encode(mac.finalize().into_bytes());
    format!("t={timestamp},v1={digest}")
}

/// Delivery-time SSRF check, returning the client the delivery must use.
///
/// This used to call `url_guard::assert_public_target` and then hand the *URL*
/// to the shared client. Those are two independent resolutions with nothing
/// binding them: the guard approves one answer, and the client resolves the name
/// again to connect — so a zero-TTL record alternating a public and an internal
/// address passes the check and connects internally. The guard's own
/// documentation says exactly this and names the remedy, and every other
/// outbound path here already took it. This was the last one that had not, and
/// the only one whose target is supplied entirely by an operator.
///
/// So the check now yields a **pinned** client rather than a verdict: it can
/// only reach the addresses that were approved, and nothing between the check
/// and the connection can change the destination.
///
/// The `allow_private` opt-out is webhook-specific and stays here: a
/// self-hosting operator may legitimately deliver to their *own* internal
/// receiver, which is a target they chose. It must never be extended to a target
/// a caller supplies.
async fn client_for_target(
    shared: &reqwest::Client,
    url_str: &str,
    allow_private: bool,
) -> Result<reqwest::Client, String> {
    if allow_private {
        return Ok(shared.clone());
    }
    dpp_common::outbound::pinned_client_for(shared, url_str)
        .await
        .map_err(|e| e.to_string())
}

/// Record a transient failure: back off and retry, unless the attempt cap is
/// reached in which case the row is terminally `exhausted`.
async fn back_off_or_exhaust(
    outbox: &Arc<dyn WebhookOutbox>,
    delivery_id: uuid::Uuid,
    attempts: i32,
    reason: String,
    stats: &mut DrainStats,
) {
    if attempts + 1 >= MAX_ATTEMPTS {
        let _ = outbox
            .mark_exhausted(delivery_id, format!("max attempts reached: {reason}"))
            .await;
        metrics::counter!("webhook_delivery_total", "outcome" => "exhausted").increment(1);
        stats.exhausted += 1;
    } else {
        let _ = outbox.mark_attempt_failed(delivery_id, reason).await;
        metrics::counter!("webhook_delivery_total", "outcome" => "retried").increment(1);
        stats.retried += 1;
    }
}

/// Drain up to `batch` due deliveries once.
pub async fn drain_once(
    outbox: &Arc<dyn WebhookOutbox>,
    client: &reqwest::Client,
    batch: i64,
    allow_private: bool,
) -> DrainStats {
    let mut stats = DrainStats::default();
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "webhook outbox drain: query failed");
            return stats;
        }
    };
    for row in due {
        let id = row.delivery_id;

        // The delivery uses the client this returns, never the shared one: it is
        // pinned to the addresses the guard approved.
        let delivery_client = match client_for_target(client, &row.url, allow_private).await {
            Ok(c) => c,
            Err(reason) => {
                tracing::warn!(delivery_id = %id, reason = %reason, "webhook target blocked");
                let _ = outbox
                    .mark_exhausted(id, format!("blocked target: {reason}"))
                    .await;
                metrics::counter!("webhook_delivery_total", "outcome" => "blocked").increment(1);
                stats.exhausted += 1;
                continue;
            }
        };

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let signature = signature_header(&row.secret, ts, &row.body);

        let started = std::time::Instant::now();
        let resp = delivery_client
            .post(&row.url)
            .header("Content-Type", "application/json")
            .header("X-Odal-Signature", signature)
            .header("X-Odal-Delivery", id.to_string())
            .header("X-Odal-Event", &row.event_type)
            .body(row.body.clone())
            .send()
            .await;
        metrics::histogram!("webhook_delivery_seconds").record(started.elapsed().as_secs_f64());

        match resp {
            Ok(r) if r.status().is_success() => {
                let _ = outbox.mark_delivered(id).await;
                metrics::counter!("webhook_delivery_total", "outcome" => "delivered").increment(1);
                stats.delivered += 1;
            }
            Ok(r) => {
                // Any non-2xx (4xx or 5xx) backs off and retries up to the cap,
                // then exhausts. A brief 4xx during a receiver deploy must not
                // permanently kill the subscription; the cap bounds the retries.
                back_off_or_exhaust(
                    outbox,
                    id,
                    row.attempts,
                    format!("receiver returned {}", r.status()),
                    &mut stats,
                )
                .await;
            }
            Err(e) => {
                back_off_or_exhaust(outbox, id, row.attempts, e.to_string(), &mut stats).await;
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_for_known_inputs() {
        // Fixed vector: HMAC-SHA256("shhh", "1700000000.{\"a\":1}").
        let got = signature_header("shhh", 1_700_000_000, r#"{"a":1}"#);
        assert!(got.starts_with("t=1700000000,v1="));
        // Deterministic: same inputs → same digest.
        assert_eq!(got, signature_header("shhh", 1_700_000_000, r#"{"a":1}"#));
        // A different body changes the digest.
        assert_ne!(got, signature_header("shhh", 1_700_000_000, r#"{"a":2}"#));
    }

    #[tokio::test]
    async fn blocks_loopback_and_metadata_targets_by_default() {
        let shared = reqwest::Client::new();
        assert!(
            client_for_target(&shared, "https://127.0.0.1/hook", false)
                .await
                .is_err()
        );
        assert!(
            client_for_target(&shared, "https://169.254.169.254/latest", false)
                .await
                .is_err()
        );
        // Bracketed IPv6 loopback must be caught (host_str keeps the brackets).
        assert!(
            client_for_target(&shared, "https://[::1]/hook", false)
                .await
                .is_err()
        );
        // Opt-in permits a private literal.
        assert!(
            client_for_target(&shared, "https://127.0.0.1/hook", true)
                .await
                .is_ok()
        );
        // Non-https is always refused.
        assert!(
            client_for_target(&shared, "http://example.com/hook", false)
                .await
                .is_err()
        );
    }

    /// The point of the change: a refused target yields **no client at all**, so
    /// a delivery cannot be attempted against it.
    ///
    /// The previous shape returned a verdict and left the caller holding a
    /// client that could still reach anywhere — which is what let the check and
    /// the connection disagree. Asserting on the returned value rather than on a
    /// boolean is what pins that.
    #[tokio::test]
    async fn a_refused_target_yields_no_client() {
        let shared = reqwest::Client::new();
        let refused = client_for_target(&shared, "https://169.254.169.254/latest", false).await;
        assert!(
            refused.is_err(),
            "the metadata endpoint must not produce a usable client"
        );
    }
}
