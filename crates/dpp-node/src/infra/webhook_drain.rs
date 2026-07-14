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

use hmac::{Hmac, Mac};
use sha2::Sha256;

use dpp_common::url_guard::ip_is_disallowed;
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
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let digest = hex::encode(mac.finalize().into_bytes());
    format!("t={timestamp},v1={digest}")
}

/// Delivery-time SSRF re-check: re-resolve the host *now* and refuse any
/// private/loopback/metadata address (guards a hostname that resolves internal,
/// and DNS rebinding between create and delivery). Skipped when `allow_private`.
async fn assert_public_target(url_str: &str, allow_private: bool) -> Result<(), String> {
    let url = reqwest::Url::parse(url_str).map_err(|e| format!("invalid URL: {e}"))?;
    // Trust opt-in: skip the scheme + range guard entirely (internal receiver).
    if allow_private {
        return Ok(());
    }
    if url.scheme() != "https" {
        return Err("scheme is not https".into());
    }
    // `Host` parses IP literals correctly, including bracketed IPv6.
    match url.host().ok_or("no host")? {
        url::Host::Ipv4(ip) => reject_if_disallowed(std::net::IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => reject_if_disallowed(std::net::IpAddr::V6(ip)),
        url::Host::Domain(host) => {
            // Re-resolve now and check every answer (catches a hostname that
            // resolves internal, and DNS rebinding between create and delivery).
            let port = url.port_or_known_default().unwrap_or(443);
            let addrs = tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| format!("DNS resolution failed: {e}"))?;
            let mut resolved = false;
            for addr in addrs {
                resolved = true;
                reject_if_disallowed(addr.ip())?;
            }
            if resolved {
                Ok(())
            } else {
                Err("host did not resolve".into())
            }
        }
    }
}

fn reject_if_disallowed(ip: std::net::IpAddr) -> Result<(), String> {
    if ip_is_disallowed(ip) {
        Err(format!("host is a non-public address ({ip})"))
    } else {
        Ok(())
    }
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

        if let Err(reason) = assert_public_target(&row.url, allow_private).await {
            tracing::warn!(delivery_id = %id, reason = %reason, "webhook target blocked");
            let _ = outbox
                .mark_exhausted(id, format!("blocked target: {reason}"))
                .await;
            metrics::counter!("webhook_delivery_total", "outcome" => "blocked").increment(1);
            stats.exhausted += 1;
            continue;
        }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let signature = signature_header(&row.secret, ts, &row.body);

        let started = std::time::Instant::now();
        let resp = client
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
        assert!(
            assert_public_target("https://127.0.0.1/hook", false)
                .await
                .is_err()
        );
        assert!(
            assert_public_target("https://169.254.169.254/latest", false)
                .await
                .is_err()
        );
        // Bracketed IPv6 loopback must be caught (host_str keeps the brackets).
        assert!(
            assert_public_target("https://[::1]/hook", false)
                .await
                .is_err()
        );
        // Opt-in permits a private literal.
        assert!(
            assert_public_target("https://127.0.0.1/hook", true)
                .await
                .is_ok()
        );
        // Non-https is always refused.
        assert!(
            assert_public_target("http://example.com/hook", false)
                .await
                .is_err()
        );
    }
}
