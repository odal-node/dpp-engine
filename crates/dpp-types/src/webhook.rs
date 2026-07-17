//! Signed outbound webhooks — subscriptions and the delivery outbox.
//!
//! Operators register receiver URLs (`webhook_subscription`); every domain event
//! is fanned out to a durable delivery outbox (`webhook_delivery`, `ops/pg/0022`)
//! and drained by the node as an HMAC-signed HTTP POST with backoff.
//!
//! # Why this lives here (not in core's `dpp-domain::ports`)
//!
//! The DPP standard says nothing about notifying an operator's own ERP/PLM when a
//! passport changes — outbound delivery is purely this deployment's operational
//! concern. So the ports stay engine-side alongside `RegistrySyncOutbox`, never
//! promoted to a core port.
//!
//! # Delivery guarantee
//!
//! Enqueue is **after-commit**, from the event chokepoint (`emit`) — not inside
//! the state-mutation transaction. Events are best-effort notifications (the DB
//! is the source of truth); the tiny commit→enqueue window is the same one the
//! NATS bus already accepts. Once a row exists it is loss-proof: transient
//! failures back off and stay `pending`, so a killed node redelivers on restart.
//! This is deliberately weaker than `RegistrySyncOutbox`'s transactional
//! guarantee, because a missed webhook is an operational annoyance, not the
//! legal violation a missed EU registration would be.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use dpp_domain::DppError;

/// Persisted state of one delivery-outbox row. Mirrors the `status` CHECK on
/// `odal.webhook_delivery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookDeliveryStatus {
    /// A delivery attempt is due or backed off (drainable).
    Pending,
    /// Receiver accepted it (2xx) — terminal success.
    Delivered,
    /// Retries exhausted, or a terminal receiver/config error — terminal failure.
    Exhausted,
}

impl WebhookDeliveryStatus {
    /// The exact string persisted in the `status` column.
    #[must_use]
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Exhausted => "exhausted",
        }
    }

    /// Parse a `status` column value. Unknown values map to `Pending` so an
    /// unexpected row is drained/inspected rather than silently ignored.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "delivered" => Self::Delivered,
            "exhausted" => Self::Exhausted,
            _ => Self::Pending,
        }
    }
}

/// A receiver subscription — public (redacted) view. The signing `secret` is
/// never carried here; it is returned exactly once from the create call and
/// otherwise stays server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookSubscription {
    /// Subscription id.
    pub id: Uuid,
    /// Receiver URL (validated `https`, non-private host at creation time).
    pub url: String,
    /// Subject filter: event_type strings, or a single `"*"` for all events.
    pub events: Vec<String>,
    /// Whether the subscription is live. Removal is a soft `active = false`.
    pub active: bool,
    /// Optional operator-facing label.
    pub description: Option<String>,
    /// When the subscription was created.
    pub created_at: DateTime<Utc>,
    /// When the subscription was last modified.
    pub updated_at: DateTime<Utc>,
}

/// Validated input for creating a subscription. The signing secret is generated
/// server-side (never client-supplied), so it is not part of this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewWebhookSubscription {
    /// Receiver URL. The service SSRF-validates this before persisting.
    pub url: String,
    /// Subject filter: event_type strings, or a single `"*"` for all events.
    pub events: Vec<String>,
    /// Optional operator-facing label.
    pub description: Option<String>,
}

/// One drainable delivery, denormalised with its subscription's `url` + `secret`
/// so the drain worker needs no second query to POST and sign.
#[derive(Debug, Clone)]
pub struct WebhookDeliveryRow {
    /// Delivery-row id (also the `X-Odal-Delivery` header, for receiver dedupe).
    pub delivery_id: Uuid,
    /// Owning subscription.
    pub subscription_id: Uuid,
    /// Receiver URL to POST to.
    pub url: String,
    /// Signing secret for the HMAC.
    pub secret: String,
    /// The event type (also the `X-Odal-Event` header).
    pub event_type: String,
    /// The exact serialised body to POST and sign.
    pub body: String,
    /// Attempts made so far (pre-increment).
    pub attempts: i32,
}

/// Aggregate counts for boot reconciliation and gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebhookCounts {
    /// Rows awaiting a delivery attempt.
    pub pending: i64,
    /// Rows terminally delivered.
    pub delivered: i64,
    /// Rows terminally exhausted (need attention).
    pub exhausted: i64,
}

/// CRUD over receiver subscriptions. Implemented by the Postgres DAL; consumed
/// by the vault management handlers.
#[async_trait]
pub trait WebhookSubscriptionStore: Send + Sync {
    /// Persist a new subscription with its server-generated signing `secret`.
    async fn create(
        &self,
        input: &NewWebhookSubscription,
        secret: &str,
    ) -> Result<WebhookSubscription, DppError>;

    /// All subscriptions (active and retired), newest first.
    async fn list(&self) -> Result<Vec<WebhookSubscription>, DppError>;

    /// One subscription by id, if it exists.
    async fn get(&self, id: Uuid) -> Result<Option<WebhookSubscription>, DppError>;

    /// Soft-remove: set `active = false`. Returns `true` if a row was updated.
    async fn deactivate(&self, id: Uuid) -> Result<bool, DppError>;
}

/// The delivery outbox — enqueue (from the event chokepoint) and drain (from the
/// node's background loop). Implemented by the Postgres DAL.
#[async_trait]
pub trait WebhookOutbox: Send + Sync {
    /// Fan-out enqueue: insert one `pending` delivery per **active** subscription
    /// whose filter matches `event_type` (or is `"*"`). `body` is stored verbatim
    /// — the exact bytes to POST and sign. Returns the number of rows enqueued.
    async fn enqueue(&self, event_type: &str, body: &str) -> Result<u64, DppError>;

    /// Enqueue a single delivery for one subscription regardless of its filter
    /// (the `test` endpoint). Returns the number of rows enqueued (0 if the
    /// subscription does not exist).
    async fn enqueue_for(
        &self,
        subscription_id: Uuid,
        event_type: &str,
        body: &str,
    ) -> Result<u64, DppError>;

    /// Rows due for a delivery attempt (`pending`, `next_attempt_at <= now`),
    /// oldest first, capped at `limit`. Not filtered on subscription `active` —
    /// in-flight rows drain even if their subscription was just retired, so no
    /// row is stranded forever `pending`.
    async fn due(&self, limit: i64) -> Result<Vec<WebhookDeliveryRow>, DppError>;

    /// Terminal success: mark `delivered`.
    async fn mark_delivered(&self, delivery_id: Uuid) -> Result<(), DppError>;

    /// Transient failure: increment `attempts`, push `next_attempt_at` out by an
    /// exponential backoff (with jitter), keep the row `pending`.
    async fn mark_attempt_failed(&self, delivery_id: Uuid, message: String)
    -> Result<(), DppError>;

    /// Terminal failure: mark `exhausted` and store the reason. The row stays for
    /// audit — it is never deleted.
    async fn mark_exhausted(&self, delivery_id: Uuid, message: String) -> Result<(), DppError>;

    /// Counts by status, for boot reconciliation logs and the `webhook_delivery_*`
    /// gauges.
    async fn status_counts(&self) -> Result<WebhookCounts, DppError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_status_db_roundtrip() {
        for s in [
            WebhookDeliveryStatus::Pending,
            WebhookDeliveryStatus::Delivered,
            WebhookDeliveryStatus::Exhausted,
        ] {
            assert_eq!(WebhookDeliveryStatus::from_db(s.as_db()), s);
        }
        // Unknown maps to Pending (drain/inspect, never silently ignore).
        assert_eq!(
            WebhookDeliveryStatus::from_db("bogus"),
            WebhookDeliveryStatus::Pending
        );
    }

    #[test]
    fn subscription_serialises_camel_case() {
        let sub = WebhookSubscription {
            id: Uuid::now_v7(),
            url: "https://example.test/hook".into(),
            events: vec!["*".into()],
            active: true,
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_value(&sub).unwrap();
        assert!(json.get("createdAt").is_some());
        assert!(json.get("created_at").is_none());
        // The secret is never part of the serialised view.
        assert!(json.get("secret").is_none());
    }
}
