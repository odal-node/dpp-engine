//! Platform event bus — trait, envelope, and NoOp implementation.
//!
//! # Design decisions
//!
//! - **Trait location**: `dpp-common` (infrastructure), not `dpp-types` (pure data).
//!   The event bus is behaviour, not a domain type. `dpp-types` stays data-only.
//! - **Versioned envelope**: every event carries `version: u32` so consumers can
//!   handle schema evolution without breakage.
//! - **Fire-and-forget semantics**: callers emit events *after* the DB commit
//!   succeeds. If publish fails, the error is logged but the mutation is NOT
//!   rolled back. The database is the source of truth; events are notifications.
//! - **NoOp fallback**: when `NATS_URL` is not configured, `NoOpEventBus` is
//!   injected. This means self-hosted single-node deployments work without NATS.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Event envelope ──────────────────────────────────────────────────────────

/// Versioned event envelope. Every event published through the bus uses this
/// structure so consumers can deserialise without knowing the concrete type.
///
/// ```json
/// {
///   "version": 1,
///   "eventId": "01964f3a-...",
///   "eventType": "dpp.passport.published",
///   "timestamp": "2026-05-27T14:30:00Z",
///   "operatorId": "self_hosted",
///   "data": { "passportId": "...", "status": "active" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DppEvent {
    /// Schema version of this event envelope. Starts at 1.
    /// Increment when the `data` shape changes in a breaking way.
    pub version: u32,
    /// Unique identifier for this event instance (UUIDv7, time-ordered).
    pub event_id: Uuid,
    /// Dot-separated event type, e.g. `dpp.passport.published`.
    /// Also used as the NATS subject.
    pub event_type: String,
    /// When the event was created.
    pub timestamp: DateTime<Utc>,
    /// Operator that owns the resource.
    pub operator_id: String,
    /// Event-specific payload. Shape depends on `event_type` + `version`.
    pub data: serde_json::Value,
}

impl DppEvent {
    /// Create a new v1 event with the given type, operator, and data payload.
    pub fn v1(
        event_type: impl Into<String>,
        operator_id: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            version: 1,
            event_id: Uuid::now_v7(),
            event_type: event_type.into(),
            timestamp: Utc::now(),
            operator_id: operator_id.into(),
            data,
        }
    }
}

// ─── Well-known event subjects ───────────────────────────────────────────────

/// Well-known NATS subject strings. Use these constants as the `event_type`
/// argument to `DppEvent::v1` so subjects are consistent across all publishers.
pub mod subjects {
    // Passport lifecycle
    pub const PASSPORT_CREATED: &str = "dpp.passport.created";
    pub const PASSPORT_UPDATED: &str = "dpp.passport.updated";
    pub const PASSPORT_PUBLISHED: &str = "dpp.passport.published";
    pub const PASSPORT_SUSPENDED: &str = "dpp.passport.suspended";
    pub const PASSPORT_ARCHIVED: &str = "dpp.passport.archived";
    pub const PASSPORT_FAILED: &str = "dpp.passport.failed";

    // Batch import
    pub const IMPORT_COMPLETED: &str = "dpp.import.completed";
    pub const IMPORT_FAILED: &str = "dpp.import.failed";
}

// ─── Error type ──────────────────────────────────────────────────────────────

/// Lightweight error for event publishing. Callers log this and move on.
#[derive(Debug, thiserror::Error)]
pub enum EventBusError {
    #[error("event bus publish failed: {0}")]
    PublishFailed(String),
    #[error("event bus connection lost: {0}")]
    ConnectionLost(String),
    #[error("event serialisation failed: {0}")]
    Serialisation(String),
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Platform event bus for publishing domain events.
///
/// Implementations:
/// - `NoOpEventBus` — silent discard (default when NATS is unavailable)
/// - `NatsEventBus` — publishes to NATS JetStream (in `dpp-node`)
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish an event. The `event_type` field is used as the NATS subject.
    async fn publish(&self, event: &DppEvent) -> Result<(), EventBusError>;
}

// ─── NoOp implementation ─────────────────────────────────────────────────────

/// Silent event bus that discards all events. Used when NATS is not configured.
pub struct NoOpEventBus;

#[async_trait]
impl EventBus for NoOpEventBus {
    async fn publish(&self, event: &DppEvent) -> Result<(), EventBusError> {
        tracing::debug!(
            event_type = %event.event_type,
            event_id = %event.event_id,
            "event discarded (NoOp bus)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpp_event_v1_sets_fields() {
        let evt = DppEvent::v1(
            subjects::PASSPORT_CREATED,
            "operator_1",
            serde_json::json!({"passportId": "abc-123"}),
        );
        assert_eq!(evt.version, 1);
        assert_eq!(evt.event_type, "dpp.passport.created");
        assert_eq!(evt.operator_id, "operator_1");
        assert_eq!(evt.data["passportId"], "abc-123");
    }

    #[test]
    fn dpp_event_serialises_to_camel_case() {
        let evt = DppEvent::v1(subjects::PASSPORT_PUBLISHED, "t1", serde_json::json!({}));
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("eventId").is_some());
        assert!(json.get("eventType").is_some());
        assert!(json.get("operatorId").is_some());
        // Snake-case keys should NOT exist
        assert!(json.get("event_id").is_none());
        assert!(json.get("event_type").is_none());
    }

    #[tokio::test]
    async fn noop_bus_succeeds_silently() {
        let bus = NoOpEventBus;
        let evt = DppEvent::v1("dpp.test", "t1", serde_json::json!({}));
        assert!(bus.publish(&evt).await.is_ok());
    }
}
