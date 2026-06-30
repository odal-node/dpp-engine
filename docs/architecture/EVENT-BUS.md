# Event Bus Architecture

This document covers the platform event bus: the trait, the versioned envelope, NATS JetStream integration, and the fire-after-commit guarantee.

---

## 1. Design Decisions

- **Trait location**: `dpp-common` (infrastructure behaviour), not `dpp-types` (pure data). The event bus is behaviour, not a domain type. `dpp-types` stays data-only.
- **Fire-and-forget**: Callers emit events after the DB commit succeeds. If publish fails, the error is logged but the mutation is NOT rolled back. The database is the source of truth; events are notifications.
- **NoOp fallback**: When `NATS_URL` is not configured, `NoOpEventBus` is injected. Self-hosted single-node deployments work without NATS.

---

## 2. Event Envelope

Every event uses the `DppEvent` versioned envelope:

```rust
pub struct DppEvent {
    pub version: u32,           // Envelope schema version (starts at 1)
    pub event_id: Uuid,         // UUIDv7 (time-ordered)
    pub event_type: String,     // NATS subject, e.g. "dpp.passport.published"
    pub timestamp: DateTime<Utc>,
    pub operator_id: String,    // Owning operator
    pub data: serde_json::Value, // Event-specific payload
}
```

JSON serialisation uses `#[serde(rename_all = "camelCase")]`:

```json
{
  "version": 1,
  "eventId": "01964f3a-...",
  "eventType": "dpp.passport.published",
  "timestamp": "2026-05-27T14:30:00Z",
  "operatorId": "self_hosted",
  "data": { "passportId": "...", "status": "active" }
}
```

---

## 3. Well-Known Subjects

| Subject | When Emitted |
|---|---|
| `dpp.passport.created` | New passport created (draft) |
| `dpp.passport.updated` | Draft passport fields updated |
| `dpp.passport.published` | Passport signed and published (draft -> active) |
| `dpp.passport.suspended` | Active passport suspended |
| `dpp.passport.archived` | Passport archived (irreversible) |
| `dpp.passport.failed` | Passport operation failed |
| `dpp.import.completed` | Bulk import job completed |
| `dpp.import.failed` | Bulk import job failed |

All subjects follow the pattern `dpp.{resource}.{action}`, compatible with NATS subject wildcards (`dpp.>` for all events, `dpp.passport.>` for passport events only).

---

## 4. EventBus Trait

```rust
#[async_trait]
pub trait EventBus: Send + Sync {
    async fn publish(&self, event: &DppEvent) -> Result<(), EventBusError>;
}
```

### Implementations

**NoOpEventBus** — Logs the event at DEBUG level and discards it. Default when `NATS_URL` is absent.

**NatsEventBus** — Publishes to NATS JetStream:
- Stream: `DPP_EVENTS`
- Subject pattern: `dpp.>`
- Retention: 7-day message TTL
- Storage: File-based (survives NATS restart)
- Location: `dpp-node/src/infra/nats_event_bus.rs`

---

## 5. Fire-After-Commit Flow

```
PassportService::publish()
    |
    +-- 1. Validate passport state
    +-- 2. Sign with Ed25519 via IdentityPort
    +-- 3. Update passport in PostgreSQL (retention_locked = true)
    |       (registry registration is written to the registry_sync outbox in the same transaction)
    +-- 4. Emit event:
            DppEvent::v1("dpp.passport.published", operator_id, data)
    +-- 5. Return published passport to handler
```

If step 3 fails (DB error), step 4 never runs — no phantom events.
If step 4 fails (NATS down), the error is logged at WARN and the function returns the published passport. The consumer sees the event eventually (when NATS recovers) or misses it (acceptable — DB is the source of truth).

---

## 6. Consumer Guidelines

Consumers of the event bus should follow these rules:

1. **Be idempotent** — The same event may be delivered more than once (at-least-once delivery via JetStream).
2. **Use the version field** — When the event payload shape changes, the version increments. Handle both versions during migration.
3. **Don't rely on ordering** — Events are published per-subject. Cross-subject ordering is not guaranteed.
4. **Don't use events as the source of truth** — Always read from the database for the canonical state. Events are notifications, not commands.

---

## 7. Adding a New Event

1. Add a constant to `dpp-common/src/event.rs::subjects`:

```rust
pub const PASSPORT_RECALLED: &str = "dpp.passport.recalled";
```

2. Emit it from the appropriate service method:

```rust
self.emit(subjects::PASSPORT_RECALLED, &auth.operator_id, &passport);
```

3. Update this document's subject table.

No NATS configuration changes needed — the `dpp.>` wildcard subject captures all new subjects automatically.
