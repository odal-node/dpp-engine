# Design Patterns

This document describes the architectural patterns used in dpp-engine and the reasoning behind each choice.

---

## 1. Hexagonal Architecture — Platform as Adapters

dpp-core defines the domain and the port traits. dpp-engine implements every adapter:

```
         +---------------------------------------------+
         |             Driving Adapters                 |
         |  Axum HTTP handlers, CSV parser, CLI         |
         +---------------------+------------------------+
                               |  <- Port traits (defined in dpp-core)
                   +-----------v-----------+
                   |    Domain / Core      |
                   |  (dpp-core repo)      |
                   |  - Passport types     |
                   |  - Lifecycle rules    |
                   |  - Schema validation  |
                   |  - Signing logic      |
                   +-----------+-----------+
                               |  <- Port traits (defined in dpp-core)
         +---------------------v------------------------+
         |             Driven Adapters                  |
         |  PostgreSQL repos, NATS event bus,           |
         |  Wasm plugin host, identity HTTP client      |
         +---------------------------------------------+
```

The platform never modifies the domain. It only implements traits and wires dependencies.

---

## 2. Serde-Driven Repositories

All repositories follow the same serde-driven pattern in the PostgreSQL backend (`dpp-dal/src/pg/`): the entity serialises to its full JSON document (`doc JSONB`), extracted columns are written alongside it, and reads deserialise the document back via serde.

**Why this pattern:**
- All field mapping is handled by `#[serde(rename_all = "camelCase")]` on the structs — no manual column name mapping
- The `doc JSONB` column stores the full entity; extracted columns (e.g. `operator_id`, `status`) exist for indexed queries

The `api_key` repository is a variation: it uses an internal `ApiKeyRow` struct for deserialisation because the DB row contains `keyHash` which is not part of the public `ApiKey` type.

---

## 3. Composite Authentication

Authentication is a chain of providers, not a single strategy:

```rust
pub struct CompositeAuthProvider {
    providers: Vec<Box<dyn AuthProvider>>,
}

impl AuthProvider for CompositeAuthProvider {
    async fn authenticate(&self, request: &Request) -> Result<AuthContext, AuthError> {
        for provider in &self.providers {
            match provider.authenticate(request).await {
                Ok(ctx) => return Ok(ctx),
                Err(AuthError::NotApplicable) => continue,  // Try next provider
                Err(e) => return Err(e),                     // Hard failure
            }
        }
        Err(AuthError::Unauthenticated)
    }
}
```

**Current chain:**
1. `ApiKeyAuthProvider` — matches `Bearer odal_sk_...` tokens, SHA-256 hash lookup
2. `LocalAuthProvider` — matches HTTP Basic auth against env var credentials

**Why composite:** Adding a new auth method (OAuth, mTLS, OIDC) is a single `push` to the provider list. No changes to the middleware or existing providers.

---

## 4. Fire-After-Commit Events

Events are published *after* the database write succeeds:

```rust
// In PassportService::publish()
let passport = self.repo.update(passport).await?;  // DB write
self.emit("dpp.passport.published", &auth.operator_id, &passport);  // Event
// If emit() fails: logged, NOT propagated. DB is source of truth.
```

**Why fire-after-commit:**
- The database is the source of truth. If the event publish fails, the passport is still published.
- If we published events *before* the DB write, a failed write would leave a dangling event.
- Consumers must be idempotent — events may be delivered more than once (at-least-once via NATS JetStream).

**Failure handling:** `emit()` catches all errors, logs them at WARN level, and continues. The passport operation succeeds regardless of event bus health.

---

## 5. Versioned Event Envelope

Every event carries a schema version:

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

**Why:** When the event payload shape changes (new fields, renamed fields), the version increments. Consumers can branch on `version` to handle both old and new shapes during migration. Without versioning, every consumer would break simultaneously on a payload change.

---

## 6. NoOp Fallback Pattern

Infrastructure dependencies that are optional use a NoOp implementation:

| Dependency | Real Implementation | NoOp Fallback |
|---|---|---|
| Event bus | `NatsEventBus` | `NoOpEventBus` (discards events) |
| Compliance | Wasm sector plugin | `PassthroughRegistry` (accepts all) |
| EU Registry | *(future)* | `GhostRegistrySync` (returns Pending) |

**Why:** Self-hosted single-node deployments should work without NATS. The NoOp pattern means the code paths are identical — no `if nats_enabled { ... }` branches. The trait dispatch handles it.

---

## 7. Localhost Inter-Service Communication

In the single-binary MVP, vault, identity, and integrator are separate Axum routers nested under one listener. They communicate via localhost HTTP:

```rust
// Vault calls identity for signing during publish
let identity_client = IdentityHttpClient::new("http://localhost:8001/identity");
let signed = identity_client.sign(passport_payload).await?;
```

**Why localhost HTTP instead of direct function calls:**
- Each service can be deployed independently later without code changes
- The HTTP contract is the same whether services are co-located or distributed
- Integration tests exercise the real HTTP layer, catching serialisation bugs

**Trade-off:** ~0.1ms overhead per localhost call. Acceptable for DPP operations (not latency-critical).

---

## 8. Job Store Pattern

Bulk imports use a two-phase pattern: synchronous validation + asynchronous processing.

```
1. POST /import/{sector} — validate file, create job (queued), return job_id
2. Background task processes rows (queued -> processing -> completed/failed)
3. GET /imports/{job_id} — poll for status and progress
```

Two implementations exist:
- `InMemoryJobStore` — for tests and single-request development
- `PgJobStore` — production, persists job state to `import_job` table

A background cleanup task runs every 6 hours, removing completed/failed jobs older than 30 days.
