# Engine Architecture Overview

This document describes the dpp-engine architecture: how the pure domain library (`dpp-core`) is wired into HTTP services, database persistence, authentication, event publishing, and Wasm plugin hosting to form a production Digital Product Passport system.

---

## 1. Architectural Philosophy

dpp-engine is the **adapter layer** in a Hexagonal Architecture. The domain logic lives in `dpp-core` (Apache-2.0). The engine implements the port traits defined there and adds everything needed to run the DPP system as a service: HTTP routing, PostgreSQL persistence (single-tenant; no RLS), API key authentication, event bus, and bulk import.

The invariant: **engine adapts to core, never the reverse.** If a type or trait needs to change, it changes in `dpp-core` first. The engine then updates its implementations. No engine concerns (auth, audit, API keys, operator management) leak into the core.

---

## 2. The Golden Rule

> If code changes because an EU regulation changed, it belongs in **dpp-core**.
> If code changes because of how the system is deployed or operated, it belongs in **dpp-engine**.

This separation keeps the regulatory implementation open-source, auditable, and free to use under Apache-2.0.

---

## 3. Operator Model

dpp-engine uses an **operator** model, not a tenant model. The term "operator" comes directly from EU ESPR Article 2(17): the natural or legal person who places a product on the EU market is the "economic operator" and is responsible for its Digital Product Passport.

Every deployment is single-operator. The node is **strictly single-tenant**: isolation is an **infrastructure** boundary (one node per operator), not an in-process one — there is **no Row-Level Security** and no operator scoping in queries. There are no shared clusters and no cross-operator data paths. Multi-operator isolation is provided by the Control Plane at the infrastructure layer, never inside a node process. This is an architectural invariant, not a configuration option.

The standalone MVP uses the constant `STANDALONE_OPERATOR_ID = "self_hosted"` as the node's constant operator identity for provenance — not an in-process scope.

---

## 4. Service Architecture

The MVP is a single binary (`dpp-node`) that assembles three services on one port:

```
                    +-----------------------+
                    |      dpp-node         |
                    |    (single binary)    |
                    +-----------+-----------+
                                |
              +-----------------+-----------------+
              |                 |                 |
     /vault/*           /identity/*       /integrator/*
              |                 |                 |
    +--------+------+  +-------+------+  +-------+--------+
    |   dpp-vault   |  | identity-svc |  | dpp-integrator |
    | Passport CRUD |  | did:web, JWS |  | CSV/XLSX import|
    | Auth middleware|  | Key rotation |  | Batch jobs     |
    +--------+------+  +-------+------+  +-------+--------+
              |                                   |
              +-----------------------------------+
              |
    +---------+---------+
    |      dpp-dal      |
    | PostgreSQL/sqlx   |
    | repos (no RLS)    |
    +-------------------+
```

Sub-services communicate via localhost HTTP (e.g., vault calls identity for signing during publish). They share a single PostgreSQL connection pool.

---

## 5. Data Flow

### Write Path (Create -> Publish)

```
1. Operator submits product data via POST /vault/api/v1/dpp
2. Auth middleware extracts AuthContext { user_id, plan } from Bearer token
3. Core schema validation runs via VersionedSchemaRegistry
4. Compliance check runs via ComplianceRegistry (Wasm plugin or passthrough)
5. Passport persisted to PostgreSQL via PgPassportRepo
6. On publish (POST /vault/api/v1/dpp/{id}/publish):
   a. Identity service signs passport with Ed25519 -> JWS compact serialisation
   b. retention_locked = true, status = active, qrCodeUrl generated
   c. Passport updated in DB
   d. Event emitted to NATS (fire-after-commit)
   e. Registration intent written to the durable registry outbox in the same
      transaction; a background drain retries with backoff — the HTTP adapter
      stays Ghost until the Commission publishes the Art. 13 registry API, so
      nothing is lost while waiting and publish never blocks on the registry
7. Later lifecycle: suspend / archive / end-of-life (typed reason) /
   transfer-of-responsibility (dual-signed handshake) — each appends to the
   hash-chained audit trail; a signed evidence dossier of the whole history
   is exportable at any time (GET /vault/api/v1/dpp/{id}/evidence)
```

### Read Path (QR Scan)

```
1. Consumer scans QR code on product
2. QR URL resolves to GET /vault/public/dpp/{dppId}
3. Passport fetched from PostgreSQL (no auth required for public read)
4. JWS signature can be verified against manufacturer's did:web DID document
5. Passport served as JSON
```

### Bulk Import Path

```
1. Operator uploads CSV/XLSX via POST /integrator/api/v1/import/{sector}
2. File parsed and validated row-by-row against sector schema
3. Each valid row becomes a POST to vault service (localhost HTTP)
4. Job tracked in JobStore with status (queued -> processing -> completed/failed)
5. Operator polls GET /integrator/api/v1/imports/{job_id} for progress
```

---

## 6. Crate Dependency Graph

```
dpp-core (external repo, Apache-2.0)
    ^
    |  (one-way: engine -> core. Core has zero knowledge of engine.)
    |
dpp-types <-- dpp-dal <-- dpp-vault <-- dpp-node
                  ^              ^
                  |              +-- dpp-identity <-- dpp-node
                  |
              dpp-integrator <-- dpp-node

dpp-common (event bus trait, telemetry) <-- dpp-vault, dpp-node
dpp-plugin-host <-- dpp-node

dpp-seal        (CSC/QTSP adapter scaffold — resolves to Ghost until a QTSP is
                 configured; a NODE_PROFILE=production node refuses to boot on it)
dpp-factor-data (licensed-LCI store — ghost provider until a dataset licence is
                 signed; ghost-derived results are marked dataset_id="ghost")
```

**Dependency rules:**
- `dpp-types` is pure data (no I/O, no async runtime)
- `dpp-common` is infrastructure behaviour (event bus trait, RFC 7807)
- `dpp-dal` implements core port traits against PostgreSQL
- Service crates (`dpp-vault`, `dpp-identity`, `dpp-integrator`) are Axum HTTP services
- `dpp-node` is the assembly point — it wires everything together

---

## 7. Infrastructure Dependencies

| Dependency | Required | Purpose |
|---|---|---|
| PostgreSQL | Yes | Primary data store (all tables; single-tenant, no RLS) |
| NATS JetStream | No (NoOp fallback) | Event bus for passport lifecycle events |
| Redis | No (resolver only) | Resolver cache (standalone resolver service) |
| Docker | Dev only | Runs PostgreSQL, NATS, Redis for local development |
