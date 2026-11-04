# Engine architecture overview

How `dpp-engine` wires the domain library (`dpp-core`) into HTTP services, PostgreSQL
persistence, authentication, event publishing and Wasm plugin hosting to make a running
Digital Product Passport node.

---

## 1. Ports and adapters

`dpp-engine` is the **adapter layer** of a hexagonal architecture. The domain logic lives
in `dpp-core` (Apache-2.0). The engine implements the port traits defined there and adds
what running the system as a service needs: HTTP routing, PostgreSQL persistence
(single-tenant, no row-level security), API key authentication, an event bus and bulk
import.

The rule: **the engine adapts to core, never the reverse.** If a type or trait has to
change, it changes in `dpp-core` first and the engine then updates its implementations.
Engine concerns (auth, audit, API keys, operator management) never move into core.

---

## 2. Where code belongs

> If code changes because an EU regulation changed, it belongs in **dpp-core**.
> If code changes because of how the system is deployed or operated, it belongs in
> **dpp-engine**.

That split keeps the regulatory implementation open source and free to use under
Apache-2.0.

---

## 3. Operator model

The engine uses an **operator** model, not a tenant model. The term comes from ESPR
Article 2: the natural or legal person who places a product on the EU market is the
economic operator responsible for its Digital Product Passport.

Every deployment serves one operator. The node is **strictly single-tenant**: isolation is
an **infrastructure** boundary (one node per operator), not an in-process one. There is no
row-level security, no operator scoping in queries, no shared cluster and no
cross-operator data path. Serving several operators means running several deployments.
This is a fixed property of the design, not a configuration option.

The node uses the constant `STANDALONE_OPERATOR_ID` as its operator identity for
provenance; it is not an in-process scope.

---

## 4. Services

The node is a single binary, `dpp-node`, that mounts three route groups on one port. The
resolver is a separate binary.

```text
                    +-----------------------+          +-------------------+
                    |      dpp-node         |          |   dpp-resolver    |
                    |   (single binary)     |<---------|  public, read-only|
                    +-----------+-----------+  public  +-------------------+
                                |              reads
              +-----------------+-----------------+
              |                 |                 |
          /vault/*        /identity/*       /integrator/*
              |                 |                 |
    +---------+------+  +-------+------+  +-------+--------+
    |   dpp-vault    |  | dpp-identity |  | dpp-integrator |
    | passport CRUD, |  | did:web doc, |  | CSV/XLSX       |
    | lifecycle,     |  | public routes|  | import jobs    |
    | auth middleware|  |              |  |                |
    +---------+------+  +--------------+  +-------+--------+
              |                                   |
              +-----------------+-----------------+
                                |
                      +---------+---------+
                      |      dpp-dal      |
                      | PostgreSQL / sqlx |
                      +-------------------+
```

The node signs in process, through `dpp_vc::LocalIdentityService`; it mounts only the
public identity routes. The integrator calls the vault over localhost HTTP. All of them
share one PostgreSQL connection pool.

---

## 5. Data flow

### Write path (create, then publish)

```text
1. A client sends product data: POST /vault/api/v1/dpp
2. Auth middleware puts an AuthContext { user_id, scope, key_id } on the request
3. Core schema validation runs through VersionedSchemaRegistry
4. The compliance check runs through ComplianceRegistry (Wasm plugin or passthrough)
5. The draft is stored in PostgreSQL through PgPassportRepo, with an audit entry
6. On publish (POST /vault/api/v1/dpp/{id}/publish):
   a. The passport is signed with the operator's Ed25519 key (compact JWS)
   b. retention_locked = true, status = active, the carrier URL (qrCodeUrl) is minted
   c. The passport update and the EU registry outbox row commit in one transaction
   d. An event is published to NATS after the commit
   e. A background drainer submits the outbox row with retry and backoff. With
      EU_REGISTRY_CLIENT_ID and EU_REGISTRY_CLIENT_SECRET set, it submits to the
      registry's sandbox; without them the adapter is a stub and submits nothing.
      Publishing never waits on the registry.
7. Later lifecycle: amend, supersede, suspend, retire, end of life (typed reason),
   and transfer of responsibility (a two-step handshake). Each appends to the
   hash-chained audit trail. POST /vault/api/v1/dpp/{id}/evidence generates and stores
   a signed evidence dossier of the whole history.
```

### Read path (QR scan)

```text
1. A consumer scans the digital link on the product, here a GS1 Digital Link:
   GET /01/{gtin}/21/{serial} on the resolver
2. The resolver redirects (307) to /dpp/{id}
3. The resolver reads the public view from the node (GET /vault/public/dpp/{id}) and the
   operator's DID document, and verifies the JWS before answering
4. The public view is served as HTML, JSON-LD or an AAS environment, by Accept header
```

### Bulk import path

```text
1. An operator uploads CSV or XLSX: POST /integrator/api/v1/import/{productGroup}
2. The file is parsed and validated row by row against the product group schema
3. Each valid row becomes a create call to the vault (localhost HTTP)
4. The job is tracked in a JobStore (queued, processing, completed or failed)
5. The operator polls GET /integrator/api/v1/imports/{job_id}
```

---

## 6. Crate dependencies

```text
dpp-core (separate repository, Apache-2.0)
    ^
    |  one way: the engine depends on core; core knows nothing about the engine
    |
dpp-types <-- dpp-dal <-- dpp-vault <-- dpp-node
                  ^                      ^  ^  ^
                  |      dpp-identity ---+  |  |
                  +--- dpp-integrator ------+  |
                                               |
dpp-common, dpp-plugin-host, dpp-render, dpp-seal ---+

dpp-resolver: dpp-common, dpp-render (and core crates)
dpp-factor-data: dpp-calc only; nothing depends on it yet
```

[CONTRIBUTING.md](../../CONTRIBUTING.md#dependencies) lists every edge.

- `dpp-types` is plain data, with no I/O and no async runtime.
- `dpp-common` is infrastructure behaviour: the event bus trait, RFC 9457 errors, metrics,
  idempotency, the outbound URL guard.
- `dpp-dal` implements core's port traits against PostgreSQL.
- `dpp-vault`, `dpp-identity` and `dpp-integrator` are Axum services.
- `dpp-seal` selects one seal backend from `SEAL_PROVIDER`: the experimental local
  development sealer, or a stub when unset. Neither has legal weight, and a
  `NODE_PROFILE=production` node refuses to start on either.
- `dpp-factor-data` is the licensed LCI factor store. Only a stub provider exists until a
  dataset licence is signed, and a result derived from it is marked `dataset_id="ghost"`.
- `dpp-node` wires everything together.

---

## 7. Infrastructure

| Dependency | Required | Purpose |
|---|---|---|
| PostgreSQL | Yes | Primary data store (single-tenant, no row-level security) |
| Redis | Yes, for the resolver | The resolver's response cache |
| NATS JetStream | No | Event bus for lifecycle events. Without `NATS_URL`, events are discarded |
| S3-compatible object storage | No | Back-up copy and continuity snapshots, when configured |
| Docker | For local development and the Compose stack | Runs PostgreSQL, Redis and NATS |
