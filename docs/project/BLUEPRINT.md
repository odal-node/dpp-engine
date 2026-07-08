# Odal Node Engine — Blueprint

## Vision

dpp-engine is the production layer that turns dpp-core into a deployable
Digital Product Passport system. It provides everything an economic operator
needs to create, sign, publish, and serve DPPs in compliance with EU ESPR
requirements — with zero shared infrastructure between operators.

---

## Guiding Principles

### 1. Operator Isolation

Every deployment is single-operator. There are no shared clusters, no
cross-operator data paths. Each operator runs their own node with their own
PostgreSQL instance. Isolation is an infrastructure boundary (one node per
operator), not an application concern — there is no Row-Level Security.
Multi-operator hosting is provided by the Control Plane at the
infrastructure layer, never inside a node process.

This is an architectural invariant, not a configuration option. The term
"operator" comes from EU ESPR Article 2(17): the economic operator who
places a product on the EU market is responsible for its DPP.

### 2. Core Purity

The platform adapts to dpp-core, never the reverse. No platform concerns
(authentication, audit logging, API keys, operator management) may be pushed
into the core library. If a type or trait needs to change, it changes in
dpp-core first. The platform then updates its adapter implementations.

### 3. Self-Contained Binary

The MVP ships as a single binary (`dpp-node`) that fuses all services into
one process. No Kubernetes required. No service mesh. An operator can run
the entire system with `docker compose up` and a single Rust binary.

This does not prevent future decomposition — each service is already a
separate Axum router with its own state, communicating via localhost HTTP.

### 4. Standards Over Features

Technical decisions start from open standards:
- GS1 Digital Link for product identification and QR resolution
- W3C Verifiable Credentials for access control and manufacturer identity
- did:web for decentralised manufacturer identity
- NATS JetStream for event streaming (open-source, no vendor lock-in)
- PostgreSQL for persistence (open-source, self-hostable, single-tenant — no RLS)

### 5. Fire-After-Commit

The database is the source of truth. Events, webhooks, and external
notifications are published after the database write succeeds. If publishing
fails, the operation still succeeds. Consumers must be idempotent.

---

## MVP Scope (v0.1.0)

| Feature | Status | Notes |
|---|---|---|
| Passport CRUD (create, read, update, list) | Done | 7 endpoints |
| Passport lifecycle (publish, suspend, archive) | Done | State machine enforcement |
| Ed25519 signing on publish | Done | JWS compact serialisation via identity service |
| did:web DID document serving | Done | `/.well-known/did.json` |
| Key rotation | Done | Non-destructive, old signatures remain valid |
| API key authentication | Done | SHA-256 hash, prefix lookup |
| Local admin authentication | Done | HTTP Basic auth from env vars |
| Operator config management | Done | GET/PATCH endpoints |
| Operator identifiers (VAT, EORI, LEI) | Done | Database tables and seed data |
| Facility records | Done | ESPR Annex III (point (i)) |
| Audit trail | Done | Append-only, per-passport |
| CSV/XLSX bulk import | Done | Per-sector templates, async jobs |
| Event bus (NATS JetStream) | Done | Fire-after-commit, NoOp fallback |
| Wasm plugin compliance | Done | Sandboxed sector plugins |
| EU Central Registry sync | **Outbox done**; adapter ghost until spec | Registration intent committed in the publish transaction to the durable `registry_sync` outbox; background drain with backoff; `EuRegistrySync` HTTP adapter activates when the Commission publishes the Art. 13 API |
| Unsold goods reporting | Done | ESPR Arts. 24 (disclosure) / 25 (destruction ban, 19 Jul 2026); standardised disclosure format (implementing act of 9 Feb 2026) applies Q1 2027 — conformance pass pending (implementation plan 07) |
| End-of-life & transfer of responsibility | Done | Typed EOL declaration; dual-signed transfer handshake (initiate/accept, fail-closed verify); hash-chained audit |
| Evidence dossier export + offline verification | Done | `GET …/dpp/{id}/evidence` + `odal verify` via the Apache `dpp-evidence` crate — third parties verify with zero network |
| Trust-mode honesty (`NODE_PROFILE`) | Done | Per-port `trust_mode` in `/health`; production profile refuses to boot on ghost trust adapters |
| Signed compliance-ruleset channel | Done (loader) | Ed25519-signed bundles, fail-closed verify, atomic hot-swap; active version in `/health` |
| Public passport resolver | Done | Content-negotiated (JSON/HTML) |
| QR code generation | Done | Resolver endpoint |

---

## Post-MVP Roadmap

| Feature | Priority | Notes |
|---|---|---|
| Graph tables (component, material, supplier) | Phase 2 | Migration 007 is commented out |
| OAuth/OIDC authentication | Phase 2 | Add to composite auth chain |
| CO2e calculator (PEFCR depth + licensed factors) | Phase 2 | Baseline methodology **is implemented** in Apache `dpp-calc` (cradle-to-gate CO2e, repairability); Phase 2 = PEFCR-precise rulesets + real LCI factors via `dpp-factor-data` (licence-gated) |
| Repairability calculator (EU-methodology depth) | Phase 2 | Same: `dpp-calc` baseline shipped; Phase 2 deepens against the final delegated-act methodology |
| EU Central Registry integration | When API published | Replace GhostRegistrySync |
| Dashboard (Next.js) | Parallel | Separate directory, consumes vault API |
| Managed hosting (Control Plane) | v1.0.0 | One isolated node per operator; no in-engine multi-tenancy |
| Kubernetes deployment templates | Post-MVP | Helm charts |

---

## Non-Goals

The following are explicitly out of scope:

- Shared-cluster multi-tenancy (violates operator isolation principle)
- Application-level multi-operator support / in-process operator scoping — the node is permanently single-tenant; there is no multi-operator phase
- Blockchain anchoring
- Native mobile app
- IoT sensor integration
- AI/ML features
- Direct ERP connectors (CSV import is the integration strategy)
- Consumer tracking analytics
- Any code that requires dpp-core to know about the platform
