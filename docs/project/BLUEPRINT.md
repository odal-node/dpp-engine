# Scope and principles

What `dpp-engine` is for, the rules its design follows, what is built, and what it will
not do. Feature status uses the labels of the public
[roadmap](https://odal-node.io/roadmap), which is the place to follow what changes.

## Purpose

`dpp-engine` turns the `dpp-core` library into a node an economic operator runs on its
own infrastructure to create, validate, sign, publish, version and serve EU Digital
Product Passports. Supplier and bill-of-materials data stays on the operator's servers;
no third party sees it.

## Principles

1. **One operator per node.** Each operator runs its own node and its own PostgreSQL.
   Isolation between operators is a deployment boundary; there is no in-process tenant
   scoping and no row-level security. ("Operator" is the economic operator of ESPR
   Art. 2, who is responsible for the passport.)
2. **The engine adapts to `dpp-core`, never the reverse.** Authentication, audit, API
   keys and operator administration stay in the engine. If a domain type must change,
   it changes in `dpp-core` first. Code that changes because a regulation changed
   belongs in `dpp-core`; code that changes because of how the node is deployed or
   operated belongs here.
3. **One process to run.** `dpp-node` combines the vault, identity and integrator
   services in one binary, started with `docker compose` or `odal up`. Each service
   keeps its own router and binary, so it can be split out later.
4. **Open standards first.** GS1 Digital Link for carriers, `did:web` and W3C
   Verifiable Credentials for identity and access, JWS for signatures, OpenAPI 3.1 for
   the HTTP contract, PostgreSQL and NATS JetStream for storage and events.
5. **The database is the source of truth.** Obligations that must not be lost (EU
   registry registration) are written to an outbox in the same transaction as the
   change. Events and webhooks are sent after commit and never fail the operation.
6. **Report what is not real.** Every trust adapter reports whether it is live, a
   sandbox or a stub, and a production profile refuses to start on a stub.

## What is built

**Available** (on `main`, tested):

| Area | What exists |
|---|---|
| Passport lifecycle | Create, validate (dry run), update drafts, publish, amend (successor), supersede, suspend, retire, end of life, transfer of responsibility |
| Signing and identity | Ed25519 JWS on publish, `did:web` document, key rotation that keeps old signatures valid |
| Disclosure | Per-field public, legitimate-interest and authority views; access credentials for legitimate-interest roles |
| History | Hash-chained append-only audit trail, version history per passport, evidence dossiers verifiable offline |
| Import | CSV and XLSX with templates per product group, row-level reports, dry run, delta matching |
| Compliance | Signed Wasm plugins per product group, plausibility lint, signed ruleset channel with hot swap |
| Regulatory catalog | Which product groups need a passport, from when, under which acts |
| Resolver | GS1 Digital Link resolution, HTML, JSON-LD and AAS views, QR codes, signature verification on every read |
| Operator administration | API keys with scopes, facilities, operator identifiers, webhooks, unsold-goods disclosure lines |
| Continuity | Signed pre-rendered snapshots of public pages in object storage |
| Operations | `odal` CLI and console, Prometheus metrics, trust mode reporting |

**Built, waiting on a legal step:**

| Item | Waiting on |
|---|---|
| Qualified electronic seals | A qualified seal certificate issued to the operator; sealing works end to end today with a self-generated, clearly unqualified certificate |
| EU registry registration | The registry's official interface; the outbox already records every registration |

**In progress, planned and considered:** see the [roadmap](https://odal-node.io/roadmap).
In short: more product identifier schemes, carbon and repairability figures in the
passport, import for the remaining product groups, selective disclosure credentials
(in progress); public container images and a one-command install, JavaScript and
TypeScript packages, a web dashboard (planned).

## Non-goals

- Shared clusters or multi-tenancy inside a node. The node is permanently single-tenant.
- Blockchain anchoring.
- A native mobile app.
- IoT sensor integration.
- Direct ERP connectors. Integration is through the HTTP API, webhooks and file import.
- Tracking of the people who scan a passport. Scan counts are aggregates with no
  per-person data.
- Anything that requires `dpp-core` to know about the engine.
