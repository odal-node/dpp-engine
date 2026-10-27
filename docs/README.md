# dpp-engine documentation

These documents cover **running the node**: services, database, operations and security.
The regulatory model (data model, regulation mapping, cryptography) is documented with the
library, in [dpp-core/docs](https://github.com/odal-node/dpp-core/tree/main/docs). Guides
for operators and integrators are on [docs.odal-node.io](https://docs.odal-node.io).

## Start here

1. **[architecture/OVERVIEW.md](architecture/OVERVIEW.md):** the services and how write and
   read requests flow through them.
2. **[guides/DEVELOPER-GUIDE.md](guides/DEVELOPER-GUIDE.md):** run it, test it, change it.
3. **[ops/PRODUCTION-RUNBOOK.md](ops/PRODUCTION-RUNBOOK.md):** what running a node for a
   real operator involves: topology, hardening, backups, upgrades, key custody.

## By question

| Question | Read |
|---|---|
| Which services exist, and how do requests flow? | [architecture/OVERVIEW.md](architecture/OVERVIEW.md), [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) |
| What engineering patterns recur here? | [architecture/DESIGN-PATTERNS.md](architecture/DESIGN-PATTERNS.md): repositories, composite auth, and how fallbacks report themselves |
| How is data stored, migrated and bootstrapped? | [architecture/DATA-MODEL.md](architecture/DATA-MODEL.md), [architecture/DATABASE.md](architecture/DATABASE.md), [../ops/pg/README.md](../ops/pg/README.md) |
| How do auth and API keys work? | [architecture/AUTH.md](architecture/AUTH.md) |
| Which events does the node emit, and how reliably? | [architecture/EVENT-BUS.md](architecture/EVENT-BUS.md) |
| How are evidence dossiers built and checked? | [architecture/EVIDENCE-DOSSIER.md](architecture/EVIDENCE-DOSSIER.md) |
| Which standards does the code cite, at which revision? | [architecture/STANDARDS.md](architecture/STANDARDS.md) |
| What exactly is the HTTP surface? | [../api/openapi.bundled.yaml](../api/openapi.bundled.yaml) (OpenAPI 3.1), browsable at [docs.odal-node.io/api](https://docs.odal-node.io/api/); [../api/README.md](../api/README.md) explains how it is built |
| How are routes mounted in the node? | [project/ENDPOINTS.md](project/ENDPOINTS.md) |
| How do I set up and onboard an operator? | [guides/OPERATOR-SETUP.md](guides/OPERATOR-SETUP.md) |
| How do I run the demonstration? | [guides/DEMO-RUNBOOK.md](guides/DEMO-RUNBOOK.md) |
| How do outbound webhooks work? | [guides/WEBHOOKS.md](guides/WEBHOOKS.md) |
| How do I operate this in production? | [ops/PRODUCTION-RUNBOOK.md](ops/PRODUCTION-RUNBOOK.md), [ops/METRICS-PLAN.md](ops/METRICS-PLAN.md) |
| What are the licence terms? | [legal/LICENSING.md](legal/LICENSING.md), [legal/DPP-RETENTION.md](legal/DPP-RETENTION.md) |
| What is built, and what is out of scope? | [project/BLUEPRINT.md](project/BLUEPRINT.md) |
| How are releases cut and versioned? | [governance/RELEASE.md](governance/RELEASE.md), [governance/VERSIONING.md](governance/VERSIONING.md), [governance/GIT-STRATEGY.md](governance/GIT-STRATEGY.md) |

## What the node guarantees, in one paragraph

**Fail-fast startup:** every trust-critical adapter reports its mode (`ghost` for a stub,
`sandbox` or `live`) on the authenticated `GET /vault/api/v1/node/state` and as a
`trust_mode` gauge on the private metrics listener (the public `/health` reports liveness
only), and under `NODE_PROFILE=production` the node refuses to start while a required
adapter is a stub. **Tamper-evident history:** audit entries are hash-chained, so an edit
is detected at the exact entry. **Durable registration:** the EU registry submission is
written to an outbox in the same transaction as the publish, and drained with retry and
backoff. **Verifiable evidence:** a signed evidence dossier is generated and stored in one
call, then checked against its own signatures and hash chains with `odal verify` or the
evidence API. Tests enforce each of these.

The signed ruleset channel verifies Ed25519-signed bundles and refuses forged or stale
ones, but today a swap changes only the version the node reports: the rules that run are
compiled in. See `crates/dpp-node/src/infra/ruleset.rs`.
