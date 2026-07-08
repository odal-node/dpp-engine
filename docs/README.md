# dpp-engine Documentation — start here

This folder documents **running the product**: services, database, operations, security. The *standard itself* (data model, regulation mapping, crypto) is documented in [dpp-core/docs](https://github.com/odal-node/dpp-core/tree/main/docs) — the golden rule is that regulation-driven things live there, deployment-driven things live here.

## If you're new, read these three, in this order

1. **[architecture/OVERVIEW.md](architecture/OVERVIEW.md)** — service topology and the write/read request paths, end to end.
2. **[guides/DEVELOPER-GUIDE.md](guides/DEVELOPER-GUIDE.md)** — run it, test it, change it.
3. **[ops/PRODUCTION-RUNBOOK.md](ops/PRODUCTION-RUNBOOK.md)** — what "running this for a real operator" actually involves: topology, hardening, backups, upgrades, key custody.

## By question

| You're asking… | Read |
|---|---|
| "What services exist and how do requests flow?" | [architecture/OVERVIEW.md](architecture/OVERVIEW.md) · [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) |
| "What are the recurring engineering patterns here?" | [architecture/DESIGN-PATTERNS.md](architecture/DESIGN-PATTERNS.md) — repos, composite auth, fallbacks *and the honesty rule that governs them* |
| "How is data stored, migrated, bootstrapped?" | [architecture/DATA-MODEL.md](architecture/DATA-MODEL.md) · [architecture/DATABASE.md](architecture/DATABASE.md) |
| "How do auth and API keys work?" | [architecture/AUTH.md](architecture/AUTH.md) |
| "What events does the node emit, and how reliably?" | [architecture/EVENT-BUS.md](architecture/EVENT-BUS.md) |
| "How do I operate this in production?" | [ops/PRODUCTION-RUNBOOK.md](ops/PRODUCTION-RUNBOOK.md) · [ops/METRICS-PLAN.md](ops/METRICS-PLAN.md) |
| "What exactly is the HTTP surface?" | [../api/openapi.yaml](../api/openapi.yaml) |
| "What are the licence terms, really?" | [legal/LICENSING.md](legal/LICENSING.md) — BSL-1.1 with a genuine self-host grant · [legal/DPP-RETENTION.md](legal/DPP-RETENTION.md) |
| "What's built, what's next?" | [project/BLUEPRINT.md](project/BLUEPRINT.md) |

## What makes this node different (the 60-second version)

A **production node cannot lie about its trust level** — every trust-critical adapter reports `ghost`/`sandbox`/`live` in `/health`, and `NODE_PROFILE=production` refuses to boot on placeholders. **History is tamper-evident** — audit entries are hash-chained; edits are detected at the exact index. **Registration survives crashes** — EU-registry intent commits in the publish transaction to a durable outbox and drains with backoff. **Regulation arrives as signed data** — compliance rulesets are Ed25519-signed bundles, verified fail-closed, hot-swapped atomically. **Anyone can verify offline** — a signed evidence dossier exports in one call and verifies with zero network through the Apache-licensed `dpp-evidence` crate. Each of these is enforced by tests, not adjectives.
