# dpp-engine Architecture

This is the architecture documentation index for dpp-engine, the self-hostable engine (BSL-1.1) of the Odal Node Digital Product Passport system.

## Architecture

| Document | Description |
|---|---|
| [Overview](OVERVIEW.md) | Service architecture, data flow, crate dependency graph |
| [Data Model](DATA-MODEL.md) | PostgreSQL schema, all tables, indexes, triggers |
| [Design Patterns](DESIGN-PATTERNS.md) | Serde-driven repos, composite auth, fire-after-commit, NoOp fallback |
| [Authentication](AUTH.md) | Auth middleware, API key provider, composite chain, adding providers |
| [Event Bus](EVENT-BUS.md) | DppEvent envelope, NATS JetStream, well-known subjects |
| [Database](DATABASE.md) | PostgreSQL pool, migrations, repository patterns |

## Governance

| Document | Description |
|---|---|
| [Changelog](../governance/CHANGELOG.md) | Release history |
| [Contributing](../governance/CONTRIBUTING.md) | Setup, coding conventions, PR workflow |
| [Developer Guide](../guides/DEVELOPER-GUIDE.md) | Local setup, env vars, running, testing, quality gate, troubleshooting |
| [Git Strategy](../governance/GIT-STRATEGY.md) | Trunk-based workflow, branch protection, tagging |
| [Governance](../governance/GOVERNANCE.md) | Decision-making structure, core purity rule |
| [Release](../governance/RELEASE.md) | Release checklist, Docker images, hotfix process |
| [Versioning](../governance/VERSIONING.md) | SemVer policy, API versioning, migration versioning |

## Legal

| Document | Description |
|---|---|
| [Licensing](../legal/LICENSING.md) | BSL-1.1 terms, core vs platform boundary, commercial licensing |

## Project

| Document | Description |
|---|---|
| [Blueprint](../project/BLUEPRINT.md) | Vision, guiding principles, MVP scope, roadmap |
| [Security](../project/SECURITY.md) | Vulnerability reporting, scope, auth security, Wasm sandbox |

## Key Principles

1. **The Golden Rule**: Regulation changes go in dpp-core. Deployment and runtime changes go in dpp-engine.
2. **Core Purity**: Platform adapts to core, never the reverse. No auth/audit/API-key concerns in core.
3. **Operator Isolation**: NEVER shared clusters. Every deployment is single-operator.
4. **Fire-After-Commit**: Database is the source of truth. Events are notifications.
5. **Standards First**: GS1 Digital Link, W3C VCs, did:web, NATS, PostgreSQL — all open.
