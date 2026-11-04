# dpp-engine architecture

The index of architecture documents for `dpp-engine`, the self-hostable node (BSL-1.1) of
Odal Node.

## Architecture

| Document | What it covers |
|---|---|
| [Overview](OVERVIEW.md) | Services, data flow, crate dependencies |
| [Data model](DATA-MODEL.md) | PostgreSQL schema: tables, indexes, triggers |
| [Design patterns](DESIGN-PATTERNS.md) | Serde-driven repositories, composite auth, fire-after-commit events, fallbacks that report themselves |
| [Authentication](AUTH.md) | Auth middleware, API key provider, the composite chain, adding a provider |
| [Event bus](EVENT-BUS.md) | The `DppEvent` envelope, NATS JetStream, subjects |
| [Database](DATABASE.md) | Connection pool, migrations, repositories |
| [Evidence dossier](EVIDENCE-DOSSIER.md) | How a dossier is built and verified |
| [Standards](STANDARDS.md) | Every specification the engine cites, at which revision |

## Governance

| Document | What it covers |
|---|---|
| [Changelog](../../CHANGELOG.md) | Release history |
| [Contributing](../../CONTRIBUTING.md) | Setup, conventions, pull requests |
| [Developer guide](../guides/DEVELOPER-GUIDE.md) | Local setup, environment, running, testing, troubleshooting |
| [Git strategy](../governance/GIT-STRATEGY.md) | Trunk-based workflow, branch protection, tags |
| [Governance](../../GOVERNANCE.md) | Who decides, and the rule that the engine adapts to core |
| [Release](../governance/RELEASE.md) | Release checklist, container images, hotfixes |
| [Versioning](../governance/VERSIONING.md) | SemVer policy, API versioning, migration versioning |

## Legal

| Document | What it covers |
|---|---|
| [Licensing](../legal/LICENSING.md) | BSL-1.1 terms, the boundary with core, commercial licensing |
| [Retention](../legal/DPP-RETENTION.md) | How long a passport is kept, and why |

## Project

| Document | What it covers |
|---|---|
| [Blueprint](../project/BLUEPRINT.md) | Purpose, design rules, scope |
| [Security](../../SECURITY.md) | Reporting vulnerabilities, scope, auth, the Wasm sandbox |

## Principles

1. **Regulation in core, operation here.** A change driven by regulation goes into
   `dpp-core`; a change driven by deployment or runtime goes into `dpp-engine`.
2. **The engine adapts to core.** Never the reverse; no auth, audit or API-key concerns in
   core.
3. **One operator per deployment.** No shared clusters.
4. **Fire after commit.** The database is the source of truth; events are notifications.
5. **Open standards.** GS1 Digital Link, W3C Verifiable Credentials, `did:web`, NATS,
   PostgreSQL.
