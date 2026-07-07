# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.


## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

## Git Commit Rules

1. Keep commit titles under 50 characters, using imperative tense (e.g., "add fix" not "added fix")
2. Use Conventional Commits format: `<type>(scope): <subject>`
   - feat: new feature
   - fix: bug fix
   - docs: documentation
   - refactor: code change that doesn't fix bugs or add features
   - chore: build/tooling changes
   - `scope` is the functional area touched (`docs`, `domain`, `dal`, `vault`, `node`, …) — never the repo name itself (no `(core)` in dpp-core, no `(engine)` in dpp-engine), since a repo's own history is already scoped to that repo
3. NEVER include `Co-Authored-By` or any AI attribution tags in commit messages
4. NEVER commit or push code without approval
5. NEVER commit before running the full check suite (`just check`) locally and confirming it is green — a commit is not ready because the code looks right, it is ready because the same gate CI runs has already passed
6. Do not reference internal planning taxonomy (roadmap phase letters, review chunk numbers, priority tags like N-1/P0/R-phase) in commit messages or in code/doc comments outside the planning docs themselves — describe what the change does, not which internal tracking item it closes

## Overview

**dpp-engine** is the self-hostable engine (BSL-1.1) for the Odal Node Digital Product Passport system. It consumes the pure core library (`dpp-core`, Apache-2.0) and adds HTTP services, database persistence, auth, event bus, Wasm plugin hosting, and operator management.

**The Golden Rule**: If code changes because of how the system is deployed, run, or operated, it belongs here. If code changes because an EU regulation changed, it belongs in `dpp-core`.

**Core Purity Rule**: NEVER push tenant, audit, API-key, or auth concerns into `dpp-core`. The platform adapts to core, not the reverse.

**Operator Isolation**: NEVER shared clusters. Every deployment is single-operator (self-hosted or Odal-hosted). Zero cross-operator data access. The node is **strictly single-tenant** — there is no in-process operator scoping (no RLS). Tenant isolation is an **infrastructure** boundary (one node per operator), not an application concern. `operator_id` columns persist only as the node's constant identity for provenance.

## Port Layout

```
PostgreSQL: 5432 (Docker) — PRIMARY datastore
Node:       8001 (MVP: vault + identity + integrator — set via PORT in .env)
Resolver:   8003 (standalone)
Redis:      6379 (Docker, resolver cache)
NATS:       4222 (Docker, event bus — optional)
Dashboard:  3000 (Next.js dev server — separate repo)
```

## Crate Layout (11 crates + CLI)

```
dpp-types                       — platform-wide types: operator config, auth, audit, API keys
dpp-dal                         — PostgreSQL DAL (src/pg/, sqlx; single-tenant, no RLS)
dpp-vault                       — passport write engine (27 Axum HTTP endpoints)
dpp-identity                    — did:web identity HTTP service (5 endpoints)
dpp-resolver                    — public QR resolver (4 endpoints, standalone)
dpp-integrator                  — CSV/XLSX bulk import (4 endpoints)
dpp-common                      — event bus trait, telemetry, config helpers, RFC 7807 errors
dpp-plugin-host                 — wasmtime sandbox for sector Wasm plugins
dpp-node                        — MVP single binary fusing vault + identity + integrator
dpp-seal                        — eIDAS qualified seal adapter: CSC/QTSP wire types + QtspSealAdapter stub (NOT YET WIRED into dpp-node)
dpp-factor-data                 — licensed LCI factor data store: GhostFactorProvider + FactorStore trait (NOT YET WIRED into dpp-node)
cli/                            — management CLI (clap)
```

### Dependency direction

```
dpp-core (external repo, Apache-2.0)
    ^
    |  (one-way: platform → core. Core has zero knowledge of platform.)
    |
dpp-types ←── dpp-dal ←── dpp-vault ←── dpp-node
                  ^              ^
                  |              └── dpp-identity ←── dpp-node
                  |
              dpp-integrator ←── dpp-node

dpp-common (event bus trait, telemetry) ←── dpp-vault, dpp-node
dpp-plugin-host ←── dpp-node
```

## Dependencies on dpp-core

All core crates are pinned to published registry versions in `[workspace.dependencies]`
(`dpp-domain = "0.1.0"`, …) — this is what CI and release builds use. For local
development, copy `.cargo/config.toml.example` to `.cargo/config.toml` (or run
`just core-local`) to add a `[patch.crates-io]` override that points each core crate
at the sibling `../dpp-core` working tree. That file is git-ignored, so it never
reaches CI; `just core-published` removes it to build against the registry again.
- `dpp-domain` — domain types (`Passport`, `SectorData`), port traits (`PassportRepository`, `IdentityPort`, `ComplianceRegistry`), schema validation
- `dpp-crypto` — Ed25519, JWS compact serialisation, DID document builder, encrypted key store
- `dpp-digital-link` — GS1 Digital Link parser
- `dpp-calc` — EU-methodology calculators (CO2e, repairability)
- `dpp-plugin-traits` — Wasm plugin ABI (wit-bindgen)
- `dpp-registry` — EU EUDPP Central Registry connector (stub: `GhostRegistrySync`)

## Build and Development

Requires Docker for infrastructure (PostgreSQL, Redis, NATS).

```sh
# Start infrastructure
docker compose -f docker/docker-compose.dev.yml up -d

# Copy environment config
cp .env.example .env

# Build
cargo build --workspace

# Run the MVP node
cargo run -p dpp-node

# Run tests
cargo test --workspace

# Run integration tests (requires Docker; Postgres testcontainer is primary)
cargo test -p dpp-node --features integration-tests

# Bootstrap a fresh node (operator config + first API key) via the CLI
cargo run -p dpp-cli -- bootstrap

# Clippy
cargo clippy --workspace
```

**Environment**: Copy `.env.example` to `.env` before running. Required vars: `DATABASE_URL`, `KEY_STORE_PATH`, `KEY_STORE_PASSPHRASE`, `DID_WEB_BASE_URL`.

## Architecture

### Single-Binary MVP (`dpp-node`)

`dpp-node` fuses vault, identity, and integrator into one Axum process on a single port. Sub-services share the same PostgreSQL connection pool and call each other via localhost HTTP.

Router nesting:
- `/vault/*` — passport write engine
- `/identity/*` — did:web identity management
- `/integrator/*` — CSV/XLSX bulk import
- `/health` — node-level health check

### Database

**PostgreSQL** accessed via `sqlx` through `PgDal` (connection pool). The app role (`odal_app`) cannot run DDL or (with one sanctioned exception) DELETE. Single-tenant: no Row-Level Security — one operator per node, so there is no in-process isolation boundary to enforce.

**Schema:** `ops/pg/0001`–`0010_*.sql` — a clean, FK-ordered, append-only migration set (extensions/roles → operator → api_key → passport → audit → registry_sync → import_job → unsold_goods → identity → grants), applied via `PgDal::migrate(url)` at boot using a privileged role, or pre-applied by ops tooling. No RLS (single-tenant).

**Repos:** `pg::PgPassportRepo`, `pg::PgAuditRepo`, `pg::PgApiKeyRepo`, `pg::PgOperatorConfigRepo` in `crates/dpp-dal/src/pg/`.

**Env vars:**
```
DATABASE_URL=postgres://odal_app:<pass>@host:5432/odal      # app role (no DDL/DELETE)
DATABASE_MIGRATE_URL=postgres://postgres:<pass>@host:5432/odal  # migration role (optional)
```

If `DATABASE_MIGRATE_URL` is unset, migrations are assumed pre-applied.

**Serde-driven repos**: All DAL repos serialise structs to JSONB for the `doc` column. Field mapping is handled by `#[serde(rename_all = "camelCase")]` on the structs. The `api_key` repo uses an internal `ApiKeyRow` struct for deserialisation because the DB row contains `keyHash` which is not part of the public `ApiKey` type.

### Auth

`CompositeAuthProvider` chains two providers:
1. `ApiKeyAuthProvider` — `Bearer odal_sk_...` (SHA-256 hash comparison against DB)
2. `LocalAuthProvider` — Basic auth (ADMIN_USERNAME/ADMIN_PASSWORD env vars)

There is **no** dev/unsigned-JWT provider in shipped code (the former `DevAuthProvider` was removed — it allowed an auth bypass). Integration tests define their own test-only provider.

All `/api/v1/*` vault routes are wrapped in `auth_middleware` which extracts `AuthContext { user_id, plan }` from the token and injects it into request extensions. Single-tenant: `AuthContext` carries no operator/tenant scope.

### Event Bus

`EventBus` trait lives in `dpp-common/src/event.rs` (infrastructure behaviour, NOT in `dpp-types` which is pure data).

**Versioned envelope** (`DppEvent`): every event carries `version: u32`, `eventId`, `eventType`, `timestamp`, `operatorId`, `data`. Prevents breaking consumers on schema evolution.

**Fire-after-commit**: Events emitted after DB write succeeds; publish failures logged but NEVER propagated. Database is the source of truth.

Implementations:
- `NoOpEventBus` (default when `NATS_URL` is absent) — discards silently
- `NatsEventBus` (in `dpp-node/src/infra/`) — publishes to NATS JetStream stream `DPP_EVENTS` with subject pattern `dpp.>`, 7-day retention, file storage

Subjects: `dpp.passport.{created,updated,published,suspended,archived,failed}`, `dpp.import.{completed,failed}`.

### Job Store

`JobStore` trait in `dpp-integrator/src/infra/job_store.rs`. Async import jobs (>100 rows) are tracked with status (`queued` → `processing` → `completed`/`failed`).

Implementations:
- `InMemoryJobStore` — tests and standalone integrator dev
- `PgJobStore` (in `dpp-node/src/infra/`) — production, persists to `import_job` table

Background cleanup task runs every 6 hours, deleting completed/failed jobs older than 30 days.

### Wasm Plugin Host

`dpp-plugin-host` loads `*.wasm` sector plugins from `PLUGINS_DIR`. Implements `ComplianceRegistry` from `dpp-domain::ports`. Sandbox: 10M fuel, 64 MiB memory, deny-all WASI. Falls back to `PassthroughRegistry` when no plugin is available for a sector.

## All HTTP Routes

### MVP Node (port 8001)

| Method | Path | Auth | Handler |
|--------|------|------|---------|
| GET | `/health` | None | Node health |
| GET | `/vault/health` | None | Vault health |
| GET | `/vault/ready` | None | Pings the primary datastore (PostgreSQL) |
| GET | `/vault/api/v1/info` | None | Build info |
| GET | `/vault/public/dpp/{dppId}` | None | Public passport read |
| GET | `/vault/public/dpp/by-gtin/{gtin}` | None | Public passport read by GTIN |
| POST | `/vault/api/v1/dpp` | Bearer | Create passport |
| GET | `/vault/api/v1/dpps` | Bearer | List passports |
| GET | `/vault/api/v1/dpp/{dppId}` | Bearer | Read passport |
| PUT | `/vault/api/v1/dpp/{dppId}` | Bearer | Update passport (draft only) |
| POST | `/vault/api/v1/dpp/{dppId}/publish` | Bearer | Publish (signs with Ed25519) |
| POST | `/vault/api/v1/dpp/{dppId}/suspend` | Bearer | Suspend |
| POST | `/vault/api/v1/dpp/{dppId}/archive` | Bearer | Archive |
| GET | `/vault/api/v1/dpp/{dppId}/history` | Bearer | Audit trail |
| GET | `/vault/api/v1/node/state` | Bearer | Node setup state (claimed / configured) |
| GET | `/vault/api/v1/operator` | Bearer | Get operator config |
| PATCH | `/vault/api/v1/operator` | Bearer | Update operator branding |
| GET | `/vault/api/v1/api-keys` | Bearer | List API keys |
| POST | `/vault/api/v1/api-keys` | Bearer | Create API key |
| DELETE | `/vault/api/v1/api-keys/{id}` | Bearer | Revoke API key |
| GET | `/vault/api/v1/facilities` | Bearer (admin) | List facilities (Annex III) |
| POST | `/vault/api/v1/facilities` | Bearer (admin) | Add a facility (validated GLN/country) |
| DELETE | `/vault/api/v1/facilities/{id}` | Bearer (admin) | Remove a facility |
| POST | `/vault/api/v1/facilities/{id}/default` | Bearer (admin) | Set the default facility |
| GET | `/vault/api/v1/operator-identifiers` | Bearer (admin) | List operator identifiers (Art. 13) |
| POST | `/vault/api/v1/operator-identifiers` | Bearer (admin) | Add an identifier (validated LEI/VAT/EORI/DUNS) |
| DELETE | `/vault/api/v1/operator-identifiers/{id}` | Bearer (admin) | Remove an operator identifier |
| POST | `/vault/api/v1/operator-identifiers/{id}/primary` | Bearer (admin) | Set the primary operator identifier |
| GET | `/identity/health` | None | Identity health |
| GET | `/identity/ready` | None | Identity ready |
| GET | `/identity/.well-known/did.json` | None | DID document |
| GET | `/integrator/health` | None | Integrator health |
| GET | `/integrator/api/v1/templates/{sector}` | None | CSV template download |
| POST | `/integrator/api/v1/import/{sector}` | Bearer (forwarded) | File upload import |
| GET | `/integrator/api/v1/imports/{job_id}` | Bearer | Poll job status |

> The node mounts identity via `build_public` — only the public `/identity/*`
> routes above. The internal `sign`/`keys/rotate` endpoints are **not** exposed
> by the node (it signs in-process via `LocalIdentityService`); they exist only
> on the standalone identity service below.

### Identity service (standalone, port 8002)

Runs as its own process only when identity is deployed separately from the node.
The internal endpoints are mTLS-gated (`CN=odal-vault`).

| Method | Path | Auth | Handler |
|--------|------|------|---------|
| GET | `/health` | None | Health |
| GET | `/ready` | None | Ready |
| GET | `/.well-known/did.json` | None | DID document |
| POST | `/internal/sign` | mTLS | JWS signing |
| POST | `/internal/keys/rotate` | mTLS | Key rotation |

### Resolver (standalone, port 8003)

| Method | Path | Auth | Handler |
|--------|------|------|---------|
| GET | `/health` | None | Health |
| GET | `/ready` | None | Ready |
| GET | `/dpp/{dppId}` | None | Content-negotiated (HTML or JSON-LD) |
| GET | `/dpp/{dppId}/qr` | None | QR code PNG |
| GET | `/01/{gtin}` | None | GS1 Digital Link resolver (redirect / linkset) |

## Serde Conventions

- **All DB columns**: camelCase throughout. No snake_case/camelCase inconsistencies.
- **Core `Passport` struct**: `#[serde(rename_all = "camelCase")]`
- **Platform types in `dpp-types`**: `#[serde(rename_all = "camelCase")]` on all structs
- **API responses**: camelCase JSON keys throughout
- **Event envelope**: camelCase (`eventId`, `eventType`, `operatorId`)
- **Exception**: Identity namespace tables (`did_document`, `key_pair`) use snake_case — left as-is for MVP

## Testing

```sh
# All unit tests (no Docker needed)
cargo test --workspace

# Integration tests (needs Docker; pg_integration.rs is the primary suite)
cargo test -p dpp-node --features integration-tests

# Clippy
cargo clippy --workspace
```

Test tiers:
- **Tier 1 (no DB)**: Route mounting, health endpoints, auth middleware, validators, parsers
- **Tier 2 (testcontainers)**: Full DPP lifecycle (create → publish → read) through the assembled node

## Known Tech Debt

1. **RFC 7807 Problem type**: `dpp-common::http_problem::Problem` is the standard error shape used by vault, integrator, identity, and resolver. mTLS and health handlers were the last holdouts; now fixed. All error surfaces use `Problem`.
2. **Single-tenant by design**: the node serves one operator (`STANDALONE_OPERATOR_ID`). Multi-tenancy is intentionally NOT an application concern — it is handled by the Control Plane at the infrastructure layer. Do not re-add operator scoping to the engine. The single-tenant constraint is currently enforced by documentation and infrastructure contracts, not Rust types — a future pass could encode it at the type level (e.g. a `SingleTenantMarker` phantom on the service) so the compiler rejects accidental cross-operator access. Not blocking for MVP.
3. **Graph tables deferred**: component/material/supplier graph modelling is not in the `ops/pg/*` migration set — Phase 2, when the component/material/supplier model is designed.
4. **Unused workspace dependencies**: Some dependencies declared in workspace `Cargo.toml` but not used yet. Kept as future placeholders.
5. **UUID v7 migration complete**: all `Uuid` generation uses `now_v7()` throughout both repos. `PassportId`, audit IDs, API key IDs, event IDs, and job IDs are all time-sortable. No `new_v4()` calls remain.
