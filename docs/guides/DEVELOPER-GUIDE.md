# Developer Guide — dpp-engine

Everything you need to understand, run, test, and extend the Odal Node platform —
in one place. If you read only one doc, read this.

> **Commands live in the [`justfile`](../../justfile).** Run `just --list` for the
> full menu; this guide shows the common ones and explains the *why*. Git workflow,
> branching, and PR rules live in [GIT-STRATEGY.md](../governance/GIT-STRATEGY.md)
> and [CONTRIBUTING.md](../governance/CONTRIBUTING.md).

---

## 1. What this is

Odal Node issues **EU Digital Product Passports**. It is two repos:

- **`dpp-core`** (Apache-2.0) — the standard in code: domain types, crypto/JWS,
  GS1, schemas, the `dpp-calc` calculators, and the **port traits** that define
  the platform boundary. Stateless; compiles with zero infrastructure.
- **`dpp-engine`** (this repo, BSL-1.1) — the deployable product: HTTP services,
  PostgreSQL persistence (single-tenant, no RLS), auth, event bus, the Wasm
  plugin host, the `odal` CLI.

**The Golden Rule:** code that changes because an *EU regulation* changed belongs
in `dpp-core`; code that changes because of *how the system is deployed, run, or
operated* belongs here.

## 2. Prerequisites

- **Rust** — stable toolchain (pinned by `rust-toolchain.toml`; MSRV is
  `rust-version` in the root `Cargo.toml`).
- **Docker** + **Docker Compose** — PostgreSQL (and optionally NATS, Redis) for
  running the node and the integration tests.
- **just** — command runner (`cargo install just`). `just --list` shows everything.
- **cargo-nextest** — test runner (`cargo install cargo-nextest`).
- **cargo-audit** — dependency vulnerability scanning (`cargo install cargo-audit`).

## 3. The shape of the platform

The MVP ships as **one binary, `dpp-node`**, fusing three services on one port
(8001) under sub-path routing, plus a separately-deployed resolver (8003):

```
dpp-node (:8001)
  /vault/*       passport write engine (create, version, sign, audit)
  /identity/*    did:web identity (DID document, in-process signing)
  /integrator/*  CSV/XLSX bulk import (async jobs)
  └── dpp-plugin-host (wasmtime)   sector compliance plugins
  └── dpp-dal (PostgreSQL/sqlx)    persistence, implements core port traits
dpp-resolver (:8003)   public QR/Digital-Link resolver (standalone, JWS-verifying)
```

**Crates** (9 + cli): `dpp-types` (platform data: operator/auth/audit/keys),
`dpp-dal`, `dpp-vault`, `dpp-identity`, `dpp-resolver`, `dpp-integrator`,
`dpp-common` (event bus trait, telemetry, RFC 7807), `dpp-plugin-host`,
`dpp-node` (the assembly), `cli`.

**Dependency direction is one-way:** platform → core. Core has zero knowledge of
the platform. Persistence is a set of **port-trait implementations** in `dpp-dal`
(`PassportRepository`, `IdentityPort`, etc., defined in `dpp-core::dpp-domain`).

## 4. Run it locally

```sh
just infra            # PostgreSQL :5432, Redis :6379, NATS :4222 (Docker)
cp .env.example .env  # then edit ADMIN_PASSWORD, KEY_STORE_PASSPHRASE, …
just node             # node on :8001 — auto-applies migrations on boot
```

Drive it with the `odal` CLI (full reference: [cli/README.md](../../cli/README.md)):

```sh
just cli -- bootstrap                                       # operator + first API key
just cli -- passport import ops/demo/datasets/09-battery-valid.csv
just cli -- passport validate
just cli -- passport publish
```

The build itself needs no infrastructure (`just build` / `cargo build --workspace`
compiles with no live connection); only *running* the node needs the database.

## 5. Environment variables

`.env.example` is the source of truth — copy it to `.env`. The essentials:

**Required**

| Variable | Example | Notes |
|---|---|---|
| `DATABASE_URL` | `postgres://odal_app:pass@localhost:5432/odal` | App role — no DDL. Single-tenant: no RLS. |
| `KEY_STORE_PATH` | `./dev-keystore.enc` | Encrypted Ed25519 key store |
| `KEY_STORE_PASSPHRASE` | `dev-passphrase` | Key store passphrase |
| `DID_WEB_BASE_URL` | `http://localhost:8001` | Base URL for did:web resolution |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / … | Local admin auth — lets `odal bootstrap` mint the first API key |

**Optional**

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_MIGRATE_URL` | *(none)* | Privileged role; if set, the node runs migrations at boot. Omit to pre-apply externally. |
| `NODE_PORT` | `8001` | Node listen port (`PORT` is a legacy fallback) |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / json | `LOG_FORMAT=pretty` for human-readable local logs |
| `NATS_URL` | *(none)* | NATS JetStream URL. Omit → NoOp event bus |
| `CORS_ALLOWED_ORIGINS` | *(none)* | Comma-separated origin list |
| `BATCH_CONCURRENCY` | `20` | Concurrent rows during bulk import |
| `PLUGINS_DIR` | `./plugins` | `.wasm` sector plugins; empty/missing → passthrough compliance |
| `METRICS_ADDR` | `127.0.0.1:9100` | Private Prometheus listener — **off** the public API port (set empty to disable) |

## 6. Test it

Commands are justfile recipes — `just --list` for all of them:

```sh
just test              # unit / CLI / resolver — no Docker
just test-integration  # testcontainers tiers (dal, vault, plugin-host, node) — needs Docker
just test-pg           # the pg_integration T1–T7 lane
just check             # local gate: fmt-check → lint → debug-check → test → audit
just ci                # check + integration-feature clippy + the Docker tiers
```

| Tier | Docker? | What it covers |
|---|---|---|
| Unit (`just test`) | No | Route mounting, health, auth middleware, config parsing, validators, resolver e2e |
| Integration (`just test-integration`) | Yes | Full DPP lifecycle through the assembled node, single-tenant persistence — against real `postgres:17` / `nats` containers via `testcontainers` |

**Discipline that matters:** a feature is not done until a test exercises it
against the running surface, and CI fails if that test is absent.

> ⚠️ The feature-gated integration tests (`#![cfg(feature = "integration-tests")]`)
> are **not** compiled or linted by `just check` — only by `just lint-integration`
> and `just ci`. Run those before trusting "green," or bugs can hide in test-only
> code that the standard gate never touches.

## 7. Data model & migrations

- **Schema** in `ops/pg/0001_extensions_roles_schemas.sql` through
  `0012_registry_identity_grants.sql` — a clean, FK-ordered set (extensions/roles → operator →
  api_key → passport → audit → registry_sync → import_job → unsold_goods →
  identity → grants → public-JWS-mutable → registry/identity grants). Applied via `PgDal::migrate(url)` at boot if
  `DATABASE_MIGRATE_URL` is set, or pre-applied by ops tooling. Schema only.
- The **bootstrap seed** (operator config, first API key) is **not** a migration —
  it is applied through `odal bootstrap` over the node API. Never a hand-run script.
- **Never edit an already-applied migration.** sqlx records each migration's
  checksum; changing an applied file trips the checksum guard on the next boot.
  Add a new numbered file instead. (In dev, `just reset-db` clears it — see
  Troubleshooting.)

## 8. Auth

The node's `CompositeAuthProvider` chains two providers:

1. **API key** — `Authorization: Bearer odal_sk_…` (SHA-256 hash compare).
2. **Local admin** — `Authorization: Bearer base64(user:pass)` against
   `ADMIN_USERNAME`/`ADMIN_PASSWORD`. The CLI's `bootstrap` uses this to mint the
   **first** key before any key exists. (The middleware only reads a `Bearer `
   scheme — plain HTTP `Basic` is rejected.)

Internal signing/key-rotation routes are **not mounted** on the public port
(red-team ATK-1 fix): the node signs **in-process** via a shared `KeyStore`.

## 9. Observability

### Logging

Set the log level via `LOG_LEVEL` (or `RUST_LOG` for per-crate filters):

```sh
LOG_LEVEL=info                       # production default — INFO+, JSON format
LOG_FORMAT=pretty just node          # human-readable terminal output for local dev
RUST_LOG=dpp_vault=debug,info just node   # per-crate granularity
```

Unset `LOG_FORMAT` (or any value other than `pretty`) → structured JSON, the
production default that Loki/Grafana expect.

### Metrics

The node exposes Prometheus metrics on a **private loopback listener**
(`METRICS_ADDR`, default `127.0.0.1:9100`) — deliberately **not** on the public
API port (red-team RT2-7), so operational telemetry isn't exposed to anyone who
can reach the API:

```sh
curl http://127.0.0.1:9100/metrics
```

Phase-0 golden set — every series that has an alert rule attached:

| Series | Labels | Alert trigger |
|---|---|---|
| `http_requests_total` | `route`, `method`, `status` | 5xx rate > 1% over 10 min |
| `http_request_duration_seconds` | `route`, `method` | — |
| `passport_publish_total` | `outcome` (success/error) | — |
| `signing_failures_total` | — | Any increment in 5 min → page |
| `jws_verify_total` | `outcome` (ok/tampered/disabled) | Tampered spike → page |
| `plugin_invocations_total` | `sector`, `outcome` | — |
| `plugin_fuel_exhausted_total` | `sector` | Any increment → review |
| `db_ping_duration_seconds` | — | `/ready` failing 3× → page |
| `cache_requests_total` | `result` | — |

`registry_queue_depth` is deferred to H1 (registry adapter not yet wired).

## 10. Extending the platform

- **Add a CLI command:** create `cli/src/commands/<name>.rs` exposing
  `run_<name>`, register it in `commands/mod.rs`, add the variant + match arm in
  `main.rs`. Talk to the node via `OdalClient` (`get`/`post_json`/`patch_json`/
  `delete`); never hit the database directly from the CLI.
- **Add a sector:** add `schemas/<sector>/vX.Y.Z.json` in `dpp-core`, the
  `SectorData` variant + validation, and (optionally) a Wasm plugin. The graph
  backbone is **sector-agnostic** — don't parameterise it per sector.
- **Add a calculator:** it computes EU methodology → it belongs in `dpp-core`'s
  `dpp-calc` (Apache-2.0), not here.

## 11. Conventions

- **Serde:** camelCase on the wire and in DB columns (exception: the identity
  namespace tables use snake_case — documented MVP debt).
- **Errors:** propagate, never swallow. A logged-but-unpropagated error hid a
  broken import-job and a fail-open JWS — both real incidents. If a write can
  fail, the caller must see it (e.g. `bootstrap` returns 500 rather than a fake
  job id).
- **Single operator:** every deployment is one operator (`STANDALONE_OPERATOR_ID`
  = `self_hosted`). No RLS — isolation is an infrastructure boundary (one node per
  operator). Multi-operator hosting is post-release via the Control Plane.
- **Compliance logic stays open** — all regulatory logic is Apache-2.0 in dpp-core.
- **Git workflow** (branches, commits, PRs, tags): see
  [GIT-STRATEGY.md](../governance/GIT-STRATEGY.md) and
  [CONTRIBUTING.md](../governance/CONTRIBUTING.md). Code style: rustfmt defaults,
  `thiserror` in libs / `anyhow` in binaries, no `unwrap`/`expect` in library paths.

## 12. Troubleshooting

- **`migration N was previously applied but has been modified`** — the dev DB
  holds a stale migration checksum. Reset it: **`just reset-db`** (drops the
  `pg-data` volume, recreates, re-applies clean). Don't edit applied migrations.
- **`Failed to bind … (os error 10048)` / address already in use** — a `dpp-node`
  is already running (it holds both `:8001` and the metrics `:9100`). Find it:
  `netstat -ano | grep -E ':8001|:9100'`; stop it: `taskkill //IM dpp-node.exe //F`
  (Windows/git-bash) or `Ctrl+C` in its terminal.
- **`failed to remove … dpp-node.exe (Access is denied / os error 5)`** during a
  test build — a running node locks the binary. Stop the node first; the
  integration tests don't need it running (they spin their own containers). To
  keep the node up, build the tests into a separate dir:
  `CARGO_TARGET_DIR=target-it just test-integration`.
- **Linux-only checks on Windows** — the plugin-host fuel-limit test SEH-aborts on
  Windows; run `just test-integration` under WSL2 (a real Linux kernel) or rely on
  CI. The same applies to performance/metrics numbers, which must be measured on a
  Linux box.

## 13. Where to look next

- [cli/README.md](../../cli/README.md) — full CLI command reference.
- `docs/architecture/` — OVERVIEW, DATA-MODEL, AUTH, EVENT-BUS, DESIGN-PATTERNS.
- [GIT-STRATEGY.md](../governance/GIT-STRATEGY.md), [CONTRIBUTING.md](../governance/CONTRIBUTING.md) — git workflow + contribution.
- `dpp-cor