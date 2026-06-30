# Contributing Guide

This document is for anyone contributing to `dpp-engine` — the self-hostable Odal Node engine. It covers setup, coding conventions, testing strategy, commit format, and the PR workflow.

---

## 1. Prerequisites

| Tool | Minimum Version | Install |
|---|---|---|
| Rust | see `rust-toolchain.toml` | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Docker | 24+ | https://docs.docker.com/get-docker/ |
| Docker Compose | v2 | Included with Docker Desktop |

Optional but recommended:

| Tool | Purpose |
|---|---|
| `cargo-nextest` | Fast parallel test runner: `cargo install cargo-nextest` |
| `cargo-audit` | Security advisory check: `cargo install cargo-audit` |
| `cargo-watch` | Auto-recompile on file change: `cargo install cargo-watch` |
| `just` | Command runner: `cargo install just` |

Docker is required for infrastructure (PostgreSQL, Redis, NATS).

---

## 2. Local Setup

```bash
git clone https://github.com/odal-node/dpp-engine.git
cd dpp-engine

# Start infrastructure
docker compose -f docker/docker-compose.dev.yml up -d

# Copy environment config
cp .env.example .env

# Build
cargo build --workspace

# Run tests (unit tests, no Docker needed)
cargo test --workspace

# Run integration tests (requires Docker for postgres:17 testcontainer)
cargo test -p dpp-node --features integration-tests

# Run the node
cargo run -p dpp-node
```

---

## 3. Workspace Structure

```
dpp-engine/
  Cargo.toml              # Workspace root — 10 member crates
  LICENSE                  # BSL-1.1
  docker/                  # Dockerfiles + compose (dev infra + prod stack)
  scripts/                 # install.sh (curl|bash bootstrap)
  ops/
    pg/                    # PostgreSQL DDL migrations (0001–0012_*.sql)
    demo/                  # CSV/XLSX import fixtures + JSON samples
  crates/
    dpp-types/             # Platform-wide types (operator, auth, audit, API keys)
    dpp-dal/               # PostgreSQL DAL (sqlx, single-tenant, no RLS)
    dpp-vault/             # Passport write engine (27 HTTP endpoints)
    dpp-identity/  # did:web identity service (5 endpoints)
    dpp-resolver/          # Public QR resolver (4 endpoints)
    dpp-integrator/        # CSV/XLSX bulk import (4 endpoints)
    dpp-common/            # Event bus trait, telemetry, RFC 7807
    dpp-plugin-host/       # Wasmtime sandbox for sector Wasm plugins
    dpp-node/              # MVP single binary
    dpp-seal/              # eIDAS qualified seal adapter stub (NOT YET WIRED)
    dpp-factor-data/       # Licensed LCI factor data store stub (NOT YET WIRED)
  cli/                     # Management CLI (the `dpp` control plane)
  web/                     # Dashboard (Next.js)
  docs/                    # Architecture and design documentation
```

### Dependency Rules

The dependency graph is strictly acyclic:

```
dpp-types        -> (standalone, no internal deps)
dpp-common       -> (standalone, no internal deps)
dpp-dal          -> dpp-types, dpp-domain (core)
dpp-vault        -> dpp-dal, dpp-types, dpp-common, dpp-domain (core)
dpp-integrator   -> dpp-types, dpp-common
dpp-node         -> dpp-vault, dpp-identity, dpp-integrator, dpp-common

# not yet wired into dpp-node:
dpp-seal         -> dpp-domain (core) [SealPort trait]
dpp-factor-data  -> dpp-calc (core)   [FactorProvider trait]
```

**Core purity rule**: No engine crate may modify `dpp-core` types or traits. The engine adapts to core, not the reverse.

---

## 4. Coding Conventions

### Serde and DB Column Naming

All DB columns and API responses use **camelCase** via `#[serde(rename_all = "camelCase")]` on structs. Exception: identity namespace tables use snake_case (legacy, accepted for MVP).

### Error Types

Service-layer crates use `DppError` from `dpp-domain`. Infrastructure crates map errors via `anyhow` and convert to `DppError` at the boundary.

### Logging

All crates use `tracing`. Never log secrets — API keys, private keys, and passphrases must never appear in log output.

### Clippy and Formatting

All code must pass:
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --all --check`

---

## 5. Testing Strategy

| Test type | Location | Scope |
|---|---|---|
| Unit test | `src/*.rs` (inline `#[cfg(test)]`) | Pure logic, validators, parsers |
| Integration test | `tests/` directory | Full HTTP lifecycle with testcontainers |

### Test Tiers

- **Tier 1 (no DB)**: Route mounting, health endpoints, auth middleware, config parsing. Run with `cargo test --workspace`.
- **Tier 2 (testcontainers)**: Full DPP lifecycle (create -> publish -> read) through the assembled node. Requires Docker. Run with `cargo test -p dpp-node --features integration-tests`.

---

## 6. Commit Format

All commits follow [Conventional Commits](https://www.conventionalcommits.org/) v1.0.0:

```
<type>(<scope>): <subject>
```

**Types:** `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `perf`, `security`

**Scopes:** `vault`, `dal`, `identity`, `integrator`, `node`, `types`, `common`, `resolver`, `ops`, `ci`, `docs`

**Examples:**
```
feat(vault): add operator config PATCH endpoint
fix(dal): normalise api_key repo query
docs(ops): rewrite seed data for new schema
chore(deps): upgrade axum to 0.8.2
```

Breaking changes use `!` after the scope: `feat(types)!: rename TenantConfig to OperatorConfig`.

### NEVER include AI attribution

Do not add `Co-Authored-By`, `Generated-By`, or any AI attribution tags in commit messages.

---

## 7. Pull Request Workflow

- Every change goes through a PR. No direct pushes to `main`.
- All CI checks must pass: build, test, clippy.
- PRs that modify port trait implementations must explain the core version targeted.
- PRs that add a new dependency must state why in the PR description.
- PR titles follow the same Conventional Commits format.

### Branch Names

```
feat/operator-config-endpoint
fix/api-key-hash-lookup
docs/architecture-suite
chore/upgrade-sqlx
```

---

## 8. Security Practices

- **No hardcoded secrets** anywhere, including tests. Use temp files with random names.
- **No `unsafe` code** without explicit justification.
- **Never log API keys or private keys.**
- **`cargo audit`** should pass before release.

Report security vulnerabilities to **security@odal-node.io** — do not open public issues.
