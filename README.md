# Odal Node Engine

**Sovereign, self-hostable Digital Product Passport infrastructure**

[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-orange.svg)](LICENSE)
[![CI](https://github.com/odal-node/dpp-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/odal-node/dpp-engine/actions/workflows/ci.yml)
[![Rust 1.96+](https://img.shields.io/badge/Rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-green.svg)]()

The self-hostable runtime for Odal Node — HTTP services, PostgreSQL persistence, auth, telemetry, and compliance calculators: everything an operator needs to issue, sign, and serve EU-compliant Digital Product Passports on their own infrastructure. Self-hosting for your own compliance is permitted at no charge (see [LICENSE](LICENSE)).

Consumes [dpp-core](https://github.com/odal-node/dpp-core) (Apache-2.0) for domain types, crypto, and schema validation.

---

## The Golden Rule

> If code changes because of **how the system is deployed, run, or operated**, it belongs here.
> If code changes because an **EU regulation** changed, it belongs in dpp-core.

---

## Architecture

The engine ships as a **single binary** (`dpp-node`) that fuses all services under one Axum router, plus a separately deployed public resolver.

```
+---------------------------------------------------+
|              dpp-node (port 8001)                 |
|  +-----------+  +-------------+  +--------------+ |
|  |   vault   |  |  identity   |  |  integrator  | |
|  | /vault/*  |  | /identity/* |  | /integrator/*| |
|  +-----------+  +-------------+  +--------------+ |
|  +---------------------------------------------+  |
|  |         dpp-plugin-host (wasmtime)          |  |
|  +---------------------------------------------+  |
|  +---------------------------------------------+  |
|  |         dpp-dal (PostgreSQL)                |  |
|  +---------------------------------------------+  |
+---------------------------------------------------+

+---------------------------------------------------+
|       dpp-resolver (standalone, port 8003)        |
|   public QR / Digital Link resolver (JWS-verified)|
+---------------------------------------------------+
```

---

## Crate Map

| Crate | Type | Description |
|---|---|---|
| `dpp-types` | lib | Platform-wide types — operator config, auth, audit, API keys |
| `dpp-dal` | lib | PostgreSQL DAL — passport repo, migrations (single-tenant; no RLS) |
| `dpp-vault` | bin+lib | DPP write engine — create, version, sign, audit (27 endpoints) |
| `dpp-identity` | bin+lib | `did:web` identity HTTP service — signing, key rotation (5 endpoints) |
| `dpp-resolver` | bin+lib | Public QR / Digital Link resolver, JWS-verified (4 endpoints) |
| `dpp-integrator` | bin+lib | CSV/XLSX-to-DPP bulk import adapter (4 endpoints) |
| `dpp-common` | lib | Event bus trait, telemetry, config helpers, RFC 7807 HTTP errors |
| `dpp-plugin-host` | lib | wasmtime sandbox — fuel metering, memory cap, deny-all WASI |
| `dpp-node` | bin | **MVP single binary — fuses all services** |
| `dpp-cli` (`cli/`) | bin | `odal` — the operator control-plane CLI |
| `dpp-seal` *(not wired)* | lib | eIDAS qualified seal adapter — CSC/QTSP wire types + `QtspSealAdapter` stub |
| `dpp-factor-data` *(not wired)* | lib | Licensed LCI factor data store — `GhostFactorProvider` + `FactorStore` trait |

### Dependencies on dpp-core

All core crates are consumed from crates.io (dpp-core is published independently, version-pinned to `^0.4.1` — keep this line, the workspace `Cargo.toml`, and `.cargo/config.toml`'s sync note in agreement on every core bump; local dev can override to a sibling checkout via `.cargo/config.toml`, see `.cargo/config.toml.example`):

| Core Crate | Used For |
|---|---|
| `dpp-domain` | Domain types, port traits, schema validation |
| `dpp-crypto` | Ed25519 key management, JWS, DID builder, encrypted key store |
| `dpp-digital-link` | GS1 Digital Link parser |
| `dpp-calc` | EU-methodology calculators (CO2e, repairability) |
| `dpp-plugin-traits` | Wasm plugin ABI |
| `dpp-registry` | EU registry interface types |

**Dependency direction**: dpp-engine -> dpp-core (one-way). dpp-core has zero knowledge of this repo.

---

## Quick Start

**Requirements:** Rust 1.96+, Docker 24+, [just](https://github.com/casey/just)

```bash
git clone https://github.com/odal-node/dpp-engine.git
cd dpp-engine

# Start infrastructure (PostgreSQL, Redis, NATS)
docker compose -f docker/docker-compose.dev.yml up -d

# Build everything
cargo build --workspace

# Run the MVP node
cargo run -p dpp-node

# Run tests
cargo nextest run --workspace
```

The node starts on port **8001**. The resolver runs separately on port **8003**.

**Environment**: Copy the single root template — `cp .env.example .env`. It documents every backend var, grouped by deployable (node + resolver). The `web/` dashboard keeps its own `.env` (frontend secrets).

### Operate it with the `odal` CLI

The CLI is the operator control plane — onboarding through the full passport
lifecycle, all over the node's HTTP API:

```bash
cargo build -p dpp-cli                          # builds target/debug/odal
./target/debug/odal bootstrap                   # onboard operator + mint first API key
./target/debug/odal passport import ops/demo/datasets/09-battery-valid.csv
./target/debug/odal passport validate && ./target/debug/odal passport publish
```

Full command reference: **[cli/README.md](cli/README.md)**.

---

## Service Endpoints

### MVP Node (port 8001)

Routes are mounted by prefix: `/vault/*`, `/identity/*`, `/integrator/*` (see
`crates/dpp-node/src/router.rs`). The fused node mounts identity's
**public-only** router — the internal signing/key-rotation endpoints exist in
`dpp-identity` for **standalone** deployment only and are never network-reachable
here; the vault signs in-process instead (see `ATK-1` regression test).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/health` | None | Node |
| GET | `/vault/health` | None | Vault |
| GET | `/vault/ready` | None | Vault |
| GET | `/vault/api/v1/info` | None | Vault |
| GET | `/vault/public/dpp/{id}` | None | Vault |
| GET | `/vault/public/dpp/by-gtin/{gtin}` | None | Vault |
| POST | `/vault/api/v1/dpp` | Bearer | Vault |
| GET | `/vault/api/v1/dpps` | Bearer | Vault |
| GET | `/vault/api/v1/dpp/{id}` | Bearer | Vault |
| PUT | `/vault/api/v1/dpp/{id}` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/publish` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/suspend` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/archive` | Bearer | Vault |
| GET | `/vault/api/v1/dpp/{id}/history` | Bearer | Vault |
| GET | `/vault/api/v1/node/state` | Bearer | Vault |
| GET | `/vault/api/v1/operator` | Bearer | Vault |
| PATCH | `/vault/api/v1/operator` | Bearer (Admin) | Vault |
| GET | `/vault/api/v1/api-keys` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/api-keys` | Bearer (Admin) | Vault |
| DELETE | `/vault/api/v1/api-keys/{id}` | Bearer (Admin) | Vault |
| GET | `/vault/api/v1/facilities` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/facilities` | Bearer (Admin) | Vault |
| DELETE | `/vault/api/v1/facilities/{id}` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/facilities/{id}/default` | Bearer (Admin) | Vault |
| GET | `/vault/api/v1/operator-identifiers` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/operator-identifiers` | Bearer (Admin) | Vault |
| DELETE | `/vault/api/v1/operator-identifiers/{id}` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/operator-identifiers/{id}/primary` | Bearer (Admin) | Vault |
| GET | `/identity/health` | None | Identity |
| GET | `/identity/ready` | None | Identity |
| GET | `/identity/.well-known/did.json` | None | Identity |
| GET | `/integrator/health` | None | Integrator |
| GET | `/integrator/api/v1/templates/{sector}` | None | Integrator |
| POST | `/integrator/api/v1/import/{sector}` | Bearer | Integrator |
| GET | `/integrator/api/v1/imports/{job_id}` | Bearer | Integrator |

### Resolver (port 8003, standalone)

| Method | Path | Auth |
|---|---|---|
| GET | `/health` | None |
| GET | `/ready` | None |
| GET | `/dpp/{id}` | None — content-negotiated (HTML or JSON-LD via `Accept`) |
| GET | `/dpp/{id}/qr` | None |
| GET | `/01/{gtin}` | None — GS1 Digital Link resolution |

---

## Infrastructure

| Service | Port | Purpose |
|---|---|---|
| PostgreSQL | 5432 | Primary datastore (passports, audit; single-tenant, no RLS) |
| Redis | 6379 | Resolver response cache |
| NATS | 4222 | Event bus (optional — active when `NATS_URL` is set, NoOp otherwise) |

Docker Compose: `docker/docker-compose.dev.yml`

Migrations: `ops/pg/0001_extensions_roles_schemas.sql` through `0012_registry_identity_grants.sql` — applied via `PgDal::migrate` at startup if `DATABASE_MIGRATE_URL` is set.

---

## Open-Core Boundary

| Tier | Repository | License | Contents |
|---|---|---|---|
| **Odal Core** | `dpp-domain` | Apache-2.0 | Domain types, crypto, schemas, plugin ABI, port traits |
| **Odal Engine** | dpp-engine (this repo) | BSL-1.1 | HTTP services, database, auth, telemetry, calculators |

The `ComplianceRegistry` trait in `dpp-domain::ports` is a technical extension seam. Compliance calculation is open: the Wasm plugin registry and the `dpp-calc` calculators (CO2e, repairability) are all Apache-2.0 in dpp-core.

---

## Documentation

| Document | Description |
|---|---|
| [cli/README.md](cli/README.md) | `odal` CLI reference — the operator control plane |
| [docs/guides/DEVELOPER-GUIDE.md](docs/guides/DEVELOPER-GUIDE.md) | Run, test, and extend the engine |
| [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) | Service topology and request flow |
| [docs/architecture/DATA-MODEL.md](docs/architecture/DATA-MODEL.md) | Tables, migrations, and bootstrap |
| [docs/architecture/AUTH.md](docs/architecture/AUTH.md) | Authentication and authorisation |
| [docs/governance/CONTRIBUTING.md](docs/governance/CONTRIBUTING.md) | Repo layout and contribution flow |
| [docs/legal/LICENSING.md](docs/legal/LICENSING.md) | BSL-1.1 terms and the open-core boundary |

Architecture and design docs live in [dpp-core/docs/](https://github.com/odal-node/dpp-core/tree/main/docs) since they describe the standard, not the engine.

---

## Legal

- **License**: [Business Source License 1.1](LICENSE) (BSL-1.1)

---

## Security

Do **not** open public issues for security vulnerabilities. Report privately to **security@odal-node.io**.

---

*Odal Node — built by [Odal Node](https://odal-node.io)
