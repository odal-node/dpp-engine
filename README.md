# Odal Node Engine

**Sovereign, self-hostable Digital Product Passport infrastructure**

[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-orange.svg)](LICENSE)
[![CI](https://github.com/odal-node/dpp-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/odal-node/dpp-engine/actions/workflows/ci.yml)
[![Rust 1.96+](https://img.shields.io/badge/Rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-green.svg)]()

The self-hostable runtime for Odal Node — HTTP services, PostgreSQL persistence, auth, telemetry, and the operational trust layer: everything an operator needs to issue, sign, serve, and *prove* EU-compliant Digital Product Passports on their own infrastructure. Self-hosting for your own compliance is permitted at no charge (see [LICENSE](LICENSE)).

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
| `dpp-vault` | bin+lib | DPP write engine — create, versioned lifecycle (publish / suspend / archive / end-of-life), transfer-of-responsibility handshake, hash-chained audit, evidence-dossier generation + verification |
| `dpp-identity` | bin+lib | `did:web` identity HTTP service — signing, key rotation |
| `dpp-resolver` | bin+lib | Public QR / Digital Link resolver, JWS-verified fail-closed |
| `dpp-integrator` | bin+lib | CSV/XLSX-to-DPP bulk import adapter with per-sector templates |
| `dpp-common` | lib | Event bus trait + well-known subjects, telemetry, RFC 7807 HTTP errors |
| `dpp-plugin-host` | lib | wasmtime sandbox — fuel metering, memory cap, deny-all WASI, signed-plugin policy |
| `dpp-node` | bin | **The single binary — fuses all services**, boot trust-report, registry outbox drain, signed-ruleset loader |
| `dpp-cli` (`cli/`) | bin | `odal` — the operator control plane, from bootstrap to evidence dossier generation and verification |
| `dpp-seal` | lib | eIDAS qualified-seal adapter (CSC/QTSP client scaffold) — resolves to a clearly-marked Ghost until a QTSP is configured; a production-profile node **refuses to boot** on ghost trust adapters |
| `dpp-factor-data` | lib | Licensed LCI factor store — ghost provider until a dataset licence is signed; any ghost-derived result is marked `dataset_id="ghost"` |

### Dependencies on dpp-core

All core crates are consumed from crates.io (dpp-core is published independently, version-pinned to `^0.10.0` — keep this line, the workspace `Cargo.toml`, and `.cargo/config.toml`'s sync note in agreement on every core bump; local dev can override to a sibling checkout via `.cargo/config.toml`, see `.cargo/config.toml.example`):

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

**Environment**: Copy the single root template — `cp .env.example .env`. It documents every backend var, grouped by deployable (node + resolver), including the trust-layer surface: `NODE_PROFILE` (a `production` node refuses to boot on placeholder trust adapters), `RULESET_BUNDLE_PATH` + `RULESET_PUBLISHER_PUBKEY` (signed compliance-ruleset channel), and the optional `EU_REGISTRY_*` / `ARCHIVE_S3_*` / `QTSP_*` adapter blocks.

### Operate it with the `odal` CLI

The CLI is the operator control plane — onboarding through the full passport
lifecycle, all over the node's HTTP API:

```bash
cargo build -p dpp-cli                          # builds target/debug/odal
./target/debug/odal bootstrap                   # onboard operator + mint first API key
./target/debug/odal passport import ops/demo/datasets/09-battery-valid.csv
./target/debug/odal passport validate && ./target/debug/odal passport publish
```

```bash
# Generate a signed evidence dossier and verify it against the node
./target/debug/odal passport evidence <dpp-id>   # generates + stores a dossier
./target/debug/odal verify <dossier-id>          # 8+ independent checks, exit 0 = verified
```

Full command reference: **[cli/README.md](cli/README.md)**.

---


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

Migrations: `ops/pg/0001_extensions_roles_schemas.sql` through `0021_evidence_dossier.sql` — applied via `PgDal::migrate` at startup if `DATABASE_MIGRATE_URL` is set. The audit table is append-only (DB trigger) and hash-chained (`0015`); the registry outbox (`0006`) is written inside the publish transaction and drained with backoff; evidence dossiers are append-only (`0021`).

---

## What Makes This Node Different (the trust layer, shipped)

**Honesty is enforced, not promised.** Every trust-critical port reports its tier (`ghost` / `sandbox` / `live`) in `/health`; under `NODE_PROFILE=production` the node **refuses to start** while any required port resolves to a placeholder — a node cannot claim trust services it doesn't have. **History is tamper-evident:** every audit entry is hash-chained; a superuser edit is detected at the exact index. **Registration is never lost:** EU-registry intent is committed to a durable outbox in the same transaction as publish, then drained with retry/backoff — kill the node mid-publish and nothing is lost (tested). **Regulation ships as signed data:** compliance rulesets arrive as Ed25519-signed bundles, verified fail-closed and hot-swapped atomically; the active version is visible in `/health`. **Evidence is generated and verified, not just claimed:** a signed dossier (passport, JWS, DID document, audit chain, transfer chain) is generated and stored in one call, then checked against its own signatures and hash chains via `odal verify` or the evidence API — see [docs/architecture/EVIDENCE-DOSSIER.md](docs/architecture/EVIDENCE-DOSSIER.md).

---

## Open-Core Boundary

| Tier | Repository | License | Contents |
|---|---|---|---|
| **Odal Core** | `dpp-domain` | Apache-2.0 | Domain types, crypto, schemas, plugin ABI, port traits |
| **Odal Engine** | dpp-engine (this repo) | BSL-1.1 | HTTP services, database, auth, telemetry, calculators |

The `ComplianceRegistry` trait in `dpp-domain::ports` is a technical extension seam. Compliance calculation is open: the Wasm plugin registry and the `dpp-calc` calculators (CO2e, repairability) are all Apache-2.0 in dpp-core.

---

## Documentation

**Start with the guided index: [docs/README.md](docs/README.md)** — grouped by question, with a three-document reading path for newcomers.

| Document | Description |
|---|---|
| [cli/README.md](cli/README.md) | `odal` CLI reference — the operator control plane |
| [docs/guides/DEVELOPER-GUIDE.md](docs/guides/DEVELOPER-GUIDE.md) | Run, test, and extend the engine |
| [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) | Service topology and request flow |
| [docs/architecture/DATA-MODEL.md](docs/architecture/DATA-MODEL.md) | Tables, migrations, and bootstrap |
| [docs/architecture/AUTH.md](docs/architecture/AUTH.md) | Authentication and authorisation |
| [docs/ops/PRODUCTION-RUNBOOK.md](docs/ops/PRODUCTION-RUNBOOK.md) | Running Odal Node for real operators — topology, hardening, backups, upgrades |
| [api/openapi.yaml](api/openapi.yaml) | HTTP surface specification |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Repo layout and contribution flow |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |
| [GOVERNANCE.md](GOVERNANCE.md) | Decision-making structure and maintainer authority |
| [CHANGELOG.md](CHANGELOG.md) | Release history, one entry per version |
| [docs/legal/LICENSING.md](docs/legal/LICENSING.md) | BSL-1.1 terms and the open-core boundary |

Architecture and design docs live in [dpp-core/docs/](https://github.com/odal-node/dpp-core/tree/main/docs) since they describe the standard, not the engine.

---

## Legal

- **License**: [Business Source License 1.1](LICENSE) (BSL-1.1)

---

## Security

Do **not** open public issues for security vulnerabilities. Report privately to **security@odal-node.io** — see [SECURITY.md](SECURITY.md) for full disclosure policy.

---

*Odal Node — built by [Odal Node](https://odal-node.io)
