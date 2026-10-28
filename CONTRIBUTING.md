# Contributing

How to build, test and change `dpp-engine`. For the organization-wide rules (issues first,
primary sources, conduct), see the
[organization guide](https://github.com/odal-node/.github/blob/main/CONTRIBUTING.md).
Documentation follows the
[documentation style guide](https://github.com/odal-node/.github/blob/main/DOCS-STYLE.md).

`dpp-engine` is licensed under BSL-1.1. Read [LICENSE](LICENSE) before you contribute.

## 1. Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust | pinned in `rust-toolchain.toml` | [rustup.rs](https://rustup.rs) |
| Docker with Compose v2 | 24+ | [docs.docker.com](https://docs.docker.com/get-docker/) |
| just | latest | `cargo install just` |
| cargo-nextest | latest | `cargo install cargo-nextest` |
| cargo-audit | latest | `cargo install cargo-audit` |
| cargo-deny | latest | `cargo install cargo-deny` |

Docker runs the local infrastructure (PostgreSQL, Redis, NATS) and the integration tests
(testcontainers). `just openapi-check` also needs Node.js.

## 2. Local setup

```bash
git clone https://github.com/odal-node/dpp-engine.git
cd dpp-engine
just infra              # PostgreSQL, Redis and NATS in Docker
cp .env.example .env    # then set KEY_STORE_PASSPHRASE
cargo run -p dpp-node   # the node, on port 8001
```

| Command | What it runs |
|---|---|
| `just check` | The local gate: format, clippy over every target (the Docker-gated suites included), the guard scripts, the spec-version check, unit tests, `cargo audit` and `cargo deny` |
| `just ci` | `just check` plus the Docker-backed integration tiers |
| `just test` | Unit tests (`cargo nextest`), no Docker |
| `just test-integration` | The Docker-backed integration tiers |
| `just openapi-check` | Lint the OpenAPI bundle and fail if it drifted from `api/` (needs Node) |
| `just openapi-bundle` | Regenerate `api/openapi.bundled.yaml` from the `api/` tree |
| `just core-local` / `just core-published` | Build against a sibling `../dpp-core` checkout, or back against crates.io |

`just --list` shows every recipe. Run `just check` before you push, not only `just test`:
`just test` never builds the feature-gated integration suites.

## 3. Workspace layout

```text
dpp-engine/
  Cargo.toml            workspace root: 12 crates and the CLI
  LICENSE               BSL-1.1
  api/                  the OpenAPI 3.1 description, authored multi-file and bundled
  docker/               Dockerfiles and Compose files (dev infrastructure, full stack)
  scripts/              the guard scripts `just check` and CI run
  ops/
    pg/                 PostgreSQL migrations, append-only and never renumbered
    bootstrap/          database role provisioning
    demo/               import fixtures, demo passports and evidence dossiers
  crates/
    dpp-node/           the node binary: router, boot checks, outbox drainers
    dpp-vault/          passport lifecycle, transfer, audit, evidence dossiers
    dpp-identity/       did:web documents, signing, key rotation
    dpp-resolver/       public digital link resolver
    dpp-render/         the HTML renderer for the public passport page
    dpp-integrator/     CSV/XLSX import
    dpp-dal/            PostgreSQL access (sqlx), single-tenant
    dpp-types/          operator, auth, audit and API-key types
    dpp-common/         event bus, RFC 9457 errors, metrics, idempotency
    dpp-plugin-host/    the wasmtime sandbox for product group plugins
    dpp-seal/           eIDAS seal backends behind the SealPort
    dpp-factor-data/    licensed LCI factor store (stub provider only; no dependent yet)
  cli/                  the `odal` CLI (package dpp-cli)
  docs/                 architecture, operations, governance
```

### Dependencies

Internal edges, from each crate's `[dependencies]` (core crates in parentheses):

```text
dpp-common       -> (none)
dpp-types        -> (dpp-domain, dpp-rules)
dpp-dal          -> dpp-common, dpp-types, (dpp-domain)
dpp-render       -> (dpp-digital-link)
dpp-seal         -> dpp-common, dpp-types, (dpp-domain)
dpp-plugin-host  -> dpp-common, (dpp-domain, dpp-plugin-traits)
dpp-integrator   -> dpp-common, dpp-types, (dpp-domain)
dpp-identity     -> dpp-common, (dpp-crypto, dpp-domain, dpp-vc)
dpp-vault        -> dpp-common, dpp-dal, dpp-types, (dpp-calc, dpp-crypto, dpp-digital-link, dpp-domain, dpp-registry, dpp-rules, dpp-vc)
dpp-resolver     -> dpp-common, dpp-render, (dpp-aas, dpp-crypto, dpp-digital-link, dpp-domain, dpp-vc)
dpp-node         -> dpp-common, dpp-dal, dpp-identity, dpp-integrator, dpp-plugin-host, dpp-render, dpp-seal, dpp-types, dpp-vault, (dpp-crypto, dpp-domain, dpp-registry, dpp-rules, dpp-vc)
dpp-factor-data  -> (dpp-calc)
dpp-cli          -> dpp-types, (dpp-crypto, dpp-vc)
```

**The engine adapts to `dpp-core`, never the reverse.** No engine change modifies core
types or traits. Tenant, audit, API-key and auth concerns stay in the engine. If a rule
changes because the law changed, it belongs in `dpp-core`; if it changes because of how
the system is deployed or operated, it belongs here.

## 4. Code conventions

### Serde and column naming

Database columns and API responses use **camelCase** through
`#[serde(rename_all = "camelCase")]`. The exception is the identity tables, which use
snake_case.

### Errors

HTTP errors are RFC 9457 problem documents (`dpp_common::http_problem::Problem`) on every
surface. Service code uses `DppError` from `dpp-domain`; infrastructure code maps errors
with `anyhow` and converts to `DppError` at the boundary.

### Identifiers

New identifiers are UUID v7 (`now_v7()`), so they sort by time.

### Logging

All crates use `tracing`. API keys, private keys and passphrases never appear in logs.

### Lints and formatting

Code passes `just lint` (clippy with warnings as errors, over every target, with the
Docker-gated suites' features on, as CI runs it) and `cargo fmt --all --check`.

## 5. Tests

| Kind | Where | Scope |
|---|---|---|
| Unit tests | inline `#[cfg(test)]` modules | Pure logic, validators, parsers |
| Integration tests | each crate's `tests/`, behind the `integration-tests` feature | Full HTTP lifecycle against PostgreSQL in testcontainers |
| CLI tests | `cli/tests/` | The `odal` binary as a child process: exit codes, output, the `config.toml` it writes |

- **Tier 1 (no database):** route mounting, health endpoints, auth middleware, config
  parsing. Runs in `just test`.
- **Tier 2 (testcontainers):** the full passport lifecycle (create, publish, read)
  through the assembled node. Needs Docker; runs in `just test-integration`.
- **CLI (no database, no node):** the `odal` binary run against a temporary `$HOME`,
  covering first-run messages, exit codes, the written `config.toml` and error rendering
  (the last against a local stub that returns an RFC 9457 body). Runs in `just test`.

Shared test scaffolding lives behind `dpp-dal`'s `test-harness` feature. Do not write
another Postgres harness; extend that one. `just harness-check` fails if you do.

If you document an error condition in `api/paths/`, write a test that produces it and
asserts the status.

## 6. Commits

[Conventional Commits](https://www.conventionalcommits.org/) v1.0.0:

```text
<type>(<scope>): <subject>
```

- **Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `ci`, `build`,
  `style`, `revert`. CI rejects a pull request title with any other type.
- **Scopes:** the area touched, for example `vault`, `dal`, `identity`, `integrator`,
  `node`, `types`, `common`, `resolver`, `seal`, `cli`, `ops`, `deps`, `ci`, `docs`. Never
  `engine` or `dpp-engine`.
- **Subject:** imperative mood, under 50 characters.
- **Breaking change:** `!` after the scope, for example
  `feat(types)!: rename TenantConfig to OperatorConfig`.
- **No AI attribution:** no `Co-Authored-By`, `Generated-By` or similar trailers.

```text
feat(vault): add operator config PATCH endpoint
fix(dal): normalise api_key repo query
docs(ops): rewrite seed data for new schema
chore(deps): upgrade axum to 0.8.2
```

Sign off every commit under the [DCO](https://developercertificate.org/):
`git commit -s`.

## 7. Pull requests

- Every change goes through a pull request. Nobody pushes directly to `main`.
- CI passes: build, tests, clippy, the guard scripts, the integration tiers.
- A change to a port implementation names the `dpp-core` version it targets.
- The pull request title is a Conventional Commit.

### New dependencies

A pull request that adds a **direct** dependency answers these in its description:

- **What it is for:** the specific need.
- **Which targets it compiles for:** anything platform-specific (build scripts, `libc` or
  system headers, proc-macro build cost).
- **Maintenance status:** last release, open advisories (`cargo audit`, `cargo deny
  check`), and whether one person or an established team maintains it.
- **Whether it touches untrusted input, secrets or the network.** This matters most. The
  engine's untrusted-input surfaces are: uploaded XLSX and CSV (`dpp-integrator`), Wasm
  plugin binaries (`dpp-plugin-host`), signed compliance rulesets, webhook targets, and
  resolver requests. A dependency on one of those paths is a different decision from one
  in the CLI's progress bar; say which it is.

This is a checklist for the description, not a CI check. It gives the reviewer the
context the author had when choosing the crate.

### Branch names

```text
feat/operator-config-endpoint
fix/api-key-hash-lookup
docs/architecture-suite
chore/upgrade-sqlx
```

## 8. Security practices

- **No hard-coded secrets**, including in tests. Use temporary files with random names;
  a test keystore uses `tempfile::tempdir()`.
- **No `unsafe` code** without explicit justification.
- **Never log API keys or private keys.**
- **`just audit`** (`cargo audit` and `cargo deny`) passes before release.

Report vulnerabilities privately to **security@odal-node.io**, never in a public issue.
See [SECURITY.md](SECURITY.md).
