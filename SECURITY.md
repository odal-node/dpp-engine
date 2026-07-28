# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately to **security@odal-node.io** with:

1. A description of the vulnerability and its potential impact
2. Steps to reproduce or a minimal proof of concept
3. The affected crate(s) and version(s)
4. Any suggested fix or mitigation, if you have one

## What to Expect

| Step | Timeframe |
|------|-----------|
| Acknowledgement of your report | Within 48 hours |
| Initial assessment and severity classification | Within 5 business days |
| Fix or mitigation for critical/high severity | Within 14 days |
| Fix or mitigation for medium/low severity | Within 30 days |
| Public disclosure (coordinated with reporter) | After fix is released |

We follow coordinated vulnerability disclosure (CVD).

## Scope

This policy covers all crates in the dpp-engine workspace:

| Crate | Security-Relevant Surface |
|-------|---------------------------|
| **dpp-vault** | Authentication middleware, API key hashing, passport access control |
| **dpp-dal** | SQL query construction, input escaping, database credentials |
| **dpp-identity** | Ed25519 key management, JWS signing endpoints |
| **dpp-node** | Service assembly, NATS credentials, config loading |
| **dpp-integrator** | File upload handling, CSV parsing |
| **dpp-plugin-host** | Wasm sandbox boundaries, fuel/memory limits |
| **dpp-types** | Auth context, API key types |
| **dpp-common** | Event bus credentials |

Issues in the following areas are particularly important:

- Authentication bypass (accessing protected endpoints without valid credentials)
- API key hash timing attacks or lookup bypasses
- SQL injection in parameterized queries
- Wasm sandbox escape (plugin gaining host access)
- Private key leakage (Ed25519 keys exposed in logs, responses, or events)
- Privilege escalation (accessing another operator's data)

## Out of Scope

- Issues in dpp-core (report to the same email, but the core has its own security policy)
- Feature requests or non-security bugs (use GitHub Issues)

A small number of upstream advisories are accepted risk rather than out of
scope: the engine runs a dated, code-anchored suppression register
(`.cargo/audit.toml`, enforced by `scripts/check-audit-register.sh`). Every
entry states its reachability as a checked category — not in the dependency
graph, dev- or build-time only, reachable but mitigated by a named guard, or
reachable and accepted — plus the code fact that makes the category true, an
owner, and an expiry date after which CI fails until it is re-verified. The
categories are checked against both a default build and the feature set the
published image is built with, because a claim that holds only outside the
shipped artefact is not a claim about what operators run.

`.cargo/audit.toml` is the authoritative list, and this document deliberately
does not restate what is in it — including how many entries there are or
whether any is reachable. Read the file: every entry carries its own category,
evidence and expiry date. A summary here would be a second copy of a fact whose
home is that file, and it would go stale the first time an upstream fix lands.

If you believe a suppressed advisory is in fact exploitable, report it — the
register's own reachability claim may be wrong or stale, and that is exactly
the kind of report we want.

## Supported Versions

Only the latest tagged minor release receives security patches — see
[CHANGELOG.md](CHANGELOG.md) for the current version.

## Authentication Security

### API Key Storage

API keys are stored as SHA-256 hashes. The full key is never persisted.
The prefix (first 12 characters) enables efficient DB lookup without
scanning all keys.

### Credential Handling

- API keys, passwords, and Ed25519 private keys are never logged
- No dev/unsigned bypass auth provider ships. Integration tests define their
  own test-local auth stub rather than relying on a shipped bypass provider —
  see [AUTH.md §3.4](docs/architecture/AUTH.md#34-devauthprovider--removed-phase-0--audit-finding-v0)
- HTTP Basic auth credentials (`Authorization: Basic base64(user:pass)`) are
  read from `ADMIN_USERNAME`/`ADMIN_PASSWORD` environment variables, not
  from the database or configuration files, and are only ever matched
  against the `Basic` scheme — a Bearer token can never authenticate as
  local admin, see [AUTH.md §3.3](docs/architecture/AUTH.md#33-localauthprovider)

### PostgreSQL Access

- `PgDal` uses a connection pool with the app role (`odal_app`); credentials are
  loaded from `DATABASE_URL` at startup and never written to disk
- The app role cannot run DDL and cannot `DELETE` (one sanctioned exception).
  The node is single-tenant; there is no Row-Level Security, because
  isolation is an infrastructure boundary — one node per operator (ADR-005)
  — not an in-process one
- Migration credentials (`DATABASE_MIGRATE_URL`) are used only at startup and are
  not kept in the pool

## Wasm Plugin Security

Sector plugins run in a sandboxed Wasm environment:

| Capability | Status |
|---|---|
| Filesystem | DENIED |
| Network | DENIED |
| System random | DENIED |
| Threads | DENIED (single-threaded) |
| CPU | Capped via fuel metering (10M fuel) |
| Memory | Capped per instance (64 MiB) |

Plugins communicate only via JSON over Wasm linear memory. They cannot
access the host filesystem, network, or any other system resource.

## Security Tooling

Enforced in CI on every push, and by `just check` before a local commit:

- `cargo audit` plus `scripts/check-audit-register.sh` — checks dependencies
  against the RustSec Advisory Database, and that every accepted-risk entry
  in `.cargo/audit.toml` is current (dated, code-anchored, still reachable)
- `cargo clippy --workspace --all-targets -- -D warnings` — catches common
  correctness issues
- `cargo test --workspace` (via `cargo nextest`) — runs the full test suite

## Cryptographic Design

dpp-engine delegates all cryptographic operations to dpp-core (`dpp-crypto`).
The platform does not implement any custom cryptography. The only
crypto-adjacent operation in the platform is SHA-256 hashing of API keys,
which uses the `sha2` crate.

For the full cryptographic design, see the
[dpp-core Security Policy](https://github.com/odal-node/dpp-core/blob/main/SECURITY.md).

## Recognition

We credit security researchers in the CHANGELOG and release notes (unless
you prefer to remain anonymous). We do not currently operate a bug bounty
programme.
