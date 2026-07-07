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
- Vulnerabilities in upstream dependencies (report to the dependency maintainer)
- Feature requests or non-security bugs (use GitHub Issues)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |

Only the latest release receives security patches.

## Authentication Security

### API Key Storage

API keys are stored as SHA-256 hashes. The full key is never persisted.
The prefix (first 12 characters) enables efficient DB lookup without
scanning all keys.

### Credential Handling

- API keys, passwords, and Ed25519 private keys are never logged
- The `DevAuthProvider` (unsigned JWT extraction) is only compiled when
  the `integration-tests` feature flag is enabled
- HTTP Basic auth credentials are read from environment variables, not
  from the database or configuration files

### PostgreSQL Access

- `PgDal` uses a connection pool with the app role (`odal_app`); credentials are
  loaded from `DATABASE_URL` at startup and never written to disk
- The app role cannot bypass Row-Level Security or run DDL
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

The following checks should be run before each release:

- `cargo audit` — checks dependencies against the RustSec Advisory Database
- `cargo clippy -- -D warnings` — catches common correctness issues
- `cargo test --workspace` — runs the full test suite

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
