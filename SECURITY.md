# Security policy

## Report a vulnerability

**Do not open a public issue.** Report privately through **Report a vulnerability** on this
repository's **Security** tab, or by email to **security@odal-node.io**, with:

1. What the vulnerability is and what it allows.
2. Steps to reproduce, or a minimal proof of concept.
3. The affected crates and versions.
4. A suggested fix or mitigation, if you have one.

## Response times

| Step | Target |
|---|---|
| Acknowledgement | 48 hours |
| Initial assessment and severity | 5 business days |
| Fix or mitigation, critical or high severity | 14 days |
| Fix or mitigation, medium or low severity | 30 days |
| Public disclosure | After the fix is released, coordinated with you |

We follow coordinated vulnerability disclosure.

## Scope

This policy covers every crate in the `dpp-engine` workspace:

| Crate | Security-relevant surface |
|---|---|
| `dpp-node` | Service assembly, boot checks, configuration, NATS credentials, mTLS on internal routes |
| `dpp-vault` | Authentication middleware, API key hashing, passport access control, evidence dossiers, webhook delivery |
| `dpp-dal` | SQL query construction, database credentials, role grants |
| `dpp-identity` | Ed25519 key management, JWS signing, `did:web` documents |
| `dpp-resolver` | Public, unauthenticated request handling; signature verification before serving |
| `dpp-render` | HTML rendering of passport content |
| `dpp-integrator` | File upload handling, CSV and XLSX parsing |
| `dpp-plugin-host` | Wasm sandbox boundaries, fuel and memory limits, plugin signature checks |
| `dpp-seal` | Seal backends, CMS envelopes, EU Trusted List verification |
| `dpp-types` | Auth context, API key types |
| `dpp-common` | Event bus credentials, the outbound URL guard (SSRF), RFC 9457 errors |
| `dpp-cli` (`odal`) | Local credential storage (`~/.config/odal/credentials.toml`, owner-only) |

Findings that matter most:

- Authentication bypass: reaching a protected endpoint without valid credentials.
- API key hash timing attacks or lookup bypasses.
- SQL injection.
- Wasm sandbox escape: a plugin gaining host access.
- Private key leakage: Ed25519 keys in logs, responses or events.
- Privilege escalation: a read-only or write key performing admin actions.
- Server-side request forgery through webhook targets, credential issuers or other
  outbound calls.

## Out of scope

- **Issues in `dpp-core`.** Report them to the same address; the core has its
  [own policy](https://github.com/odal-node/dpp-core/blob/main/SECURITY.md).
- **Feature requests and ordinary bugs.** Use GitHub Issues.

A few upstream advisories are accepted risk rather than out of scope. The engine keeps a
dated suppression register in `.cargo/audit.toml`, enforced by
`scripts/check-audit-register.sh`. Every entry states its reachability as a checked
category (not in the dependency graph; dev or build time only; reachable but mitigated by a
named guard; reachable and accepted), the code fact that makes the category true, an owner,
and an expiry date after which CI fails until it is re-checked. The categories are checked
against both a default build and the feature set the published image is built with,
because a claim that holds only outside the shipped artefact says nothing about what
operators run.

`.cargo/audit.toml` is the authoritative list. This document does not restate it,
including how many entries there are or whether any is reachable: every entry carries its
own category, evidence and expiry, and a summary here would go stale the first time an
upstream fix lands. If you believe a suppressed advisory is exploitable, report it; the
register's reachability claim may be wrong or out of date.

## Supported versions

Only the latest tagged minor release receives security fixes. [CHANGELOG.md](CHANGELOG.md)
names the current version.

## Authentication

### API key storage

API keys are stored as SHA-256 hashes; the full key is never persisted. The first 12
characters are kept as a prefix for an indexed lookup.

### Credential handling

- API keys, passwords and Ed25519 private keys are never logged.
- No development or unsigned bypass auth provider ships. Integration tests define their own
  test-only provider; see [AUTH.md](docs/architecture/AUTH.md).
- The local admin credential (`Authorization: Basic base64(user:pass)`) comes from the
  `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables, never from the database or a
  configuration file, and is matched only for the `Basic` scheme, so a Bearer token can
  never authenticate as local admin. With either variable unset, no Basic credential is
  accepted. The node refuses to start on known placeholder values.

### PostgreSQL access

- `PgDal` uses a connection pool with the app role (`odal_app`). Its credentials come from
  `DATABASE_URL` at startup and are never written to disk. The node refuses to start if
  that URL connects as a superuser.
- The app role cannot run DDL, and may `DELETE` only from the counter and queue tables
  listed under "The DELETE set" in [`ops/pg/README.md`](ops/pg/README.md), which
  `just grants-check` holds to the actual grants. No table holding passport, audit,
  evidence, seal or registry data has a `DELETE` grant.
- The node serves one operator, with no row-level security: isolation between operators is
  an infrastructure boundary (one node per operator), not an in-process one.
- Migration credentials (`DATABASE_MIGRATE_URL`) are used only at startup and are not kept
  in the pool.

## Wasm plugin sandbox

Product group plugins run in a sandboxed Wasm environment:

| Capability | Status |
|---|---|
| Filesystem | Denied |
| Network | Denied |
| System random | Denied |
| Threads | Denied (single-threaded) |
| CPU | Capped by fuel metering (10M fuel) |
| Memory | Capped per instance (64 MiB) |

Plugins communicate only through JSON in Wasm linear memory. A plugin must carry a valid
Ed25519 signature from `PLUGIN_SIGNING_KEY` to load; `ALLOW_UNSIGNED_PLUGINS=true` lifts
that only under `NODE_PROFILE=development`, and a production or sandbox node refuses to
start with it set.

## Security checks

In CI on every push, and in `just check` locally:

- `cargo audit` with `scripts/check-audit-register.sh`: dependencies against the RustSec
  Advisory Database, and every accepted-risk entry in `.cargo/audit.toml` current (dated,
  tied to code, still reachable). The advisory scan also runs daily on a schedule.
- `just lint`: clippy, every warning an error, over every target.
- The full test suite through `cargo nextest`, and the integration tiers in CI.
- Guard scripts, including the outbound URL guard (`outbound-check.sh`), the XML parser
  configuration (`no-xml-entity-resolution.sh`) and the database grants
  (`grants-check.sh`).

## Cryptography

Passport signing, JWS and the keystore come from `dpp-core` (`dpp-crypto`); see the
[dpp-core security policy](https://github.com/odal-node/dpp-core/blob/main/SECURITY.md).
The engine adds:

| Purpose | Mechanism | Crates |
|---|---|---|
| API key storage | SHA-256 | `sha2` |
| Webhook payload signatures | HMAC-SHA256 | `hmac`, `sha2` |
| Plugin and ruleset bundle signatures | Ed25519 verification | `ed25519-dalek` |
| Seal envelopes and certificates | CMS (CAdES), X.509 | `cms`, `x509-cert`, `der`, `rcgen` |
| EU Trusted List signatures | XMLDSig | `xml-sec` |

No primitive is implemented in this repository.

## Credit

Reporters are credited in the CHANGELOG and release notes unless they prefer to stay
anonymous. There is no bug bounty.
