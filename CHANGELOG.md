# Changelog

All notable changes to dpp-engine are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the pre-1.0 conventions in [VERSIONING.md](docs/governance/VERSIONING.md): a
**minor** bump may contain breaking changes, each listed below under a
**Breaking** heading with a migration note.

## [Unreleased]

## [0.4.0] - 2026-07-06

### Changed

- dpp-core dependency pins bumped to 0.6.0, adding `dpp-rules` (with the
  `bundle` feature) as a direct dependency — unblocks the signed
  Compliance-Current ruleset bundle loader (`dpp-node::infra::ruleset`,
  added in 0.3.0), which needs `dpp_rules::bundle` to verify and hot-swap
  bundles.

## [0.3.0] - 2026-07-04

### Fixed

- Passport literals in integration tests and vault code missing the `seal`
  field after the dpp-core 0.5.0 bump (`Passport.seal: Option<SealedEnvelope>`).

### Changed

- dpp-core dependency pins bumped 0.4.1 -> 0.5.0.

## [0.2.0] - 2026-07-03

### Added

- **Registry-sync outbox** (`dpp-types::RegistrySyncOutbox`,
  `dpp-dal::PgRegistrySyncRepo`, `dpp-node::infra::registry_drain`): a durable,
  drainable retry queue for EU registry registration. Each passport publish
  enqueues an outbox row; a drain worker registers due rows against
  `RegistrySyncPort`, records the terminal (`registered`/`rejected`) or
  transient (backoff) outcome, and surfaces drain-pass stats to metrics.
- **Tamper-evident audit hash chain** (migration `0015_audit_hash_chain.sql`,
  `dpp-types::audit`): every audit entry now carries `entry_hash` (SHA-256
  over the JCS-canonicalised entry content folded with `prev_hash`), linking
  it to its predecessor. Computed in the app so canonicalisation matches
  verification exactly; the existing append-only trigger already forbids
  UPDATE/DELETE, so the chain cannot be silently rewritten.
- **Ghost-honesty trust-tier guard** (`dpp-types::trust::NodeTrustReport`):
  every trust port (seal, registry sync, archive, …) reports the tier that
  produced it — `Ghost` (placeholder), `Sandbox` (real service, non-production),
  or `Live` — and a production node fails to boot if a required port resolves
  to a ghost. List-driven: a newly wired port only inherits the guard by being
  registered in `NodeTrustReport::ports`.
- **Compliance-Current signed ruleset bundle loader**
  (`dpp-node::infra::ruleset`): rulesets ship as versioned bundles whose
  manifest is signed (compact EdDSA JWS) by an offline publisher key distinct
  from any operator key. The node pins the publisher public key, verifies
  fail-closed, and can hot-swap the active bundle without a restart. The
  bundle format and fail-closed verification live in `dpp_rules::bundle`
  (dpp-core, Apache-2.0); this crate supplies the concrete verifier, signing,
  disk reads, and hot-swappable runtime state.
- **End-of-life declaration and transfer-of-responsibility handshake**
  (`dpp-vault::handlers::eol`, `handlers::transfer`, `dpp-dal::repo_transfer`;
  migrations `0016_deactivated_state.sql`, `0017_passport_transfer.sql`):
  operators can declare a passport's end-of-life (recycled / destroyed /
  exported / lost, with derogation citation where required) and hand off
  responsibility for a passport to another operator via a signed handshake.
- **Facility and operator-identifier retire-not-delete**
  (`dpp-vault::domain::registry_identity_service`, migration
  `0013_facility_retire.sql`): facilities and operator identifiers are retired
  rather than deleted, with append-only audit and enriched registry payloads,
  so a published passport's provenance survives retirement of its source
  facility or identifier.
- Production runbook (`docs/ops/PRODUCTION-RUNBOOK.md`) for running Odal Node
  with real operators.

### Fixed

- `RUSTSEC-2026-0194` (quick-xml) mitigated with an attribute-count precheck
  in the integrator.
- An intermittent false failure in the tampered-signature ruleset test.

### Changed

- dpp-core dependency requirement bumped to `^0.3.0`.

## [0.1.0] - 2026-07-01

Initial release of the dpp-engine workspace, on PostgreSQL as the primary
and only datastore.

### Added

- `/metrics` Prometheus endpoint and HTTP metrics middleware on the node.
- Postgres integration suite `pg_integration.rs` (T1–T5: round-trip parity,
  retention/audit immutability triggers, key-prefix uniqueness, patch-merge
  semantics) plus a dedicated CI lane. Single-tenant, no RLS.
- Wasm plugin host hardening: memory limiter and fail-closed
  `PLUGIN_SIGNING_KEY` validation at startup.
- `reqwest` on `rustls-tls` (no OpenSSL requirement in the node image).

#### dpp-types

- `OperatorConfig` and `UpdateOperatorConfig` types for operator management.
- `OperatorConfigRepository` trait for operator config persistence.
- `AuthContext` with `user_id`, `plan` fields (no operator scope — single-tenant).
- `AuthProvider` trait for pluggable authentication.
- `AuditEntry` with `operator_id` scoping.
- `ApiKey`, `ApiKeyRecord`, `ApiKeyRepository` trait (no operator scoping —
  namespace isolation provides the boundary).
- `STANDALONE_OPERATOR_ID` constant for single-operator MVP.

#### dpp-dal

- `PgDal` — PostgreSQL connection pool (sqlx, single-tenant, no RLS).
- `PgPassportRepo` implementing `PassportRepository` from dpp-core.
- `PgAuditRepo` for append-only audit trail.
- `PgOperatorConfigRepo` for operator config CRUD.
- `PgApiKeyRepo` for API key management.
- Schema migrations via `PgDal::migrate` (`ops/pg/0001_extensions_roles_schemas.sql` through `0012_registry_identity_grants.sql`).

#### dpp-vault

- 27 Axum HTTP endpoints for passport CRUD, operator config, facilities, operator identifiers, and API key management.
- `CompositeAuthProvider` chaining `ApiKeyAuthProvider` and `LocalAuthProvider`.
- `PassportService` orchestrating create, update, publish, suspend, archive.
- `OperatorService` for operator config get/upsert.
- `ApiKeyService` for key lifecycle (create, list, revoke).

#### dpp-identity

- 5 HTTP endpoints: health, ready, DID document, JWS signing, key rotation.
- `KeyStore` integration for Ed25519 key management.

#### dpp-integrator

- 4 HTTP endpoints: health, CSV template download, file upload import, job status polling.
- `InMemoryJobStore` for tests.
- Batch import pipeline with per-row validation and error reporting.

#### dpp-common

- `EventBus` trait with `DppEvent` versioned envelope.
- `NoOpEventBus` for deployments without NATS.
- Well-known event subjects (`dpp.passport.*`, `dpp.import.*`).
- RFC 7807 `HttpProblem` error type.

#### dpp-plugin-host

- Wasmtime-based sandbox for sector Wasm plugins.
- 10M fuel, 64 MiB memory, deny-all WASI.
- `ComplianceRegistry` implementation that dispatches to loaded plugins.
- Fallback to `PassthroughRegistry` when no plugin is available.

#### dpp-node

- Single-binary MVP assembling vault + identity + integrator on one port.
- `NatsEventBus` — NATS JetStream publisher with 7-day retention.
- `PgJobStore` — persistent job store backed by PostgreSQL.
- `NodeConfig` — unified env-based configuration.
- Background cleanup task for expired import jobs (every 6 hours).
- Wasm plugin host boot from `PLUGINS_DIR`.
- Smoke tests (Tier 1: no DB, Tier 2: testcontainers).

#### dpp-resolver

- 4 HTTP endpoints: health, ready, content-negotiated passport read, QR code PNG.
- Redis-backed cache.

#### ops

- PostgreSQL schema migrations in `ops/pg/0001_extensions_roles_schemas.sql` through `0012_registry_identity_grants.sql`.
- Docker Compose for dev infrastructure (PostgreSQL, Redis, NATS).
- `odal` CLI bootstrap flow (`odal bootstrap`) for operator config + first API key.
- `ops/demo/` — CSV/XLSX import fixtures and JSON samples.

[0.1.0]: https://github.com/odal-node/dpp-engine/releases/tag/v0.1.0
