# Changelog

All notable changes to dpp-engine are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Unreleased (release candidate)

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

[0.1.0]: https://github.com/od