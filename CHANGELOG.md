# Changelog

All notable changes to dpp-engine are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the pre-1.0 conventions in [VERSIONING.md](docs/governance/VERSIONING.md): a
**minor** bump may contain breaking changes, each listed below under a
**Breaking** heading with a migration note.

## [Unreleased]

### Added

- Signed sector-plugin hot-install: an admin can install or update a sector
  plugin at runtime with no node restart. The node verifies the artifact's
  detached signature against its pinned publisher key, gates the declared ABI,
  instantiate-smokes it, persists it so a restart re-loads the same set, and
  atomically hot-swaps it into service — fail-closed and last-good, so a rejected
  artifact never overwrites the live file or the running plugin. Both a portable
  `.wasm` (compiled on the node) and a precompiled `.cwasm` (loaded only if it
  matches this node's engine) are accepted.
- New endpoint: `POST /api/v1/plugins` (admin-scoped, `multipart/form-data`:
  `wasm` + `sig`, optional `sector`). New CLI: `odal plugin install <file>`
  (uploads the file and its sibling `<file>.sig`).

### Changed

- The plugin host now enforces ABI compatibility at load: a plugin whose
  declared ABI the running host cannot honour is refused (fail-closed) instead
  of being loaded and left to fail at dispatch. This applies to boot-time
  discovery as well as runtime install.

## [0.6.0] - 2026-07-13

This release consumes **dpp-core 0.8.0**, which adds the passport reference
types, the bounded graph cycle/depth check, and the schema-lens registry the
lineage, graph, and view features below build on.

### Added

- Second-life lineage: a passport may cite a `parentPassportRef` (its
  predecessor). The reference is verified by hash-pinning the referenced
  passport's published JWS — passports do not publish an issuer DID, so this is
  integrity-pinning, not signature verification. The resolver exposes the
  `predecessor`/`successor` linkset.
- Bill-of-materials graph: a passport may carry `componentRefs`.
  `GET /api/v1/dpp/{dppId}/verify-tree` walks the component tree recursively and
  verifies each node with bounded depth and node caps, path-based cycle
  detection (diamonds are not cycles), and fail-closed handling. Evidence
  dossiers embed and attest the component-graph report so tampering with it is
  detectable; the resolver exposes the `hasComponent` linkset.
- Schema views: `?schema_view=<version>` on the public reads (by id and by
  GTIN) serves the passport upcast through the registered schema lenses,
  returning `{ passport, schemaView }`.
- Evidence dossiers are now persisted: migration `0021_evidence_dossier.sql`
  adds an append-only `odal.evidence_dossier` table, backed by
  `PgEvidenceDossierRepo`.
- New evidence endpoints: `POST /api/v1/dpp/{dppId}/evidence` generates and
  stores a dossier; `GET /api/v1/evidence/{id}` fetches one; `POST
  /api/v1/evidence/{id}/verify` verifies a stored dossier; `POST
  /api/v1/evidence/verify` verifies an uploaded dossier document.
- `odal verify <dossier-id | file>` now verifies against the node instead of
  reading a local file only — same exit-code convention (0 verified, 1
  tamper, 2 unreadable/unparseable/unreachable).
- Signed outbound webhooks: operators register receiver URLs and the node POSTs
  each passport event to them, HMAC-SHA256 signed. Migration `0022_webhooks.sql`
  adds `odal.webhook_subscription` + a durable `odal.webhook_delivery` outbox,
  backed by `PgWebhookRepo`; a background drain delivers with backoff and
  survives restarts.
- New endpoints: `GET`/`POST /api/v1/webhooks`, `DELETE /api/v1/webhooks/{id}`,
  `POST /api/v1/webhooks/{id}/test` (admin-scoped). New CLI: `odal webhook
  list | add | remove | test`. See `docs/guides/WEBHOOKS.md` for receiver
  signature verification.
- New event `dpp.passport.transferred`, emitted on transfer initiate/accept so
  webhooks (and NATS) fire on handovers — previously transfer only wrote an
  audit entry.
- `WEBHOOK_ALLOW_PRIVATE_TARGETS` (default off): opt-in to deliver to private/
  loopback receivers on a self-hosted node. Off by default, an SSRF guard
  requires https + a public host.
- Fuzz and property tests: cargo-fuzz targets (`parse_csv`,
  `verify_dossier_json`) and proptest suites for the CSV parser, audit types,
  the outbound-URL SSRF guard, and component-graph grading.

### Changed

- An update that fails schema validation now returns `422 Unprocessable Entity`
  instead of `500 Internal Server Error`.
- The evidence dossier wire format (`DossierV1`, `DossierManifest`,
  `SignedLayer`) and the audit-trail wire type (`AuditEntry`) are now defined
  in this repo's `dpp-types` crate. The verification engine (signature,
  hash-chain, and transfer-chain checks) now lives in `dpp-vault`'s
  `domain::verify` module and verifies JWS signatures via `dpp-crypto`
  directly.
- `odal passport evidence <id>` now generates and stores a dossier (`POST`)
  instead of exporting one on the fly (`GET`).

### Removed

- The `dpp-evidence` crate dependency. Its dossier format and verification
  engine are dissolved into this repository (see Changed); the crate itself
  was removed from `dpp-core` and its crates.io release deleted.

### Breaking

- `GET /api/v1/dpp/{dppId}/evidence` now returns stored-dossier summaries
  instead of assembling a dossier on the fly. To get a dossier document,
  `POST` to the same path first, then `GET /api/v1/evidence/{id}`.
- `odal verify` requires a reachable node; it no longer verifies a local
  file with zero network.

## [0.5.0] - 2026-07-08

### Added

- **Evidence dossier export** (N02): `GET /vault/api/v1/dpp/{dppId}/evidence`
  assembles a self-contained, signed dossier proving a passport's full proof
  chain — both JWS signatures, DID document snapshots, the hash-chained audit
  trail, and (when present) the transfer chain and end-of-life record. New
  CLI: `odal passport evidence <id>`. Documented in `api/openapi.yaml`.
- **`odal verify <file>`**: verifies an evidence dossier fully offline using
  `dpp-evidence`'s `verify_dossier_json`, zero trust in the issuing node.
  Reports each check (`manifest_signature`, `content_integrity`,
  `full_view_signature`, `public_view_signature`, `audit_chain`,
  `transfer_chain`, `input_fidelity`, …) and exits 0 (verified), 1 (tamper
  detected), or 2 (not a valid dossier). Also available from the console's
  top-level `Verify` menu item.

### Changed

- `dpp-vault`/`dpp-types` now depend on `dpp-core`'s `dpp-evidence` crate
  (`dpp-evidence = "0.7.0"`) for the dossier wire format and the audit-trail
  type — `dpp-types::audit` re-exports `AuditEntry` from there instead of
  defining it locally (the hash-chain algorithm now has exactly one
  implementation, not a duplicate-by-doc-comment one).

### Breaking

- `IdentityPort` gains a new required method, `own_did_document`. Any custom
  `IdentityPort` implementation must add it.
- `AuditEntry::new`'s third parameter changes from `&AuthContext` to a plain
  actor string. *Migration:* `AuditEntry::new(id, action, auth, prev, new)` ->
  `AuditEntry::new(id, action, &auth.user_id, prev, new)`.

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
