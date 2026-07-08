# Platform Data Model

This document describes the **PostgreSQL** schema used by dpp-engine: all tables, their fields, indexes, and triggers. Authoritative DDL: `ops/pg/0001_extensions_roles_schemas.sql` through `0017_passport_transfer.sql` (including the hash-chained audit columns in `0015`, the end-of-life status in `0016`, and the transfer chain in `0017`).

---

## 1. Schema Layout

PostgreSQL organises the platform into two schemas:

| Schema | Purpose |
|---|---|
| `odal` | All platform tables (passports, config, keys, facilities, audit, import jobs, registry outbox) |
| `identity` | DID documents and key pairs for the identity service |

Storage model is **document-style**: the full serde JSON of a passport lives in a `doc JSONB` column; query/constraint-bearing fields (operator, sector, status, retention lock, version-chain columns) are real columns. The node is **single-tenant**, so there is **no Row-Level Security**: the app connects as the least-privilege `odal_app` role (no DDL, no DELETE bar one sanctioned exception), and `operator_id` columns persist only as the node's constant identity for provenance. Two database-level invariants back the domain rules: a **retention trigger** (locked passports reject content changes outside the mutable-field whitelist shared with the resolver) and an **append-only trigger** on the audit table.

---

## 2. Migration System

Migrations are SQL files in `ops/pg/`, applied apply-once with checksums via `sqlx::migrate!` (a tracking table replaces the old re-run-on-every-boot model — schema *changes*, not just additions, are now expressible). DDL runs under a privileged role (`DATABASE_MIGRATE_URL` or pre-applied by ops); the app role cannot run DDL.

**Current migrations (12 files, FK-ordered):**

| File | Creates | Schema |
|---|---|---|
| `0001_extensions_roles_schemas.sql` | extensions, roles, schemas (`odal`, `identity`) | — |
| `0002_operator.sql` | `operator_config`, `operator_identifier`, `facility` | `odal` |
| `0003_api_key.sql` | `api_key` | `odal` |
| `0004_passport.sql` | `passport` (+ retention trigger) | `odal` |
| `0005_passport_audit.sql` | `passport_audit` (+ append-only trigger) | `odal` |
| `0006_registry_sync.sql` | `registry_sync` (outbox) | `odal` |
| `0007_import_job.sql` | `import_job` | `odal` |
| `0008_unsold_goods_report.sql` | `unsold_goods_report` | `odal` |
| `0009_identity.sql` | `did_document`, `key_pair` | `identity` |
| `0010_grants.sql` | role grants for `odal_app` | — |
| `0011_public_jws_mutable.sql` | adds `publicJwsSignature` to the retention guard's mutable-field whitelist | `odal` |
| `0012_registry_identity_grants.sql` | `DELETE` grants for `facility` / `operator_identifier` (control-plane management) | `odal` |
| `0013_facility_retire.sql` | facility soft-delete (`retiredAt` + partial unique), revoke facility `DELETE`, append-only `registry_identity_audit` | `odal` |
| `0014_operator_identifier_retire.sql` | operator-identifier soft-delete (`retiredAt` + partial unique), revoke its `DELETE` | `odal` |

Graph tables (component/material/supplier modelling) are deliberately absent — Phase 2, when that model is designed.

---

## 3. Table Definitions

### 3.1 operator_config

Operator profile and branding. One record per deployment (single-operator MVP).

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | UNIQUE index; node's constant provenance identity (single-tenant — not a scoping key) |
| `legalName` | string | Registered company name |
| `tradeName` | string | Trading/display name |
| `address` | string | Registered address |
| `country` | string | ISO 3166-1 alpha-2 |
| `contactEmail` | string | Operator contact email |
| `didWebUrl` | string | did:web identifier |
| `productCategories` | array | Supported sectors (BATTERY, TEXTILE, etc.) |
| `brandPrimary` | string | Primary brand colour (hex) |
| `brandSecondary` | string | Secondary brand colour (hex) |
| `brandLogoUrl` | string | Logo URL |
| `customDomain` | string | Custom resolver domain |
| `dataResidency` | string | DEFAULT "EU" |
| `retentionPolicyDays` | int | DEFAULT 3650 (10 years) |
| `featureFlags` | object | Feature toggles |
| `createdAt` | datetime | |
| `updatedAt` | datetime | |

**Indexes:** `idx_opconf_operator` UNIQUE on `operatorId`.

### 3.2 operator_identifier

Normalised economic operator identifiers (VAT, EORI, LEI). One operator can have multiple identifiers across different schemes.

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | FK to operator_config |
| `scheme` | string | Identifier scheme (vat, eori, lei, duns, gln) |
| `value` | string | Identifier value |
| `label` | string | Human-readable label |
| `isPrimary` | bool | Whether this is the primary identifier |
| `createdAt` | datetime | |
| `retiredAt` | datetime | nullable; set = soft-deleted. Like facilities, the value is stamped by value onto immutable passports (Art. 13), so the row is never hard-deleted. `DELETE` is revoked for the app role (0014). |

**Indexes:** `uq_operator_identifier_live` UNIQUE on `(operatorId, scheme, value)` **where `retiredAt IS NULL`** — a retired identifier can be re-registered.

### 3.3 facility

ESPR Annex III facility records (first paragraph, point (i): unique facility identifier; point (c): identifier standards, e.g. GS1 GLN). Each facility is a physical manufacturing or processing site.

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | FK to operator_config |
| `name` | string | Facility name |
| `identifierScheme` | string | national, gln, internal |
| `identifierValue` | string | Facility identifier |
| `country` | string | ISO 3166-1 alpha-2 |
| `address` | string | Full address |
| `isDefault` | bool | Default facility for new passports |
| `createdAt` | datetime | |
| `updatedAt` | datetime | |
| `retiredAt` | datetime | nullable; set = soft-deleted. Facilities are **never** hard-deleted — their identifier is stamped by value onto immutable passports, so the row is kept as Annex III provenance. `DELETE` is revoked for the app role (0013). |

**Indexes:** `uq_facility_identifier_live` UNIQUE on `(identifierScheme, identifierValue)` **where `retiredAt IS NULL`** — two *live* facilities cannot share an identifier, but a retired one can be re-registered.

### 3.3a registry_identity_audit

Append-only trail of facility (Annex III) and operator-identifier (Art. 13) mutations, so the operator can prove what their registry-identity set was when any passport was published. Immutable by trigger (`ODAL_AUDIT`), like `passport_audit`.

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | node provenance identity |
| `entityType` | string | `facility` \| `operator_identifier` |
| `entityId` | uuid | the facility / identifier acted on |
| `action` | string | `added` \| `retired` \| `set_default` \| `set_primary` |
| `actor` | string | `user_id` from the auth context |
| `snapshot` | object | nullable, the full record at the time of the action |
| `ts` | datetime | |

### 3.4 api_key

API key records for Bearer authentication. Keys are stored as SHA-256 hashes.

| Field | Type | Notes |
|---|---|---|
| `name` | string | Human-readable key name |
| `keyHash` | string | SHA-256 hash of the full key |
| `keyPrefix` | string | First 12 chars of the key (for lookup) |
| `scopes` | array | Permission scopes (["*"] for full access) |
| `isActive` | bool | Whether the key is usable |
| `createdAt` | datetime | |
| `lastUsedAt` | datetime | nullable |
| `expiresAt` | datetime | nullable |

No operator scoping on this table — the node is single-tenant; isolation is an infrastructure boundary (one node per operator).

### 3.5 passport

The core DPP record. Contains all product data, sector-specific extensions, and lifecycle state.

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | Owner operator |
| `schemaVersion` | string | Semver schema version |
| `status` | string | draft, active, suspended, archived |
| `productName` | string | Product display name |
| `productCategory` | string | BATTERY, TEXTILE, STEEL |
| `manufacturer` | object | { name, address } |
| `materials` | array | Material composition entries |
| `co2ePerUnit` | float | nullable |
| `repairabilityScore` | float | nullable |
| `sectorData` | object | Sector-specific extension data |
| `batchId` | string | nullable |
| `facility` | object | nullable, a self-contained **snapshot** `{ scheme, value, name, country, address }` of the Annex III facility, copied by value from the `isDefault` facility on create — **not** a row FK. The passport carries the full descriptor permanently, so a published DPP stays complete even if the source facility row is later retired. The `facilityId` list/count filter matches `facility.value`. |
| `digitalLinkUrl` | string | nullable, GS1 Digital Link |
| `complianceResult` | object | nullable, compliance check output |
| `retentionLocked` | bool | Set true on publish, never cleared |
| `jwsSignature` | string | nullable, JWS compact serialisation |
| `qrCodeUrl` | string | nullable, resolver URL |
| `publishedAt` | datetime | nullable |
| `createdAt` | datetime | |
| `updatedAt` | datetime | |

**Indexes:**
- `idx_passport_operator` on `operatorId`
- `idx_passport_status` on `status`
- `idx_passport_category` on `productCategory`
- `idx_passport_created` on `createdAt`

### 3.6 passport_audit

Append-only audit trail for passport lifecycle events.

| Field | Type | Notes |
|---|---|---|
| `passportId` | string | FK to passport |
| `operatorId` | string | Operator who owns the passport |
| `actor` | string | Who performed the action (key name or user) |
| `action` | string | created, updated, published, suspended, archived |
| `previousStatus` | string | nullable |
| `newStatus` | string | |
| `timestamp` | datetime | |

### 3.7 unsold_goods_report

ESPR unsold goods destruction reporting. Tracks exemptions and validated destruction events.

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | |
| `passportId` | string | FK to passport |
| `productCategory` | string | |
| `destination` | string | recycling, donation, discountSale, other |
| `reason` | string | safetyHazard, regulatory, expiry, other |
| `quantity` | int | |
| `reportingPeriod` | string | |
| `exemptDestruction` | bool | |
| `createdAt` | datetime | |

### 3.8 import_job

Async bulk import job tracking for CSV/XLSX uploads.

| Field | Type | Notes |
|---|---|---|
| `operatorId` | string | |
| `status` | string | queued, processing, completed, failed |
| `sector` | string | Target sector |
| `totalRows` | int | |
| `processed` | int | |
| `succeeded` | int | |
| `failed` | int | |
| `errors` | array | Per-row error details |
| `createdAt` | datetime | |
| `completedAt` | datetime | nullable |

**Indexes:** `idx_importjob_operator` on `operatorId`.

### 3.9 registry_sync

EU Central Registry synchronisation status per passport.

| Field | Type | Notes |
|---|---|---|
| `passportId` | string | FK to passport |
| `registryId` | string | nullable, ID assigned by EU registry |
| `status` | string | pending, synced, failed |
| `attempts` | int | DEFAULT 0 |
| `lastAttemptAt` | datetime | nullable |
| `registeredAt` | datetime | nullable |

**Indexes:**
- `idx_regsync_passport` UNIQUE on `passportId`
- `idx_regsync_status` on `status`

### 3.10 Identity Tables (odal_identity/identity)

#### did_document

| Field | Type | Notes |
|---|---|---|
| `operator_id` | string | Node's own DID-owner identity (provenance, snake_case) — not a tenant key |
| `did` | string | did:web identifier |
| `document` | object | Full W3C DID document JSON |
| `created_at` | datetime | |
| `updated_at` | datetime | |

#### key_pair

| Field | Type | Notes |
|---|---|---|
| `operator_id` | string | Node's own DID-owner identity (provenance, snake_case) — not a tenant key |
| `key_id` | string | did:web#key-N identifier |
| `public_key_jwk` | object | Public key in JWK format |
| `private_key_enc` | string | Encrypted private key |
| `algorithm` | string | EdDSA |
| `is_active` | bool | |
| `created_at` | datetime | |

---

## 4. Naming Conventions

| Namespace | Convention | Reason |
|---|---|---|
| `odal/dev` | camelCase | Matches Rust serde output and API JSON keys |
| `odal_identity/identity` | snake_case | Legacy — left as-is for MVP to avoid identity service churn |

All new tables and fields use camelCase. The identity namespace exception is documented and accepted for the MVP release.

---

## 5. Bootstrap Data

Bootstrap is **not** a migration — migrations define schema only. A fresh node's
initial records are created through the `dpp` CLI (`odal bootstrap`), which uses
the node's HTTP API authenticated with the local admin credential:

1. **operator_config** — the operator's real identity, collected by `dpp init`
   (legal name, address, country, identifiers), `PATCH`ed onto the default
   `operatorId = "self_hosted"` row the node seeds on first boot.
2. **