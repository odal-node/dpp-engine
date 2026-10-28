# Data model

How the node stores its data in PostgreSQL. The SQL files in
[`ops/pg/`](../../ops/pg/) are the definition: this page explains the layout and the
invariants, and indexes which migration creates what. For column lists, read the
migration.

## Storage model

- **Two schemas.** `odal` holds every engine table. `identity` holds the node's
  `did:web` document and key metadata.
- **Documents plus query columns.** Each record's full `serde` JSON lives in a
  `doc JSONB` column with camelCase keys, exactly as the API returns it. Fields that
  queries, constraints or indexes need (id, product group, status, version chain,
  timestamps) are also real snake_case columns.
- **The component graph is in the document.** A passport's components are
  `componentRefs` inside `doc`, walked by `dpp-vault`'s `verify_tree`. There are no
  component, material or supplier tables.
- **Single tenant.** One operator per node, so there is no row-level security.
  `operator_id` columns, where they exist, record the node's constant identity for
  provenance.
- **Least-privilege application role.** The node connects as `odal_app`, which cannot
  run DDL and can `DELETE` only from the tables in
  [the DELETE set](../../ops/pg/README.md#the-delete-set): counters and queues, never
  passport, audit, evidence, seal or registry-identity data.

## Invariants enforced by the database

| Invariant | Mechanism | Migration |
|---|---|---|
| A published passport's content cannot change | Retention trigger on `passport`: once `retention_locked` is set, an update may only touch an allow-list of keys (status, signatures, carrier URLs, lint result, seal) | `0004`, extended by `0011`, `0018`, `0027`, `0028` |
| Audit trails and version history are append-only | Triggers refusing `UPDATE` and `DELETE` on `passport_audit`, `registry_identity_audit` and `passport_version` | `0005`, `0013`, `0040` |
| The audit trail is tamper-evident | Each entry stores a SHA-256 hash over its canonical (JCS) content and the previous entry's hash | `0015` |
| Facilities and operator identifiers are retired, never deleted | `retired_at` column, partial unique index on live rows, `DELETE` revoked | `0013`, `0014` |
| Every past version of a live passport is kept | `passport_version` rows written on every change, readable with `GET /dpp/{id}/versions?asOf=` | `0040` |

## Tables

| Table | Holds | Created in |
|---|---|---|
| `operator_config` | The operator's identity: legal name, address, country, contact, retention policy, registry verification | `0002`, `0031` |
| `operator_identifier` | Economic operator identifiers (VAT, LEI, EORI, DUNS) under ESPR Art. 13; one is primary | `0002` |
| `facility` | Facilities under ESPR Annex III; one is the default | `0002` |
| `registry_identity_audit` | Append-only history of facility and identifier changes | `0013` |
| `api_key` | API keys: SHA-256 hash, 12-character prefix for lookup, scope | `0003` |
| `passport` | Passports. Status is one of `draft`, `active`, `suspended`, `superseded`, `retired`, `deactivated` | `0004`, renamed columns in `0032`, `0041` |
| `passport_version` | Historical versions of a passport (EN 18221 clause 4.2 archiving) | `0040` |
| `passport_audit` | Hash-chained audit trail per passport, including credentialed reads | `0005`, `0015`, `0026`, `0034` |
| `passport_transfer` | The dual-signed transfer-of-responsibility chain | `0017` |
| `evidence_dossier` | Stored, immutable evidence dossiers | `0021` |
| `personal_data_record` | Personal data a passport statement names, held outside the passport so it can be erased | `0043` |
| `unsold_goods_report` | ESPR Art. 24 disclosure lines (units and weight) | `0008`, `0037` |
| `import_job` | Import jobs and their row-addressed reports | `0007`, `0020` |
| `idempotency_key` | Replayable answers to client requests sent with `Idempotency-Key` | `0036` |
| `scan_telemetry`, `qr_render` | Aggregate resolution and QR-render counts per passport and day. No IP, agent or session columns | `0025` |
| `registry_sync` | Outbox: EU registry registration per passport | `0006`, `0024`, `0030` |
| `registry_transfer` | Outbox: registry notification of a transfer of responsibility | `0029` |
| `seal_outbox`, `seal_audit_state` | Outbox for eIDAS sealing, and the position of the stored-seal audit | `0028`, `0038` |
| `snapshot_outbox` | Outbox for the static continuity tier | `0023`, `0033` |
| `webhook_subscription`, `webhook_delivery` | Webhook receivers and the delivery outbox | `0022` |
| `trusted_list_cache` | EU Trusted Lists the node has verified | `0039` |
| `identity.did_document`, `identity.key_pair` | The node's DID document and key metadata (snake_case `doc` keys, unlike the rest) | `0009` |

`0001` creates the schemas, extensions and roles; `0010` holds the initial grants.
Every later migration that creates a table ships its own grant, and a test in
`dpp-dal` checks that `odal_app` can read every table.

## Outboxes

Side effects that leave the node (EU registry registration, transfer notification,
sealing, snapshot publishing, webhook delivery) are queued as outbox rows and
delivered by drainers in `dpp-node` with retry and backoff. The two registry outboxes
are written in the same transaction as the passport change, so a crash loses
nothing. Seal, snapshot and webhook rows are queued just after commit; seals and
snapshots also have a periodic sweep that queues anything missed. Outbox rows are
only written for backends that are configured, so no backlog builds up for a backend
the node does not use. [DESIGN-PATTERNS.md](DESIGN-PATTERNS.md#4-outboxes) has the
details.

## Migrations

- Migrations are applied by `sqlx::migrate!` with a privileged role
  (`DATABASE_MIGRATE_URL`), at node start-up or ahead of time by your tooling.
- Files are append-only and never renumbered or edited: sqlx records a checksum of
  each applied file, and a node whose recorded checksum disagrees refuses to start.
  `just migrations-check` fails on any edit to an existing migration. To change what
  a migration did, add a new one. See [`ops/pg/README.md`](../../ops/pg/README.md).

## Initial data

No migration seeds operator data. `odal bootstrap` mints the first API key over the
API, and `odal operator set`, `odal facility add` and `odal operator-id add` fill in
the operator's identity. See the [CLI reference](../../cli/README.md).
