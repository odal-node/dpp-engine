# dpp-dal

The PostgreSQL data access layer: every repository the engine persists through, the
connection pool and the migration runner. Nothing else in the engine opens a
database connection. Part of [dpp-engine](../../README.md), under the Business
Source License 1.1.

## How it is built

- **`sqlx` with a pool.** `PgDal::connect(DATABASE_URL)` opens the application pool;
  `PgDal::migrate(DATABASE_MIGRATE_URL)` applies `ops/pg/*.sql` with a privileged
  role. When `DATABASE_MIGRATE_URL` is unset, the migrations must already be applied.
- **Least-privilege application role.** The node connects as `odal_app`, which
  cannot run DDL and can `DELETE` only from the tables listed in
  [`ops/pg/README.md`](../../ops/pg/README.md#the-delete-set). `just grants-check`
  fails when the grants and that list disagree.
- **Single tenant.** One operator per node, so there is no row-level security.
  `operator_id` columns hold the node's constant identity for provenance.
- **Documents in JSONB.** Each repository stores its type in a `doc` column through
  `serde`, with camelCase keys. The passport's component graph lives inside the
  passport document (`componentRefs`), not in relational tables.
- **Append-only history.** The audit table is append-only (enforced by a database
  trigger) and hash-chained. Superseded passport versions are kept by
  `ArchivingPassportRepo` in `passport_version`.

The first API key, operator configuration and facilities are not seeded by a
migration: `odal bootstrap` creates them through the API.

## Modules

```text
src/
├── pg/
│   ├── pool.rs                    PgDal: connect, migrate
│   ├── repo_passport.rs           PgPassportRepo (dpp-domain's PassportRepository)
│   ├── archiving_repo.rs          keeps every published version
│   ├── repo_audit.rs              hash-chained audit trail
│   ├── repo_api_key.rs, repo_operator_config.rs, repo_registry_identity.rs
│   ├── repo_registry_sync.rs, repo_seal.rs, repo_snapshot.rs,
│   │   repo_webhook.rs, repo_transfer.rs   transactional outboxes
│   └── …                          evidence, idempotency, scans, unsold goods, trusted lists
├── protected_fields.rs            fields a draft update may not change
├── in_memory_repo.rs              InMemoryPassportRepo for tests (test-harness feature)
└── test_harness.rs                shared PostgreSQL container harness (test-harness feature)
```

## Tests

The `test-harness` feature exposes `start_pg` and friends, the one shared
PostgreSQL container harness for this crate and `dpp-node`. Enable it from
`[dev-dependencies]` only. Write new suites against it rather than a copy;
`just harness-check` fails on a second harness.

```bash
cargo test -p dpp-dal --features integration-tests --test pg_integration
```

The integration suites need Docker. `just test-integration` runs them all.

## Licence

[Business Source License 1.1](../../LICENSE).
