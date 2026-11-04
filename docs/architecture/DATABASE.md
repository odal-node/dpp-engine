# Database architecture

PostgreSQL is the only supported datastore. The move from the earlier backend was
completed on 2026-06-11.

---

## PostgreSQL

**Schema:** the migrations in `ops/pg/`, starting at `0001_extensions_roles_schemas.sql`.
They are FK-ordered and append-only: a new migration is added, an applied one is never
edited or renumbered. See [`ops/pg/README.md`](../../ops/pg/README.md) for the current
range. They are applied by `PgDal::migrate(url)` at boot with a privileged role, or applied
beforehand by ops tooling.

**Connection:** `PgDal::connect(database_url)` connects as the least-privilege app role
`odal_app`. It cannot run DDL, and may `DELETE` only from the counter and queue tables
listed under "The DELETE set" in `ops/pg/README.md`, which `just grants-check` holds to the
actual grants. The node refuses to start if `DATABASE_URL` connects as a superuser,
because a superuser owns the audit table and the append-only trigger could not bind it.

The node is **single-tenant**, with **no row-level security**: one operator per node, so
there is no in-process isolation boundary to enforce.

**Repositories:** one per concern in `crates/dpp-dal/src/pg/`, for example
`PgPassportRepo`, `PgAuditRepo`, `PgApiKeyRepo` and `PgOperatorConfigRepo`, plus the outbox
repositories (registry sync, registry transfer, seal, snapshot), evidence, webhooks,
idempotency keys, scan telemetry, trusted lists, unsold goods and personal-data records.

**Job store:** `PgJobStore` in `crates/dpp-node/src/infra/pg_job_store.rs`.

**Environment variables:**

```bash
DATABASE_URL=postgres://odal_app:<pass>@host:5432/odal            # least-privilege app role
DATABASE_MIGRATE_URL=postgres://postgres:<pass>@host:5432/odal    # migration role (optional)
```

If `DATABASE_MIGRATE_URL` is unset, migrations are assumed to be applied already.
