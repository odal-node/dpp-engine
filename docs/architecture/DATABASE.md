# Database Architecture

The persistence layer is **PostgreSQL** (migration from the legacy backend completed 2026-06-11; PostgreSQL is the only supported datastore).

---

## PostgreSQL

**Schema:** `ops/pg/0001_extensions_roles_schemas.sql` through `0017_passport_transfer.sql` — a
clean, FK-ordered migration set applied via `PgDal::migrate(url)` at boot
using a privileged role, or pre-applied by ops tooling.

**Connection:** `PgDal::connect(database_url)` — connects as the least-privilege app
role `odal_app`, which cannot run DDL or DELETE (one sanctioned exception). The node is
**single-tenant**: there is **no Row-Level Security** — one
operator per node, so there is no in-process isolation boundary to enforce.

**Repos:** `pg::PgPassportRepo`, `pg::PgAuditRepo`, `pg::PgApiKeyRepo`,
`pg::PgOperatorConfigRepo` in `crates/dpp-dal/src/pg/`.

**Job store:** `PgJobStore` in `crates/dpp-node/src/infra/pg_job_store.rs`.

**Env vars:**
```
DATABASE_URL=postgres://odal_app:<pass>@host:5432/odal      # least-privilege app role
DATABASE_MIGRATE_URL=postgres://postgres:<pass>@host:5432/odal  # migration role (optional)
```

If `DATABASE_MIGRATE_URL` is unset, migrations are assumed pre-applied.
