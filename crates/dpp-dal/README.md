# dpp-dal

PostgreSQL data access layer for [Odal Node](https://odal-node.io).

All persistence for the platform — passports, API keys, audit entries, operator
config, import jobs — goes through this crate. Nothing else in the platform speaks
the database directly.

---

## When to use this crate

- You are writing a feature in `dpp-vault` or `dpp-integrator` and need to read
  or write persisted data.
- You are writing an integration test that targets a real PostgreSQL instance.

## When NOT to use this crate

- You need in-memory fakes for unit tests — mock the repository trait instead.

---

## Architecture

`dpp-dal` uses `sqlx` with a connection pool (`PgDal`). The node is single-tenant, so
there is **no Row-Level Security** (DECISION-0002): the app role (`odal_app`) is a
least-privilege role that cannot run DDL or DELETE (one sanctioned exception), and
`operator_id` columns persist only as the node's constant identity for provenance.

```
dpp_dal
├── pg/
│   ├── dal.rs              PgDal — connect(), migrate(), connection pool
│   ├── repo_passport.rs    PgPassportRepo implementing PassportRepository
│   ├── repo_audit.rs       PgAuditRepo for append-only audit trail
│   ├── repo_operator_config.rs  PgOperatorConfigRepo for operator config CRUD
│   └── repo_api_key.rs     PgApiKeyRepo for API key management
```

### Migrations

The schema is defined in `ops/pg/0001_extensions_roles_schemas.sql` through
`0010_grants.sql` — a clean, FK-ordered 10-file set. Apply via `PgDal::migrate(url)`
at boot (requires a privileged `DATABASE_MIGRATE_URL`), or pre-apply with ops
tooling. If `DATABASE_MIGRATE_URL` is unset, migrations are assumed pre-applied.

The bootstrap seed (operator config, default facility, first API key) is **not** a
migration — it is applied through `dpp bootstrap` over the live API.

### Feature flag: `integration-tests`

Enables test helpers that spin up a real PostgreSQL container via `testcontainers`.
Never enabled in production builds.

```sh
cargo test -p dpp-dal --features integration-tests --test pg_integration
```

Requires Docker with `postgres:17`.

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-types` | Provides `ApiKeyRecord`, `AuditEntry`, `OperatorConfig` — repo impls return these |
| `dpp-domain` | Provides `Passport` — `repo_passport` serialises/deserialises it |
| `dpp-vault` | Primary consumer — calls all four repository impls |
| `dpp-node` | Constructs `PgDal` and passes it to the vault and integrator at boot |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
