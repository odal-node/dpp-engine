# dpp-vault

DPP write engine for [Odal Node](https://odal-node.io) — create, version, sign, and
manage the full lifecycle of Digital Product Passport records.

`dpp-vault` is the authoritative service for all passport state. It is the only
component allowed to write to the `passport` table in PostgreSQL.

---

## When to use this crate

- You are adding a new passport lifecycle operation (create, update, publish, suspend, archive).
- You need to extend the HTTP API surface for passport or operator management.
- You are writing an integration test against the vault's Axum router.

---

## HTTP API

All authenticated routes require `Authorization: Bearer odal_sk_…`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe (DB connection check) |
| `GET` | `/api/v1/info` | Node version and operator identity |
| `GET` | `/public/dpp/{dppId}` | Public read — no auth, signed payload only |
| `POST` | `/api/v1/dpp` | Create a new passport (draft) |
| `GET` | `/api/v1/dpps` | List passports (paginated, filterable by status) |
| `GET` | `/api/v1/dpp/{dppId}` | Read one passport |
| `PUT` | `/api/v1/dpp/{dppId}` | Update a draft |
| `POST` | `/api/v1/dpp/{dppId}/publish` | Sign + publish; mints GS1 Digital Link |
| `POST` | `/api/v1/dpp/{dppId}/suspend` | Suspend an active passport |
| `POST` | `/api/v1/dpp/{dppId}/archive` | Archive (retention-locked after publish) |
| `GET` | `/api/v1/dpp/{dppId}/history` | Audit trail |
| `GET/PATCH` | `/api/v1/operator` | View / update operator config |
| `GET/POST` | `/api/v1/api-keys` | List / create API keys |
| `DELETE` | `/api/v1/api-keys/{id}` | Revoke an API key |

### Signing

`POST /publish` calls the `IdentityPort` (either the co-located `LocalIdentityService`
in `dpp-node` or the remote `dpp-identity` service) to produce an Ed25519 JWS over
the canonical passport JSON. The signed payload is stored and returned on public read.

---

## Module structure

```
src/
├── config.rs         Config struct (identity service URL, CORS, etc.)
├── domain/
│   ├── service.rs    PassportService — core business logic, calls repository + identity
│   ├── api_key_service.rs
│   └── operator_service.rs
├── handlers/         One file per endpoint (create, read, list, publish, …)
├── infra/
│   ├── auth/         API-key + local-admin + composite AuthProvider impls
│   ├── db/           PostgreSQL PassportRepository impl (wraps dpp-dal)
│   └── identity_client.rs  HTTP client for the remote identity service
├── middleware/auth.rs  Axum auth middleware — extracts AuthContext
├── router.rs         Route table + CORS configuration
└── state.rs          AppState (Arc-wrapped service + repo handles)
```

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-domain` | `Passport`, `SectorData`, port trait interfaces |
| `dpp-types` | `AuthContext`, `AuditEntry`, `ApiKey`, `OperatorConfig` |
| `dpp-dal` | PostgreSQL repository implementations |
| `dpp-common` | Config loading, telemetry, `ProblemDetail` responses |
| `dpp-digital-link` | GS1 Digital Link generation at publish time |
| `dpp-identity` | Signs passports (in-process in `dpp-node`, over HTTP in standalone mode) |
| `dpp-node` | Mounts this crate's router under `/vault` |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
