# dpp-types

Platform-scoped shared types for [Odal Node](https://odal-node.io) — operator configuration,
authentication context, audit entries, and API key management.

These types live in `dpp-engine` (BSL-1.1) rather than `dpp-domain` because they
carry platform concerns — authentication, audit, API keys, operator configuration — that
are not part of the open-source core. Any crate that needs to know *who is calling* imports
from here. The node is single-tenant (DECISION-0002): these types carry no tenant scope.

---

## When to use this crate

- You are writing a platform service (vault, integrator, …) and need `AuthContext`,
  `ApiKey`, or `AuditEntry`.
- You are implementing an authentication provider against the `AuthProvider` trait.
- You are wiring the operator configuration repository via `OperatorConfigRepository`.

## When NOT to use this crate

- You need the DPP data model (`Passport`, `SectorData`) → `dpp-domain`.
- You need cryptographic primitives or VC types → `dpp-crypto`.

---

## Public API

```
dpp_types
├── api_key     ApiKey, ApiKeyRecord, ApiKeyRepository, CreateApiKeyRequest, NewApiKey
├── audit       AuditEntry, AuditRepository
├── auth        AuthContext, AuthError, AuthProvider
└── operator    OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID,
                UpdateOperatorConfig
```

### `AuthContext`

Carries the authenticated caller on every inbound request. Threaded through Axum
state and read by handlers without re-verifying the token.

### `AuditEntry`

Immutable record written on every mutating operation. Stored in PostgreSQL by
`dpp-dal::pg::PgAuditRepo` and surfaced by `GET /dpp/{id}/history`.

### `OperatorConfig`

Single-row operator identity (legal name, country, DID URL, address, contact email).
Mutated via `PATCH /vault/api/v1/operator`. `STANDALONE_OPERATOR_ID` is the
well-known ID used in single-tenant deployments.

### `ApiKey`

Bearer token with a `odal_sk_` prefix. Only the SHA-256 hash is stored; the raw
secret is shown once at creation time. `ApiKeyRepository` exposes `create`, `list`,
`verify`, and `revoke`.

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-domain` | Core passport types — `dpp-types` extends the model with platform concerns |
| `dpp-dal` | Implements `ApiKeyRepository`, `AuditRepository`, `OperatorConfigRepository` |
| `dpp-vault` | Consumes `AuthContext` and `AuditEntry` in every authenticated handler |
| `dpp-common` | Supplies config helpers and telemetry used alongside these types |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
