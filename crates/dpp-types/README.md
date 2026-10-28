# dpp-types

Engine-side shared types and repository ports: authentication, API keys, the audit
trail, operator configuration, the transactional outboxes and the trust report. Part
of [dpp-engine](../../README.md), under the Business Source License 1.1.

These live in the engine rather than in `dpp-core` because they change with how the
node is deployed and operated, not with the regulations. The passport data model
itself (`Passport`, `ProductGroupData`) is `dpp-core`'s `dpp-domain`. The node is
single-tenant, so none of these types carries a tenant scope.

## Modules

| Module | Contents |
|---|---|
| `auth` | `AuthContext` (user id, scope, key id) that the middleware attaches to each request, `AuthError`, and the `AuthProvider` port |
| `api_key` | `ApiKey`, `ApiKeyScope` (`read`, `write`, `admin`) and the repository port. Only a SHA-256 hash of an `odal_sk_…` key is stored |
| `audit` | `AuditEntry`, hash-chain verification and the repository port |
| `operator` | `OperatorConfig` (legal name, country, address, contact, retention policy), its port and `STANDALONE_OPERATOR_ID` |
| `registry_identity` | Facilities (ESPR Annex III) and operator identifiers (ESPR Art. 13), with their append-only history |
| `registry_sync`, `registry_transfer`, `seal`, `snapshot`, `webhook` | Transactional outboxes: rows written in the same transaction as the passport change, then delivered by the node's drainers |
| `evidence` | The evidence dossier format, `VerificationReport` and its exit codes, and the repository port |
| `transfer`, `successor` | Transfer-of-responsibility chains, and finding a passport's successor |
| `trust` | `TrustMode`, `NodeProfile` and `NodeTrustReport`: each trust adapter's mode and the start-up check that refuses a stub under a production profile. Also the trusted-list cache port |
| `qualification` | The seal qualification result as the HTTP API serves it |
| `scan` | Scan telemetry port and aggregate read models |
| `unsold_goods` | The ESPR Art. 24 disclosure record and its port |
| `passport_request` | `CreatePassportRequest`, the body of `POST /vault/api/v1/dpp` |

`dpp-dal` implements the repository ports against PostgreSQL; `dpp-vault` and
`dpp-node` consume them.

## Licence

[Business Source License 1.1](../../LICENSE).
