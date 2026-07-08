
## Service Endpoints

### MVP Node (port 8001)

Routes are mounted by prefix: `/vault/*`, `/identity/*`, `/integrator/*` (see
`crates/dpp-node/src/router.rs`). The fused node mounts identity's
**public-only** router — the internal signing/key-rotation endpoints exist in
`dpp-identity` for **standalone** deployment only and are never network-reachable
here; the vault signs in-process instead (see `ATK-1` regression test).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/health` | None | Node |
| GET | `/vault/health` | None | Vault |
| GET | `/vault/ready` | None | Vault |
| GET | `/vault/api/v1/info` | None | Vault |
| GET | `/vault/public/dpp/{id}` | None | Vault |
| GET | `/vault/public/dpp/by-gtin/{gtin}` | None | Vault |
| POST | `/vault/api/v1/dpp` | Bearer | Vault |
| GET | `/vault/api/v1/dpps` | Bearer | Vault |
| GET | `/vault/api/v1/dpp/{id}` | Bearer | Vault |
| PUT | `/vault/api/v1/dpp/{id}` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/publish` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/suspend` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/archive` | Bearer | Vault |
| GET | `/vault/api/v1/dpp/{id}/history` | Bearer | Vault |
| POST | `/vault/api/v1/dpp/{id}/eol` | Bearer | Vault — end-of-life declaration (typed reason) |
| POST | `/vault/api/v1/dpp/{id}/transfer/initiate` | Bearer | Vault — transfer-of-responsibility (signs) |
| POST | `/vault/api/v1/dpp/{id}/transfer/accept` | Bearer | Vault — countersigns, fail-closed verify |
| GET | `/vault/api/v1/dpp/{id}/evidence` | Bearer | Vault — signed evidence dossier
| GET | `/vault/api/v1/node/state` | Bearer | Vault |
| GET | `/vault/api/v1/operator` | Bearer | Vault |
| PATCH | `/vault/api/v1/operator` | Bearer (Admin) | Vault |
| GET | `/vault/api/v1/api-keys` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/api-keys` | Bearer (Admin) | Vault |
| DELETE | `/vault/api/v1/api-keys/{id}` | Bearer (Admin) | Vault |
| GET | `/vault/api/v1/facilities` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/facilities` | Bearer (Admin) | Vault |
| DELETE | `/vault/api/v1/facilities/{id}` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/facilities/{id}/default` | Bearer (Admin) | Vault |
| GET | `/vault/api/v1/operator-identifiers` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/operator-identifiers` | Bearer (Admin) | Vault |
| DELETE | `/vault/api/v1/operator-identifiers/{id}` | Bearer (Admin) | Vault |
| POST | `/vault/api/v1/operator-identifiers/{id}/primary` | Bearer (Admin) | Vault |
| GET | `/identity/health` | None | Identity |
| GET | `/identity/ready` | None | Identity |
| GET | `/identity/.well-known/did.json` | None | Identity |
| GET | `/integrator/health` | None | Integrator |
| GET | `/integrator/api/v1/templates/{sector}` | None | Integrator |
| POST | `/integrator/api/v1/import/{sector}` | Bearer | Integrator |
| GET | `/integrator/api/v1/imports/{job_id}` | Bearer | Integrator |