# dpp-vault

The passport write engine: it creates, validates, signs, publishes and versions
Digital Product Passports, keeps the hash-chained audit trail, and serves the
operator API under `/vault/*`. It is the only component that writes passport state.
Part of [dpp-engine](../../README.md), under the Business Source License 1.1.

The node mounts this crate's router under `/vault`. A standalone `dpp-vault` binary
also exists for running the vault on its own; no deployment uses it today.

## What it covers

| Area | Routes (under `/vault`) |
|---|---|
| Passport lifecycle | `POST /api/v1/dpp`, `/validate`, `/publish`, `/amend`, `/supersede`, `/suspend`, `/retire`, `/eol` |
| Transfer of responsibility | `/transfer/initiate`, `/accept`, `/reject`, `/cancel` |
| Reads | `GET /api/v1/dpps`, `/dpp/{id}`, `/history`, `/versions`, `/verify-tree`, `/by-identity` |
| Evidence and seals | `/evidence`, `/evidence/{id}/verify`, `/seal`, `/seal/repair` |
| Operator administration | `/operator`, `/api-keys`, `/facilities`, `/operator-identifiers`, `/webhooks`, `/credentials`, `/plugins`, `/ruleset/reload` |
| Public and credentialed reads | `GET /public/dpp/{id}`, `/public/dpp/by-gtin/{gtin}`, `/credential/dpp/{id}` |

[`api/openapi.bundled.yaml`](../../api/openapi.bundled.yaml) is the complete,
tested route list, with each route's scope and error codes.

## How publish works

1. The draft is checked against its product group's JSON Schema and cross-field
   rules (from `dpp-core`). Publish fails closed: an unresolvable schema is refused.
2. For a product group whose passport obligation is in force, the default facility
   and primary operator identifier are filled in if missing, and publish is refused
   without them.
3. The public view is computed once (`public_view.rs`) and the passport is signed as
   an Ed25519 JWS through the `IdentityPort`. In the node this is the in-process
   `LocalIdentityService`.
4. The passport row and its EU registry outbox row are written in one transaction.
   After the commit, the seal and snapshot outbox rows, the event and any webhook
   deliveries are queued for the node's drainers.

## Authentication

`middleware/auth.rs` routes on the `Authorization` scheme: `Bearer odal_sk_…` goes
to the API-key provider, `Basic` goes only to the local admin provider. Handlers
then check the key's scope (`read`, `write` or `admin`).
[`docs/architecture/AUTH.md`](../../docs/architecture/AUTH.md) has the details.

## Modules

```text
src/
├── router.rs          route table and CORS
├── handlers/          one file per endpoint group
├── domain/
│   ├── service/       PassportService: create, publish, amend, lifecycle,
│   │                  transfer, evidence, seal, lint, queries
│   ├── verify/        JWS, did:web, transfer-chain and component-tree checks
│   └── compliance/    battery calculations on the publish path
├── middleware/        auth, scope, credential and idempotency layers
├── infra/             auth providers, identity client, status list, audit stamping
├── public_view.rs     the single definition of the public (redacted) view
└── state.rs           AppState
```

## Used by

| Crate | Relationship |
|---|---|
| `dpp-node` | Mounts the router under `/vault` and supplies the repositories, plugin host and drainers |
| `dpp-dal` | PostgreSQL repositories behind the domain ports |
| `dpp-types` | `AuthContext`, audit, API-key, operator and outbox types |
| `dpp-core` crates | Data model, schemas, rules, JWS and Digital Link construction |

## Licence

[Business Source License 1.1](../../LICENSE).
