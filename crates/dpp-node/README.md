# dpp-node

The Odal Node server binary: one Axum process that serves the passport API, the
operator's `did:web` document and bulk import, hosts the Wasm plugin sandbox, and
runs the background outbox drainers. Part of
[dpp-engine](https://github.com/odal-node/dpp-engine), under the Business Source
License 1.1.

> [!NOTE]
> Pre-production. The HTTP API and the database schema can still change between
> minor versions.

## Run it

The supported way to run the node is the full stack (node, resolver, PostgreSQL,
Redis, NATS) through the `odal` CLI. The
[engine README](https://github.com/odal-node/dpp-engine#quick-start) has the
step-by-step quick start. For engine development:

```bash
just infra              # PostgreSQL, Redis and NATS in Docker
cp .env.example .env    # set KEY_STORE_PASSPHRASE
cargo run -p dpp-node
```

The node listens on `NODE_PORT` (8001). Configuration comes from environment
variables; [`.env.example`](../../.env.example) lists every one under its section.

## Routes

| Prefix | Served by | What is there |
|---|---|---|
| `/health` | `dpp-node` | Liveness |
| `/vault/*` | [`dpp-vault`](../dpp-vault/README.md) | Passport lifecycle, operator configuration, keys, webhooks, evidence, seals |
| `/identity/*` | [`dpp-identity`](../dpp-identity/README.md) | The public `did:web` document and probes only |
| `/integrator/*` | [`dpp-integrator`](../dpp-integrator/README.md) | CSV/XLSX import, templates and schemas |

The node mounts only the public identity routes. It signs in-process, so there is
no network-reachable signing endpoint. The full route list, with authentication and
scopes, is the OpenAPI description:
[`api/openapi.bundled.yaml`](../../api/openapi.bundled.yaml).

Prometheus metrics are served on a separate private listener, `METRICS_ADDR`
(default `127.0.0.1:9100`).

## Start-up sequence

1. Read configuration from the environment. A missing required variable stops
   the process.
2. Connect to PostgreSQL. If `DATABASE_MIGRATE_URL` is set, apply the migrations in
   `ops/pg/` with that privileged role first; otherwise they must already be
   applied.
3. Load and verify the Wasm plugins in `PLUGINS_DIR`.
4. Open the encrypted key store at `KEY_STORE_PATH`.
5. Resolve each trust adapter (compliance plugins, EU registry, seal, credential
   issuers, ruleset channel) and record whether it is live, sandbox or a stub. Under
   `NODE_PROFILE=production` the node refuses to start while a required adapter is
   a stub.
6. Connect to NATS if `NATS_URL` is set. Without it, events are discarded.
7. Start the background tasks: the EU registry, transfer, webhook, seal and
   snapshot outbox drainers, the ruleset poll, and the clean-up jobs. Drainers
   for an unconfigured backend are not started.
8. Serve the router and the metrics listener.

## Modules

```text
src/
├── main.rs      the start-up sequence above
├── boot/        database, trust-report and background-task construction
├── config.rs    NodeConfig, read from the environment
├── infra/       NATS event bus, PostgreSQL job store, outbox drainers, ruleset
│                channel, S3 back-up and snapshot stores, trusted-list refresh
├── plugins.rs   plugin directory loading and signature checks
└── router.rs    nests the vault, identity and integrator routers
```

`lib.rs` exports `config`, `infra` and `router`, so integration tests can build the
assembled router with test state.

## Licence

[Business Source License 1.1](../../LICENSE).
