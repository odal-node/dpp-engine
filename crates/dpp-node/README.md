# dpp-node

Odal Node MVP single binary — fuses vault, identity, integrator, bridge, and plugin
host into one process for [Odal Node](https://odal-node.io) self-hosted deployments.

In production the full stack is a `docker-compose` of `dpp-node` + `dpp-resolver` +
PostgreSQL. `dpp-node` listens on `:8001`; `dpp-resolver` on `:8003`.

---

## What this binary does

1. **Loads configuration** from environment / `.env`.
2. **Runs schema migrations** via `PgDal::migrate` if `DATABASE_MIGRATE_URL` is set.
   If unset, migrations are assumed pre-applied by ops tooling.
3. **Loads Wasm plugins** — scans `/plugins/*.wasm`, compiles each with `wasmtime`,
   registers in `WasmPluginHost`.
4. **Connects to NATS JetStream** — subscribes to domain events; routes them to the
   EventBus.
5. **Builds the fused router** — mounts vault, identity (public only), and integrator
   under their respective prefixes.
6. **Starts the Axum server** on `0.0.0.0:8001`.

---

## Route prefixes

| Prefix | Crate | Description |
|---|---|---|
| `/health` | node | Top-level liveness probe |
| `/vault/…` | `dpp-vault` | Full DPP write API + operator + API key management |
| `/identity/…` | `dpp-identity` (public) | `did:web` document + health only |
| `/integrator/…` | `dpp-integrator` | CSV/Excel import jobs |

The internal identity signing endpoint (`/internal/sign`) is **not mounted** on the
network. The vault calls `LocalIdentityService` in-process, so there is no
network-reachable signing surface.

---

## Module structure

```
src/
├── config.rs     NodeConfig — merges all service configs + NATS URL + plugin dir
├── infra/        Wire-up helpers (NATS connection, plugin loader bootstrap)
├── router.rs     build() — nests vault, identity, integrator routers
└── main.rs       Binary entry point (boot sequence described above)
```

The library surface (`lib.rs`) re-exports `config`, `infra`, and `router` so
integration tests can build the assembled router with injected test states without
going through the binary entry point.

---

## Configuration (key environment variables)

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection URL for the least-privilege app role |
| `DATABASE_MIGRATE_URL` | PostgreSQL connection URL for the migration role (optional) |
| `NATS_URL` | NATS JetStream server URL |
| `DID_WEB_BASE_URL` | Operator's public hostname for `did:web` document generation |
| `PLUGIN_DIR` | Directory to scan for `.wasm` plugin files (default `/plugins`) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Local bootstrap admin credentials |

See `.env.example` in the repo root for the full list.

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-vault` | DPP write engine; router nested under `/vault` |
| `dpp-identity` | `build_public()` nested under `/identity` |
| `dpp-integrator` | Async import adapter; router nested under `/integrator` |
| `dpp-plugin-host` | Wasm sandbox; instantiated at boot, injected into vault |
| `dpp-registry` | EU Central Registry connector; library only, no HTTP surface |
| `dpp-dal` | PostgreSQL client; constructed here, passed to vault and integrator |
| `dpp-common` | Telemetry init, config loading |
| `dpp-resolver` | Separate process — not embedded in this binary |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
