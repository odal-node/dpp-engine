# Developer guide

How to build, run, test and extend `dpp-engine`. Git workflow and pull request rules
are in [CONTRIBUTING.md](../../CONTRIBUTING.md) and
[GIT-STRATEGY.md](../governance/GIT-STRATEGY.md). Every command below is a
[`justfile`](../../justfile) recipe; `just --list` shows them all.

## Prerequisites

| Tool | Why |
|---|---|
| Rust | The version pinned in `rust-toolchain.toml`; `rustup` installs it on first build |
| Docker with Compose v2 | PostgreSQL, Redis and NATS for running the node and for the integration tests |
| [`just`](https://github.com/casey/just) | Command runner |
| `cargo-nextest`, `cargo-audit`, `cargo-deny` | Test runner and the dependency checks `just check` runs (`just audit` calls both `cargo audit` and `cargo deny`) |
| Node.js | Only for `just openapi-*`, which run `@redocly/cli` through `npx` |

## Run the node from source

```bash
just infra                 # PostgreSQL :5432, Redis :6379, NATS :4222 in Docker
cp .env.example .env       # set KEY_STORE_PASSPHRASE; uncomment ADMIN_USERNAME / ADMIN_PASSWORD
just node                  # cargo run -p dpp-node, on :8001; applies migrations at start-up
```

Then drive it with the CLI from source:

```bash
set -a; . ./.env; set +a
just cli -- bootstrap --legal-name "Example GmbH" --country DE \
  --address "Musterstrasse 1, 10115 Berlin" --contact-email ops@example.com
just cli -- facility add --name "Main plant" --value 4012345000009 --country DE --default
just cli -- operator-id add --scheme vat --value DE123456789 --primary
just cli -- passport import ops/demo/samples/battery-full.json
just cli -- passport validate
just cli -- passport publish
```

`just resolver` runs the resolver on :8003. To run everything in containers instead,
use `odal up` as in the [README quick start](../../README.md#quick-start), or
`just up`. `just up-local` builds the images against a sibling `../dpp-core` checkout.

Building needs no running infrastructure; only running the node and the integration
tests do.

## Layout

```text
dpp-node (:8001)
├── /vault/*        dpp-vault       passport lifecycle, audit, keys, webhooks, evidence, seals
├── /identity/*     dpp-identity    did:web document (signing is in-process)
├── /integrator/*   dpp-integrator  CSV/XLSX import
├── dpp-plugin-host                 wasmtime sandbox for product group plugins
└── dpp-dal                         PostgreSQL repositories, migrations
dpp-resolver (:8003)                public digital link resolver
cli/ (odal)                         operator CLI, over the HTTP API
```

The crate list and what each one does is in the
[README](../../README.md#crates); `[workspace] members` in `Cargo.toml` is
authoritative. Dependencies point one way: the engine depends on `dpp-core`, never
the reverse.

**Where code belongs.** If it changes because a regulation changed, it goes in
`dpp-core`. If it changes because of how the node is deployed, stored or operated, it
stays here. Tenant, audit, API-key and auth concerns never go into `dpp-core`.

### Building against a local `dpp-core`

The workspace pins `dpp-core` crates from crates.io. To build against a sibling
checkout:

```bash
just core-local        # writes .cargo/config.toml with a [patch.crates-io] override
just core-published    # removes it again
```

`.cargo/config.toml` is git-ignored, so CI always builds against the published
crates.

## Configuration

[`.env.example`](../../.env.example) is the reference: every variable, grouped by
binary, with its default and its reasoning. The ones you need to run the node:

| Variable | Example | Notes |
|---|---|---|
| `DATABASE_URL` | `postgres://odal_app:…@localhost:5432/odal` | Application role: no DDL, no row-level security |
| `DATABASE_MIGRATE_URL` | `postgres://postgres:…@localhost:5432/odal` | Optional. When set, migrations run at start-up |
| `KEY_STORE_PATH` | `./dev-keystore.enc` | Encrypted Ed25519 key store |
| `KEY_STORE_PASSPHRASE` | output of `openssl rand -base64 32` | Never reuse a template value |
| `DID_WEB_BASE_URL` | `http://localhost:8001` | Origin of the `did:web` identifier |
| `RESOLVER_BASE_URL` | `http://localhost:8003` | Origin printed into QR codes. Required; no default |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | | Local admin credential for `odal bootstrap`. Leave unset once a key exists if you do not want the path |
| `NODE_PROFILE` | `development` (default) | Exactly `development`, `sandbox` or `production`; any other value refuses to start. `sandbox` refuses to start while a required trust adapter is a stub; `production` also refuses sandbox adapters |
| `LOG_LEVEL` | `info` | A `tracing` filter, so `dpp_vault=debug,info` also works |
| `LOG_FORMAT` | unset | `pretty` for readable terminal output; JSON otherwise |

The node refuses to start on the placeholder admin credentials that older example
files shipped, under any profile.

## Test

```bash
just test               # unit tests, no Docker
just check              # the CI gate: fmt, clippy (integration features included), guard scripts, unit tests, audit
just test-integration   # the Docker-backed tiers (dal, vault, plugin host, node)
just test-pg            # only the dpp-dal PostgreSQL lane
just ci                 # check + the Docker tiers
just test-changed       # tests for the crates your branch touched
```

| Tier | Needs Docker | Covers |
|---|---|---|
| Unit (`just test`) | No | Route mounting, health, auth middleware, config parsing, validators, the resolver end to end with test doubles |
| Integration (`just test-integration`) | Yes | The full passport lifecycle through the assembled node against real `postgres:17` and NATS containers |

Things to know:

- **`just check` compiles and lints the integration suites but does not run them.**
  A change to a status code or message that an integration test pins fails only when
  the suite runs. Run `just test-integration`, or one suite with
  `cargo nextest run -p <crate> --features integration-tests --test <name>`.
- **One shared PostgreSQL harness.** Integration suites use `dpp-dal`'s
  `test-harness` feature (`start_pg` and friends). `just harness-check` fails on a
  second copy.
- **Answer behaviour questions with a committed test**, named for the fact it pins
  (`a_bad_check_digit_is_refused_while_the_body_is_parsed`), and watch it fail
  once before trusting it.
- **Documenting an error code in `api/paths/` means writing the test that produces
  it** when the code is ambiguous (for example `404` versus `422`).
- **Test key stores use `tempfile::tempdir()`**, never `std::env::temp_dir()`: they
  hold private keys.

## Migrations

Migrations are `ops/pg/NNNN_*.sql`, applied by `sqlx::migrate!`. Add a new numbered
file; never edit or renumber an existing one, because sqlx stores each file's
checksum and a node with a mismatched checksum refuses to start.
`just migrations-check` enforces this, and `just grants-check` checks the `DELETE`
grants against [`ops/pg/README.md`](../../ops/pg/README.md). In development,
`just reset-db` drops the database volume and re-applies everything.

[DATA-MODEL.md](../architecture/DATA-MODEL.md) explains the schema.

## Authentication

| Header | Provider |
|---|---|
| `Authorization: Bearer odal_sk_…` | API key: SHA-256 hash lookup, scope `read`, `write` or `admin` |
| `Authorization: Basic base64(user:pass)` | Local admin from `ADMIN_USERNAME` / `ADMIN_PASSWORD`, used by `odal bootstrap` before any key exists |

The middleware routes by scheme, so a `Bearer` token is never checked against the
local admin credential. The node signs in-process and exposes no signing endpoint.
Details: [AUTH.md](../architecture/AUTH.md).

## Observability

- **Logs:** `tracing`, JSON by default, `LOG_FORMAT=pretty` for terminals.
- **Metrics:** Prometheus on a private listener, `METRICS_ADDR` (default
  `127.0.0.1:9100` for the node, `127.0.0.1:9101` for the resolver), not on the API
  port.

```bash
curl -s http://127.0.0.1:9100/metrics | head
```

[METRICS-PLAN.md](../ops/METRICS-PLAN.md) lists every series and the suggested
alerts. There is no OpenTelemetry export.

## Extending the engine

- **A CLI command:** add `cli/src/commands/<name>.rs` with a `run_<name>`, register
  it in `commands/mod.rs`, add the clap variant in `cli_args.rs` and the arm in
  `dispatch.rs`. Talk to the node through `OdalClient`; the CLI never touches the
  database.
- **A route:** add the handler in the owning crate, then the path file under
  `api/paths/<service>/` and any schemas. `openapi_contract.rs` fails until the route
  and its types are documented. See [`api/README.md`](../../api/README.md).
- **A product group:** schemas, data model and validation go in `dpp-core`
  (`dpp-domain`), and optionally a Wasm plugin. The engine picks it up from the
  catalog; the passport graph is not parameterised per product group.
- **A calculation:** EU methodology belongs in `dpp-core`'s `dpp-calc`.
- **An event:** add the subject to `dpp_common::event::subjects`
  ([EVENT-BUS.md](../architecture/EVENT-BUS.md)).

## Conventions

- **Serde:** camelCase on the wire and in `doc` JSON. The `identity` schema's tables
  are the snake_case exception.
- **Errors:** every HTTP error is an RFC 9457 `Problem` from `dpp-common`. Propagate
  errors; a write that can fail must surface the failure to its caller.
- **Identifiers:** UUID v7 (`Uuid::now_v7()`) for anything that is an identifier.
- **Single operator:** each node serves one operator (`STANDALONE_OPERATOR_ID` is
  `self_hosted`). Isolation between operators is a deployment boundary.
- **Style:** rustfmt defaults, `thiserror` in libraries and `anyhow` in binaries, no
  `unwrap` or `expect` in library code paths, `tracing` instead of `println!` in
  service crates (`just debug-check`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `migration N was previously applied but has been modified` | The development database holds an old checksum. `just reset-db` |
| `Address already in use` on 8001 or 9100 | A node is already running. Find it with `ss -ltnp \| grep -E ':8001\|:9100'` and stop it |
| A test build fails to replace a locked `dpp-node.exe` (Windows) | Stop the running node, or build tests elsewhere: `CARGO_TARGET_DIR=target-it just test-integration` |
| The plugin-host fuel-limit test aborts on Windows | Run the integration tiers under Linux or WSL2, or rely on CI |
