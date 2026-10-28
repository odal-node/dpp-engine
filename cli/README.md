# `odal` CLI

`odal` is the operator CLI for a self-hosted Odal Node: it starts and stops the
stack, onboards the operator, manages keys, and drives the passport lifecycle over
the node's HTTP API. Every command calls the same API documented in
[`api/openapi.bundled.yaml`](../api/openapi.bundled.yaml), so anything `odal` does
can also be scripted with `curl`.

```bash
cargo build -p dpp-cli --release     # binary: target/release/odal
odal --help
odal <command> --help                # the authoritative flag reference
```

There are no prebuilt binaries yet; build from a clone of this repository. The
[engine README](../README.md#quick-start) walks through a full first run.

## Configuration

`odal` keeps two files, split the way the AWS CLI splits `config` and
`credentials`:

| File | Holds |
|---|---|
| `~/.config/odal/config.toml` | Named profiles: the vault, identity and resolver URLs and an environment kind (`dev` or `prod`), plus the active profile. No secrets |
| `~/.config/odal/credentials.toml` | One API key per profile. Written with mode `0600` on Unix |

The node's own runtime configuration is the deployment's `.env` file. `odal` never
writes it, and it does not read it either: export the variables you need (for
example `ADMIN_USERNAME` and `ADMIN_PASSWORD` before `odal bootstrap`).

Environment variables override the files, so a CI runner needs nothing on disk:

| Variable | Overrides |
|---|---|
| `ODAL_PROFILE` | The active profile. `--profile <name>` overrides it in turn |
| `ODAL_VAULT_URL` | The vault URL of the active profile |
| `ODAL_API_KEY` | The API key of the active profile |
| `ODAL_API_SECRET` | The secret `odal key use` adopts, so it stays out of shell history |
| `ODAL_VERSION` | The image tag `odal update` pulls on a packaged install (`latest` when unset) |

Defaults, when no profile sets them: vault `http://localhost:8001/vault`, identity
`http://localhost:8001/identity`, resolver `http://localhost:8003`.

### Profiles

A profile is one node target, like a `kubectl` context. The active profile is
chosen by `--profile`, then `ODAL_PROFILE`, then the saved current profile, then
`default`.

```bash
odal profile create prod --node-url https://node.example.com \
  --resolver-url https://dpp.example.com
odal profile use prod
odal profile list                    # the active profile is marked *
odal --profile dev status            # one command against another profile
```

`--node-url` sets the vault and identity URLs together, because the node serves
both on one origin. The resolver is a separate deployment, so it always needs its
own `--resolver-url`. `--kind` is inferred from the URL when omitted.

The kind controls the start-up checks, not what is started:

- `dev` accepts the example database passwords from `.env.example`.
- `prod` runs a `.env` secret preflight before `odal up` and refuses those values.

## Interactive console and scripting mode

| Invocation | Mode |
|---|---|
| `odal` with no arguments, in a terminal | Interactive console: a menu of grouped actions with guided forms |
| `odal <command> [flags]` | Scripting: one command, a meaningful exit code, no prompts |

Both modes call the same functions, so behaviour and output match. In the console:

- Suspend, retire and bulk publish ask for confirmation and state the consequence first.
- After each action the console prints the equivalent command (`≡ odal passport import …`).
- When the active profile points at a non-local node, the start, stop and update
  actions are hidden: the CLI cannot manage containers on another host.
- With no API key configured, the console opens guided setup. `odal --reconfigure`
  reopens it later.

When stdin is not a terminal, or `CI` is set, `odal` with no subcommand prints help
and exits with code 2 instead of waiting for input.

## Scripted first run

```bash
odal init                            # scaffold docker/docker-compose.yml, ops/bootstrap/ and .env.example
cp .env.example .env                 # then set the secrets it marks as required
odal up                              # start node, resolver, PostgreSQL, Redis and NATS
odal status

set -a; . ./.env; set +a             # odal reads ADMIN_USERNAME / ADMIN_PASSWORD from the environment
odal bootstrap --legal-name "Example GmbH" --country DE \
  --address "Musterstrasse 1, 10115 Berlin" --contact-email ops@example.com
odal facility add --name "Main plant" --value 4012345000009 --country DE --default
odal operator-id add --scheme vat --value DE123456789 --primary

odal passport import ops/demo/samples/battery-full.json  # creates a battery draft
odal passport validate                                # checks the stored drafts
odal passport publish                                 # signs and publishes every draft
odal template battery-industrial -o battery.csv       # the CSV columns for your own data
```

`bootstrap` mints the first API key and saves it under the active profile. It
refuses on a node that already has an active key; use `odal key create` for more
keys, or `bootstrap --force` to mint one anyway. The operator identity flags are
optional at bootstrap and can be set later with `odal operator set`. Set them
before publishing: without a legal name, every EU registry registration the node
builds fails validation. For a product group whose passport obligation is already in
force, publish is refused until a default facility and a primary operator
identifier are configured.

## Command reference

The **Scope** column is the API key scope the node requires: `read`, `write` or
`admin` (each includes the ones before it). `none` means the command needs no key.
`odal <command> --help` lists every flag.

### Stack

| Command | What it does | Scope |
|---|---|---|
| `odal init` | Save the connection settings and scaffold `docker/docker-compose.yml`, `ops/bootstrap/` and `.env.example` in the current directory. Never overwrites a file and never writes `.env` | none |
| `odal up` | Start the full stack with Docker Compose. Inside a clone of this repository it builds the images from source; elsewhere it runs the published images | none |
| `odal down` | Stop the stack. Volumes, including the signing key, are kept | none |
| `odal update` | Inside a clone, rebuild from source and restart. Elsewhere, pull the images tagged `ODAL_VERSION` and restart | none |
| `odal status` | Health of the vault, identity service, resolver and containers. With a key configured, also each trust adapter's mode | none |
| `odal whoami` | The configured key's user, scope and key id | read |

`odal up`, `down` and `update` look for `docker/docker-compose.yml` in the current
directory and each parent, so they work from anywhere inside the deployment.

> [!NOTE]
> The published images on `ghcr.io/odal-node` are not public yet. Until they are,
> run `odal up` from a clone so the stack is built from source.

### Onboarding and keys

| Command | What it does | Scope |
|---|---|---|
| `odal bootstrap [--legal-name …] [--force]` | Mint the first API key with the local admin credential (HTTP Basic, from `ADMIN_USERNAME` / `ADMIN_PASSWORD`) | local admin |
| `odal operator show` | Print the operator configuration | read |
| `odal operator set [--legal-name …] [--retention-policy-days …]` | Update operator fields | admin |
| `odal key create <name> [--use]` | Mint an API key. The secret is printed once | admin |
| `odal key list` | List API keys by prefix | admin |
| `odal key revoke <id>` | Revoke an API key | admin |
| `odal key use [<secret> \| -]` | Save an existing `odal_sk_…` secret as this profile's key. Reads stdin for `-`, else `ODAL_API_SECRET`, else prompts | none |

### Facilities and operator identifiers

New passports are stamped with the default facility (ESPR Annex III) and the
primary operator identifier (ESPR Art. 13) at the moment they are created, so a
change applies without a restart. Both are retired rather than deleted, and each
keeps an append-only history.

| Command | What it does | Scope |
|---|---|---|
| `odal facility list` | List facilities; the default is marked `*` | admin |
| `odal facility add --name --value --country [--scheme gln] [--address] [--default]` | Add a facility. The identifier is validated (GLN check digit, ISO 3166 country) | admin |
| `odal facility set-default <id>` | Make a facility the default | admin |
| `odal facility remove <id>` | Retire a facility | admin |
| `odal facility audit <id>` | Show a facility's history | admin |
| `odal operator-id list` | List identifiers; the primary is marked `*` | admin |
| `odal operator-id add --scheme --value [--label] [--primary]` | Add an identifier: `vat`, `lei`, `eori` or `duns`, validated per scheme | admin |
| `odal operator-id set-primary <id>` | Make an identifier the primary | admin |
| `odal operator-id remove <id>` | Retire an identifier | admin |
| `odal operator-id audit <id>` | Show an identifier's history | admin |

### Passports

| Command | What it does | Scope |
|---|---|---|
| `odal passport list [--status] [--q] [--facility-id] [--limit] [--json]` | List or search passports | read |
| `odal passport import <file>` | Create drafts from CSV, TSV or JSON. Results are reported per row | write |
| `odal passport validate` | Check the stored drafts for missing required fields | read |
| `odal passport validate <file>` | Dry-run one JSON body through the create and publish checks. Creates nothing | write |
| `odal passport publish [id]` | Sign and publish one draft, or every draft | write |
| `odal passport suspend <id>` | Suspend a published passport. Its public URL answers `410 Gone` | write |
| `odal passport retire <id>` | Move a passport to the terminal `retired` state. The public page keeps serving | write |
| `odal passport eol <id> --reason [--derogation …]` | Declare end of life (terminal). `--reason destroyed` requires a `--derogation`, because ESPR Art. 25 otherwise bans destruction | write |
| `odal passport amend <id> --patch <file> [--reason]` | Correct a published passport by issuing a successor. Returns the successor, which has a new id; the original moves to `superseded` | write |
| `odal passport supersede <id> --superseded-by <id>` | Supersede a passport with one that already exists and already names it in `supersedesId` | write |
| `odal passport lint <id>` | Re-run the advisory plausibility checks and store the findings. Also reports publish readiness | write |
| `odal passport history <id>` | Show the hash-chained audit trail | read |
| `odal passport stats <id> [--days 30]` | Scan and QR-render counts for one passport | read |
| `odal passport tree <id>` | Walk the component (BOM) tree and check each node against the hash its parent pinned. An integrity check, not a signature check | read |
| `odal passport find --product-group --identifier [--batch]` | Look a passport up by product identifier (GTIN-14, identification link or DID) and batch | read |
| `odal passport export [--format json\|csv] [--status] [-o]` | Export every matching passport | read |
| `odal passport evidence <id> [-o]` | Generate and store a signed evidence dossier | write |

`export` neutralises spreadsheet formulas in CSV cells. A bare file name
(`-o report.csv`) is written to `~/.config/odal/exports/`; a path with a directory
(`-o ./report.csv`) is written exactly there.

### Transfer of responsibility

A handover has two steps and three terminal outcomes. Only a published passport can
be transferred.

| Command | What it does | Scope |
|---|---|---|
| `odal passport transfer initiate <id> --from-did … --to-did … --reason …` | Sign a pending handover onto the transfer chain. `--help` lists the eleven required fields and their allowed values | write |
| `odal passport transfer accept <id>` | Countersign and complete it | write |
| `odal passport transfer reject <id>` | End it as refused | write |
| `odal passport transfer cancel <id>` | End it as withdrawn | write |

### Verification

| Command | What it does | Scope |
|---|---|---|
| `odal verify <dossier-id \| file>` | Verify an evidence dossier's signatures and hash chains. Exit 0 verified, 1 a check failed, 2 the dossier could not be read | read |
| `odal snapshot verify <path \| url> (--key <base64> \| --did-url <url>)` | Check a continuity snapshot's signed freshness bound. Needs no node and no key. Exit 0 proven and current, 1 expired, stripped or unproven, 2 the check could not be made | none |
| `odal seal status [id]` | Sealing state, operator-wide or for one passport | read |
| `odal seal repair <id>` | Queue a replacement for a stored seal that no longer verifies. Refused unless the seal is broken, because a replacement costs a seal | admin |

`snapshot verify` takes the key as an argument because it is meant for the case
where the node is down, and on a single-binary deployment the node also serves the
DID document. Use `--did-url` only when the DID document is hosted elsewhere; it
must be HTTPS on every redirect, or loopback. A snapshot with no
`snapshotJwsSignature` is reported as unverifiable, never as current. The command
checks the outer snapshot proof only; the passport's own `publicJwsSignature` is a
separate check.

### Registry, telemetry and regulatory catalog

| Command | What it does | Scope |
|---|---|---|
| `odal registry [id] [--json]` | EU registry submission status: the rollup, or one passport | read |
| `odal stats [--days 30] [--json]` | Operator-wide scan counts | read |
| `odal product-group list [--required] [--json]` | Every product group an act reaches: whether a passport is required, and from when | none |
| `odal product-group show <group>` | One product group, with the acts behind it and their status | none |
| `odal schema list` | Product groups with a schema, the current version, and the older versions still readable | none |
| `odal schema show <group> [version] [-o]` | Print a product group's JSON Schema | none |
| `odal schema check` | The node build, `dpp-core` version and ruleset in force | none |
| `odal template <key> [-o]` | The CSV header row `odal passport import` expects. Batteries are served per category (`battery-ev`, `battery-lmt`, `battery-industrial`). An unknown key returns `404` with the list of valid keys | none |

The catalog commands need no key because "does my product need a passport?" is
asked before anyone runs a node.

### Access credentials and unsold goods

| Command | What it does | Scope |
|---|---|---|
| `odal credential issue <holder-did> --name --country [--role] [--product-groups] [--valid-for-days]` | Issue a credential the holder sends as `X-DPP-Credential` to read restricted fields | admin |
| `odal unsold-goods record --period --units --kg --category --reason --destination --country [--justification]` | Record one line of the ESPR Art. 24 disclosure of discarded unsold products | write |
| `odal unsold-goods list [--period] [--json]` | List recorded lines, newest first | admin |

`credential issue` covers legitimate-interest roles (repairers, recyclers,
remanufacturers and similar). Authority roles are refused, because a member state
confers that standing, not the operator. The node publishes no revocation list, so
a credential lives at most 90 days.

`unsold-goods` lines are not passports: Art. 24 reports on the operator over a
financial year. Both `--units` and `--kg` are required because Art. 24(1)(a) asks
for the number and the weight. `--destination exemptDestruction` requires a
`--justification` naming the Art. 25 exemption, and every other destination
refuses one.

### Webhooks, plugins and rulesets

| Command | What it does | Scope |
|---|---|---|
| `odal webhook add <https-url> [--events a,b] [--description]` | Subscribe a receiver to passport events; all events when `--events` is omitted. The signing secret is printed once | admin |
| `odal webhook list` | List subscriptions | admin |
| `odal webhook test <id>` | Send a signed test delivery | admin |
| `odal webhook remove <id>` | Remove a subscription | admin |
| `odal plugin install <file>` | Upload a product group plugin and the detached signature beside it (`plugin.wasm` needs `plugin.wasm.sig`). The node checks the signature against its pinned publisher key, checks the ABI, stores it and swaps it in without a restart | admin |
| `odal ruleset reload` | Re-read the signed ruleset channel now instead of waiting for the next poll | admin |

See [`docs/guides/WEBHOOKS.md`](../docs/guides/WEBHOOKS.md) for the delivery format
and signature check.

## Global options

| Option | Effect |
|---|---|
| `--profile <name>` | Run one command against another profile |
| `--idempotency-key <key>` | Sent as `Idempotency-Key` on commands that create something. Re-running the same command with the same key returns the first result instead of creating a second resource. Use it when retrying after a network error |
| `--reconfigure` | Reopen guided setup |

## See also

- [`docs/guides/OPERATOR-SETUP.md`](../docs/guides/OPERATOR-SETUP.md): production
  setup, environment variables, key management, backups and troubleshooting.
- The node applies database migrations on every start; there is no separate
  migration command.
