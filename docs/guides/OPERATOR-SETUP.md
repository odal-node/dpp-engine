# Operator setup

Deploying and running a self-hosted Odal Node, from an empty host to issuing
passports. For a local trial, the [README quick start](../../README.md#quick-start) is
shorter. For production topology, hardening and key custody, see
[PRODUCTION-RUNBOOK.md](../ops/PRODUCTION-RUNBOOK.md).

> [!NOTE]
> Pre-production. Prebuilt images are not public yet, so build the stack from a clone
> of this repository (`odal up` does this automatically inside a clone).

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker 24+ with Compose v2 | `docker compose version` |
| A domain you control | The `did:web` identity and the QR code origin are derived from it |
| TLS termination | A reverse proxy (Caddy, Nginx) in front of the node and the resolver |
| The `odal` binary | `cargo build -p dpp-cli --release`; no prebuilt binary is published yet |

## 1. Configure

Run `odal` with no arguments for guided setup, or script it as below. Either way, the
deployment directory needs `docker/docker-compose.yml`, `ops/bootstrap/` and a `.env`
beside them. Inside a clone they already exist; elsewhere `odal init` scaffolds them.

```bash
odal profile create prod --node-url https://node.example.com \
  --resolver-url https://dpp.example.com
odal --profile prod init       # scaffolds what is missing; never overwrites
cp .env.example .env
```

Set at least these in `.env` (never commit it; `odal` never writes it):

```bash
DATABASE_POSTGRES_PASS=<random>          # PostgreSQL superuser, used for migrations
DATABASE_APP_PASS=<different random>     # odal_app, the role the node connects as
KEY_STORE_PASSPHRASE=<random>            # protects the Ed25519 signing key
DID_WEB_BASE_URL=https://node.example.com
RESOLVER_BASE_URL=https://dpp.example.com
ADMIN_USERNAME=<not "admin">
ADMIN_PASSWORD=<random>
```

`openssl rand -base64 32` produces suitable values.

`RESOLVER_BASE_URL` is printed into every QR code at publish time and cannot be
changed afterwards. Set it to the resolver you will run before you publish anything.

A `prod` profile runs a secrets preflight before `odal up` and refuses known
development values: `admin`, `dev_only_password` and `change_me_in_env`.

## 2. Start

```bash
odal --profile prod up
odal --profile prod status     # wait for vault, identity and resolver to report OK
```

The node applies database migrations on every start; there is no separate migration
step.

## 3. Onboard

```bash
export ADMIN_USERNAME=… ADMIN_PASSWORD=…
odal --profile prod bootstrap
odal --profile prod operator set --legal-name "Example GmbH" --country DE \
  --address "Musterstrasse 1, 10115 Berlin" --contact-email ops@example.com
odal --profile prod facility add --name "Berlin plant" --scheme gln \
  --value 4012345000009 --country DE --default
odal --profile prod operator-id add --scheme vat --value DE123456789 --primary
```

- `bootstrap` mints the first API key, prints it once and saves it to
  `~/.config/odal/credentials.toml` under the profile. On a node that already has a
  key it refuses; use `odal key create` for more keys.
- The operator identity (legal name, ISO 3166-1 country, address, contact email) is
  the responsible economic operator. Without a legal name, every EU registry
  registration the node builds fails validation.
- The default facility (ESPR Annex III) and primary operator identifier
  (ESPR Art. 13) are stamped onto each new passport. For a product group whose
  passport obligation is already in force (`odal product-group list --required`),
  publish is refused without them:

  ```text
  cannot publish: missing required registry identity — facility (Annex III unique
  facility identifier); operatorIdentifier (Annex III responsible-operator
  identifier).
  ```

Check what the configured key can do with `odal whoami` (identity, scope, key id).
It is the one route a `read`-scoped key can use to learn its own scope.

## 4. Issue passports

```bash
odal template textile -o textile.csv     # the columns the importer expects
odal --profile prod passport import textile.csv
odal --profile prod passport validate
odal --profile prod passport publish
```

### What the data must look like

- **GTINs are GTIN-14 with a valid check digit.** Pad a 13-digit GTIN with a leading
  zero; GS1 defines that as the same identifier. A rejected row names the check digit
  it expected:

  ```text
  ✗ Row 1 [gtin]: GTIN check digit invalid for '03801234567890': expected 8, got 0
  ```

- **One file, one product group.** `odal passport import` reads the product group
  from the `productGroup` column of the first data row and applies it to the whole
  file. Split mixed files.
- **Dry-run a body first** with `odal passport validate <file.json>`:

  ```text
  ✓ create   would be accepted
  ✓ publish  passes the product-group-data schema gate
  ```

  The second line covers the product group schema only. Publish also checks the
  registry identity above and, for some product categories, category-mandatory
  content.

Templates for every product group are in `crates/dpp-integrator/templates/`, and
worked examples in `ops/demo/datasets/`.

## 5. Check the trust status

Run `odal status` after onboarding and read the `TRUST` section:

```text
TRUST
────────────────────────────────────────────────────────────────────────
profile             development
backup              ghost
compliance          ghost
credential_issuers  ghost
registry_sync       ghost
seal                ghost
ruleset             <version>

! Running on a stand-in: backup, compliance, credential_issuers, registry_sync, seal.
```

`ghost` means the port runs on a stub. A stock node runs every trust port that way:
its passports are well-formed, signed with your Ed25519 key and independently
verifiable, but there is no compliance plugin, no qualified seal, no registry
submission and no third-party back-up. Treat the output as test data until each port
is configured. With `NODE_PROFILE=production`, the node refuses to start while a
required port (compliance, seal, registry sync) is a stub.

`odal seal status` reports sealing in detail, including what the background audit of
stored seals has found:

- `not audited yet` means no audit pass has completed, not that the seals are fine.
  `SEAL_AUDIT_BATCH` and `SEAL_AUDIT_INTERVAL_SECS` set how long a pass takes; the
  start-up log states the estimate for your data.
- `odal seal repair <id>` queues a replacement for a seal that no longer verifies. The
  node first checks that the stored seal is broken.

## Passports are hard to take back

- **The QR code origin is permanent.** `RESOLVER_BASE_URL` is signed into each
  passport at publish.
- **Retention is enforced.** `odal passport retire` refuses inside the retention
  window:

  ```text
  Error: retire failed: retention policy forbids retiring before 2036-08-18
  ```

  To withdraw a passport from public view, `odal passport suspend <id>`: its URL then
  answers `410 Gone`. Suspension is reversible; retirement is terminal.

## Profiles

```bash
odal profile list
odal profile use prod
odal --profile dev status
```

A profile's kind (`dev` or `prod`) decides only whether the secrets preflight runs.
`odal up`, `down` and `update` always manage the full stack. Whether images are built
or pulled depends on whether the deployment directory is inside a clone. The console
shows the active profile on every screen. See the [CLI reference](../../cli/README.md).

## Day-to-day operation

`odal` with no arguments opens the console: infrastructure, passports, operator,
registry identity, dossiers, API keys, environments and schema. Every console action
prints the equivalent command, and every command works non-interactively for CI.

```bash
odal passport export --format json --status active -o export.json
odal --reconfigure     # reconnect this machine, or re-run guided setup
```

**Rotating the API key:** `odal key create <name> --use`, check it with
`odal whoami`, then `odal key revoke <old-id>`.

## Updating

```bash
odal update            # inside a clone: rebuild from source and restart
odal status
```

On a deployment without the source tree, `odal update` pulls the images tagged
`ODAL_VERSION` and restarts the stack.

## Backups

Back up two things together. Losing either one is unrecoverable.

1. **The PostgreSQL `odal` database**, on your usual schedule.
2. **The signing key store**, `/data/keystore.enc` in the node container, on the
   `node-data` volume. The compose file pins it there so a container recreate keeps
   the key.

```bash
docker compose -f docker/docker-compose.yml cp node:/data/keystore.enc ./keystore-backup.enc
docker run --rm -v odal-node_node-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/node-data.tar.gz -C /data .
```

Store the key store backup encrypted, and keep `KEY_STORE_PASSPHRASE` separately: the
file is useless without it. Without the key store you cannot sign new passports or
re-sign existing ones.

## Network and domain

`DID_WEB_BASE_URL` must be reachable over HTTPS, because verifiers fetch the signing
key from its `/.well-known/did.json`. Forward that path to the node's identity route:

```nginx
location /.well-known/did.json {
    proxy_pass http://127.0.0.1:8001/identity/.well-known/did.json;
}
location / {
    proxy_pass http://127.0.0.1:8001;
}
```

Serve the resolver (port 8003) on the `RESOLVER_BASE_URL` host.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `odal up`: *"is still a dev default"* | A `prod` profile's `.env` has a placeholder, often `ADMIN_USERNAME=admin` | Set real values |
| `odal up`: *"this install is missing files the stack needs"* | The deployment predates `ops/bootstrap/` scaffolding | Run `odal init` again; it adds missing files only |
| Node stays `starting`; logs repeat *"password authentication failed for user odal_app"* | The role-provisioning hook was not mounted on first start | Make sure `ops/bootstrap/` is beside `docker/`, then recreate the database volume (the hook runs only on first initialisation) |
| *"No profile configured yet"* | Nothing configured on this machine | `odal init` or `odal profile create <name> --node-url <url>` |
| Publish fails `422` *"missing required registry identity"* | No default facility or primary operator identifier | `odal facility add … --default`, `odal operator-id add … --primary` |
| Import rejects every row on `gtin` | 13-digit GTINs, or wrong check digits | Use GTIN-14; the error names the expected digit |
| Retire fails *"retention policy forbids retiring before …"* | The retention window is still running | Suspend instead |
| `odal verify <id>`: *"Dossier not found"* | A passport id was passed | Pass a dossier id from `odal passport evidence <passport-id>` |
| Scanned QR codes resolve nowhere | `RESOLVER_BASE_URL` named an origin nobody serves | Fix it before publishing; published carriers cannot change |
| A second `odal up` on the same host replaced the first deployment | The compose project name is fixed (`odal-node`) | One deployment per host, or set `COMPOSE_PROJECT_NAME` |
| Console: *"connection refused"* | The node is not running | `odal up` |
| `odal bootstrap` fails `401` | Wrong admin credentials in the environment | Export the values from `.env` |
| `odal facility add` fails `422` | Bad GLN check digit, or a key without `admin` scope | Check the GLN and the key's scope |
| The DID document is not reachable publicly | Proxy or DNS not set up | Check the proxy rule above and DNS |
