# Operator Setup Guide

Step-by-step guide for deploying and operating a self-hosted Odal Node — from
bare metal to a live, passport-issuing node.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Docker ≥ 24** (with Compose plugin) | `docker compose version` to verify |
| **A domain name** | Required for `did:web` — passports are signed against it |
| **TLS termination** | Reverse proxy (nginx, Caddy) in front of port 8001 recommended for production |
| **`odal` binary** | Build: `cargo build -p dpp-cli --release` or download a release |

---

## First-time setup

Run `odal` with no arguments from any directory:

```sh
odal
```

The Console launches and — because no API key is configured — immediately enters
the guided **Setup** flow:

### Step 1 — Connect

Confirm or enter your vault URL. For a local install keep the default
(`http://localhost:8001/vault`). For a remote node enter the public HTTPS URL.
This is saved as a **profile** (the URL's host decides the default environment
kind: localhost → `dev`, otherwise → `prod`). You can hold several profiles
(e.g. `dev` and `prod`) side by side and switch between them — see
[Profiles & environments](#profiles--environments).

### Step 2 — Infrastructure *(localhost only)*

The Console offers to scaffold `docker/docker-compose.yml` in the current
directory and start your services. Before confirming **Start services**, create a
`.env` file in the same directory:

```sh
# .env — never commit this file
# Two database passwords, each set once:
DATABASE_POSTGRES_PASS=<strong-random-password>   # Postgres superuser (migrations)
DATABASE_APP_PASS=<different-strong-password>      # odal_app role (least-privilege: no DDL; what the node uses)
KEY_STORE_PASSPHRASE=<passphrase-for-Ed25519-key-store>
DID_WEB_BASE_URL=https://your-domain.example
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<temporary-admin-password>
```

> The node auto-applies all database migrations at startup — no manual migration
> step is needed.

### Step 3 — Onboard

Enter the admin credentials from your `.env`. The Console mints your **first**
API key and saves it (per-profile) to `~/.config/odal/credentials.toml` — kept
separate from the non-secret `config.toml` and written owner-only.

**The API key is shown exactly once. Save it immediately.**

Onboarding is **idempotent**: if the node has already been claimed (a key
exists), the Console does not mint a second one — instead it offers to connect
this machine by pasting an existing key. To add more keys later, use the
**API keys** menu (or `odal key create`).

You then fill in your **operator identity** (legal name, ISO 3166-1 country code,
address, contact email). This is the EU responsible-economic-operator identity
and is **required before you can publish** — the node refuses to publish until it
is complete. It is editable any time via **Operator › Edit** (`odal operator set`).

Before your first publish, also register at least one **facility** and one
**operator identifier** — see [Facility & operator identifier
management](#facility--operator-identifier-management) below. Unlike operator
identity, these are not currently a hard publish gate, but they're what
satisfies ESPR Annex III (unique facility identifier) and Art. 13 (economic-
operator identifier) on every passport you create afterwards.

After setup, the Console drops into its normal top-level menu.

---

## Profiles & environments

The CLI keeps multiple node targets as named **profiles** (like `kubectl`
contexts). The active profile is shown in a banner on every screen — prod is
rendered loudly so you always know what you're operating on.

```sh
odal profile list                       # all profiles (active marked *)
odal profile create prod --vault-url https://node.acme.example/vault
odal profile use prod                   # switch
odal --profile dev status               # one-off override
```

The profile's **kind** (`dev`/`prod`) decides which Docker Compose file
`odal up`/`down`/`update` target: dev starts infra only (you run the node from
source), prod starts the full containerised stack and **refuses to start on
missing or dev-default secrets**.

You can also drive all of this from inside the Console: **Environment** in the
top-level menu.

---

## Re-running setup

If you need to reconnect to a different node, rotate credentials, or reconfigure
after a reinstall:

```sh
odal --reconfigure           # re-run the guided setup flow directly
```

Or from inside the Console: **Setup / Reconfigure** in the top-level menu. On an
already-claimed node this becomes a *reconnect* (paste an existing key) rather
than minting a new one.

---

## Day-to-day operations

```sh
odal                         # launch the Console (recommended)
```

From the Console you can:

- **Infrastructure** — check status, start/stop services, update container images
- **Passports** — import, validate, publish, suspend, archive, export
- **Operator** — view or update your operator profile
- **API keys** — create, list, revoke
- **Registry identity** — facilities (ESPR Annex III) and operator identifiers (ESPR Art. 13)
- **Schema** — check for sector-schema updates

---

## Scripting and CI/CD

Every Console action is also available as a subcommand for pipelines:

```sh
# Import, validate, and publish in one step
odal passport import products.csv
odal passport validate
odal passport publish

# Export all active passports
odal passport export --format json --status active -o export.json

# Check health
odal status
```

Run `odal --help` or `odal <subcommand> --help` for flags.

For non-interactive setup (e.g. in a deployment pipeline):

```sh
odal profile create prod --vault-url https://node.example.com/vault
odal --profile prod init
odal --profile prod bootstrap \
  --admin-user admin --admin-pass "$ADMIN_PASSWORD"   # mints first key (idempotent)
odal --profile prod operator set \
  --legal-name "Acme GmbH" --country DE \
  --address "1 Allee, Berlin" --contact-email ops@acme.example
odal --profile prod facility add \
  --name "Berlin Plant" --scheme gln --value 4012345000009 \
  --country DE --default
odal --profile prod operator-id add \
  --scheme vat --value DE123456789 --primary
```

In CI you can skip the files entirely and pass everything via the environment —
`ODAL_PROFILE`, `ODAL_VAULT_URL`, `ODAL_API_KEY` take precedence over
`~/.config/odal`. `bootstrap` is idempotent: re-running it against an
already-claimed node fails fast instead of minting duplicate keys (use `--force`
to override, or `odal key create` for additional keys).

---

## API key management

Your node can have multiple API keys — useful for CI, third-party integrations,
or rotating credentials without downtime.

```sh
odal key create ci-pipeline         # mint a new key (secret shown once)
odal key list                       # list all active keys
odal key revoke <id>                # permanently revoke a key
```

To rotate the primary key:
1. Create a new key.
2. Save it to the active profile in `~/.config/odal/credentials.toml` (or re-run
   `odal --reconfigure` and paste it).
3. Revoke the old key.

---

## Facility & operator identifier management

Every passport carries a facility identifier (ESPR Annex III) and a
responsible-operator identifier (ESPR Art. 13). Whichever facility is marked
**default** and whichever operator identifier is marked **primary** are
stamped onto new passports automatically at create time — live, so a change
here takes effect immediately with no node restart. Management is
admin-scoped (a least-privilege API key cannot mutate it). You can also drive
all of this from the Console: **Registry identity** in the top-level menu.

```sh
# Facilities (e.g. manufacturing sites, identified by GS1 GLN)
odal facility list                                   # configured facilities (default marked *)
odal facility add --name "Berlin Plant" --scheme gln \
  --value 4012345000009 --country DE --default       # add + make default
odal facility set-default <id>                       # switch which facility is default
odal facility remove <id>                             # remove a facility

# Operator identifiers (e.g. VAT, LEI, EORI, DUNS)
odal operator-id list                                 # configured identifiers (primary marked *)
odal operator-id add --scheme vat --value DE123456789 --primary
odal operator-id set-primary <id>                     # switch which identifier is primary
odal operator-id remove <id>                          # remove an identifier
```

An operator can register multiple facilities and identifiers — this is
grouping/attribution, never a tenancy or isolation boundary (see ADR-006).

---

## Updating the node

```sh
odal update        # pull latest container images
odal down          # stop running services
odal up            # restart with new images
odal status        # verify healthy
```

Or from the Console: **Infrastructure › Update images**, then **Stop**, then **Start**.

---

## Backup

The node's state lives entirely in PostgreSQL. Back up the `odal` database
according to your DR policy. The key store (`KEY_STORE_PATH`, defaults to
`./keys/`) holds your Ed25519 signing key — include it in backups. Losing the
key store means you cannot sign new passports.

---

## Network / domain setup

Passports include a `did:web` document resolved from `DID_WEB_BASE_URL`.
For this to work publicly:

1. `DID_WEB_BASE_URL` must be a reachable HTTPS URL.
2. Your reverse proxy must forward `/.well-known/did.json` to
   `http://localhost:8001/identity/.well-known/did.json`.
3. DNS must resolve before you run bootstrap — the node validates the URL at
   onboarding time.

**Example nginx location block:**

```nginx
location /.well-known/did.json {
    proxy_pass http://127.0.0.1:8001/identity/.well-known/did.json;
}
location / {
    proxy_pass http://127.0.0.1:8001;
}
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Console shows "not running (connection refused)" | Node not started | Run `odal up` or **Infrastructure › Start** |
| `odal status` shows vault healthy but identity unhealthy | Identity sub-router not responding | Check node logs: `docker compose logs node` |
| `odal bootstrap` fails with 401 | Wrong `ADMIN_USERNAME`/`ADMIN_PASSWORD` | Verify against `.env`; re-run setup |
| API key rejected after update | Old key in config | Run `odal --reconfigure` and re-enter the new key |
| `odal facility add` fails with 422 | Bad GS1 GLN check digit, or facility management attempted with a non-admin key | Verify the GLN; confirm you're using an admin-scoped key |
| DID document not publicly reachable | Proxy not configured or domain not resolving | Verify reverse proxy config and DNS |
