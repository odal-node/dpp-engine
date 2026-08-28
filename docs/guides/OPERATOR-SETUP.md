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
# .env — never commit this file. `odal` does not create or modify it.

# --- Required. The node refuses to start a prod profile without these. ---
DATABASE_POSTGRES_PASS=<strong-random-password>   # Postgres superuser (migrations)
DATABASE_APP_PASS=<different-strong-password>     # odal_app role the node connects with
KEY_STORE_PASSPHRASE=<passphrase-for-the-Ed25519-key-store>
DID_WEB_BASE_URL=https://your-domain.example
ADMIN_USERNAME=<your-admin-login>                 # NOT "admin" — see below
ADMIN_PASSWORD=<temporary-admin-password>

# --- Required before you publish anything. ---
# The public origin printed onto the product. Every passport's QR code resolves
# against this, permanently. Each operator serves their own resolver — the
# built-in default is the project's demo resolver and is not wired up, so
# leaving it prints codes that resolve to nothing.
RESOLVER_BASE_URL=https://dpp.your-domain.example

# --- Optional. Defaults shown. ---
NODE_PORT=8001
RESOLVER_PORT=8003
```

> **`ADMIN_USERNAME=admin` is rejected.** A `prod` profile runs a secrets
> preflight before starting, and `admin` is on its list of known dev defaults
> alongside `dev_only_password` and `change_me_in_env`. `odal up` will refuse
> with *"ADMIN_USERNAME is still a dev default"*. Pick a real username.

> The node applies all database migrations at startup — there is no manual
> migration step. First boot takes about 90 seconds: it loads each Wasm product group
> plugin in turn before it starts listening.

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

Before your first publish you must **also** register at least one **facility**
and one **operator identifier** — see [Facility & operator identifier
management](#facility--operator-identifier-management) below. These are a hard
publish gate, not a recommendation: publish refuses with

```
cannot publish: missing required registry identity — facility (Annex III unique
facility identifier); operatorIdentifier (Annex III responsible-operator
identifier).
```

They are what satisfies ESPR Annex III (unique facility identifier) and Art. 13
(economic-operator identifier) on every passport you create afterwards.

After setup, the Console drops into its normal top-level menu.

---

## Profiles & environments

The CLI keeps multiple node targets as named **profiles** (like `kubectl`
contexts). The active profile is shown in a banner on every screen — prod is
rendered loudly so you always know what you're operating on.

```sh
odal profile list                       # all profiles (active marked *)
odal profile create prod --node-url https://node.acme.example \
    --resolver-url https://dpp.acme.example
odal profile use prod                   # switch
odal --profile dev status               # one-off override
```

The profile's **kind** (`dev`/`prod`) does not change which stack starts —
`odal up`/`down`/`update` always target the full self-host stack (node +
resolver + infra). What it changes is that a **prod** profile **refuses to start
on missing or dev-default secrets**. Whether `odal up` builds the images from
source or uses the published ones is decided separately, by whether the install
actually carries the engine source tree.

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
- **Schema** — check for product-group schema updates

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

For non-interactive setup (e.g. in a deployment pipeline). This is the whole
path from an empty directory to a published passport, in order — every step
depends on the ones above it:

```sh
# 1. Point the CLI at the node, and scaffold the install files.
odal profile create prod --node-url https://node.example.com \
    --resolver-url https://dpp.example.com
odal --profile prod init          # writes docker/ and ops/bootstrap/

# 2. Create .env next to docker/ — see "First-time setup" above.
#    `odal` never writes this file. `odal up` refuses without it.

# 3. Start the stack. First boot takes ~90s (Wasm plugins load serially).
odal --profile prod up
odal --profile prod status        # wait for vault/identity/resolver OK

# 4. Claim the node and mint the first API key. Idempotent — a claimed node
#    is refused rather than given a second key.
odal --profile prod bootstrap \
  --admin-user "$ADMIN_USERNAME" --admin-pass "$ADMIN_PASSWORD"

# 5. Operator identity. Required before publish.
odal --profile prod operator set \
  --legal-name "Acme GmbH" --country DE \
  --address "1 Allee, Berlin" --contact-email ops@acme.example

# 6. Registry identity. ALSO required before publish — publish 422s without
#    both of these, however complete the operator identity is.
odal --profile prod facility add \
  --name "Berlin Plant" --scheme gln --value 4012345000009 \
  --country DE --default
odal --profile prod operator-id add \
  --scheme vat --value DE123456789 --primary

# 7. Load products, check them, issue them.
odal --profile prod passport import products.csv
odal --profile prod passport validate      # stored drafts
odal --profile prod passport publish
```

Check what your credential actually is at any point:

```sh
odal --profile prod whoami        # identity, scope, key id
```

`whoami` is the only authenticated route a `read`-scoped key can reach —
`odal key list` needs `admin`, so without it a least-privilege key has no way to
discover its own limits short of having a write rejected.

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
grouping/attribution, never a tenancy or isolation boundary.

---

---

## What your data has to look like

**GTINs must be GTIN-14 with a valid check digit** — exactly 14 ASCII digits.
A 13-digit retail GTIN is not accepted as-is; pad it on the left with a zero,
which GS1 defines as the same identifier and which preserves the check digit.
The importer names the digit it expected, so a rejected row tells you the answer:

```
✗ Row 1 [gtin]: GTIN check digit invalid for '03801234567890': expected 8, got 0
```

Product group templates with the current required columns live in
`crates/dpp-integrator/templates/` (`textile-v1.csv`, `battery-v1.csv`, …), and
worked examples in `ops/demo/datasets/`.

**One file, one product group.** The product group is read from the first data row and applied
to the whole file, so a file mixing product groups is validated entirely against
whichever product group came first. Split them.

**Check a file before you commit to it.** `odal passport validate <file>`
dry-runs a single passport body against the node and writes nothing:

```
✓ create   would be accepted
✓ publish  passes the product-group-data schema gate
```

Read that second line precisely. It is the product-group-data schema gate alone —
publish additionally requires the registry identity above, and category-mandatory
content for some product categories, neither of which the preview runs.

---

## What this node's output is worth

Run `odal status` after onboarding and read the **TRUST** section:

```
TRUST
profile             development
seal                ghost
archive             ghost
ruleset             baseline

! Running on a stand-in: archive, credential_issuers, registry_sync, seal.
  Simulated, not the real service — nothing this node produces
  is fit for compliance use.
```

A stock node runs every trust port on a stand-in. Passports it issues are
well-formed, signed with your own Ed25519 key, and independently verifiable —
but the qualified seal, the third-party archive, and the registry notifications
are simulated. Wiring those up is a separate exercise; until then, treat the
output as operationally real and legally not.

`odal seal status` reports the sealing side specifically.

---

## Passports are hard to take back

Two things to know before you publish at scale:

**The carrier URL is permanent.** `RESOLVER_BASE_URL` is baked into every
passport's QR code at publish time. Getting it wrong means reprinting labels.

**Publishing starts a retention clock.** ESPR retention is enforced by the node,
not just documented: `odal passport archive` refuses inside the window.

```
Error: archive failed: retention policy forbids archiving before 2036-08-18
```

To withdraw a passport from public view, suspend it — `odal passport suspend
<id>` — which serves `410 Gone` on the passport's own URL. Suspension is
reversible; archiving is terminal and gated.

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

Two things must be backed up together, and losing either is unrecoverable.

**1. The database.** All node state lives in PostgreSQL. Back up the `odal`
database according to your DR policy.

**2. The Ed25519 signing key.** In the containerised stack it is
`/data/keystore.enc` inside the node container, on the **`node-data` Docker
volume** — not a file in your install directory. The compose file pins it there
deliberately: `.env`'s `KEY_STORE_PATH` default would land it in the container's
throwaway layer, where a recreate mints a new key and invalidates every passport
ever signed.

```sh
# Copy the key store out of the running node
docker compose cp node:/data/keystore.enc ./keystore-backup.enc

# Or archive the whole volume
docker run --rm -v odal-node_node-data:/data -v "$PWD":/backup alpine \
    tar czf /backup/node-data.tar.gz -C /data .
```

Back it up encrypted, and keep `KEY_STORE_PASSPHRASE` somewhere separate — the
file is useless without it, and so are you without the file. Losing the key
store means you cannot sign new passports, and cannot re-sign the ones you have.
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
| `odal up` fails: *"is still a dev default"* | A `prod` profile's `.env` still has a placeholder — commonly `ADMIN_USERNAME=admin` | Set real values; `admin`, `dev_only_password` and `change_me_in_env` are all rejected |
| `odal up` fails: *"this install is missing files the stack needs"* | The install predates `odal init` scaffolding `ops/bootstrap/` | Run `odal init` again — it writes what is missing and leaves existing files alone |
| Node stays `health: starting`, logs repeat *"password authentication failed for user odal_app"* | The database role never got its password, because the role-provisioning hook was not mounted | Confirm `ops/bootstrap/` exists next to `docker/`, then recreate the stack (the hook only runs on first volume init) |
| Any command: *"No profile configured yet"* | Nothing is configured on this machine | `odal init` or `odal profile create <name> --node-url <url>` |
| `odal passport publish` fails 422: *"missing required registry identity"* | No default facility and/or no primary operator identifier | `odal facility add … --default` and `odal operator-id add … --primary` |
| `odal passport import` rejects every row on `gtin` | GTINs are 13-digit, or their check digit is wrong | Use GTIN-14; the error names the expected check digit |
| `odal passport archive` fails: *"retention policy forbids archiving before …"* | ESPR retention is still running on that passport | Use `odal passport suspend <id>` to withdraw it from public view instead |
| `odal verify <id>` says *"Dossier not found"* | A **passport** id was passed | `verify` takes a **dossier** id — generate one with `odal passport evidence <passport-id>` |
| Scanned QR codes resolve to nothing | `RESOLVER_BASE_URL` was left at its default when those passports were published | Set it to your own resolver before publishing; already-published carriers cannot be changed |
| A second `odal up` elsewhere on the host took over the first deployment | The compose project name is fixed, so all install roots share one deployment | Run one deployment per host, or set `COMPOSE_PROJECT_NAME` |
| Console shows "not running (connection refused)" | Node not started | Run `odal up` or **Infrastructure › Start** |
| `odal status` shows vault healthy but identity unhealthy | Identity sub-router not responding | Check node logs: `docker compose logs node` |
| `odal bootstrap` fails with 401 | Wrong `ADMIN_USERNAME`/`ADMIN_PASSWORD` | Verify against `.env`; re-run setup |
| API key rejected after update | Old key in config | Run `odal --reconfigure` and re-enter the new key |
| `odal facility add` fails with 422 | Bad GS1 GLN check digit, or facility management attempted with a non-admin key | Verify the GLN; confirm you're using an admin-scoped key |
| DID document not publicly reachable | Proxy not configured or domain not resolving | Verify reverse proxy config and DNS |
