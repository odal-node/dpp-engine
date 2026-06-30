# `odal` CLI Reference

The `odal` CLI is the **single control plane** for operating a self-hosted Odal
Node. Everything an operator needs — install, onboarding, auth, the full passport
lifecycle — is a CLI command. No hand-run scripts.

- **Binary:** `odal` (crate `dpp-cli`). Build: `cargo build -p dpp-cli`.
- **CLI config (non-secret):** `~/.config/odal/config.toml` — named **profiles**,
  each holding service URLs + an environment kind (`dev`/`prod`), plus the active
  profile. No secrets here.
- **CLI credentials (secret):** `~/.config/odal/credentials.toml` — API keys
  keyed by profile, written owner-only (0600 on Unix). Split out from the config
  so the connection settings are never co-located with secrets (the AWS CLI
  `config`/`credentials` model).
- **Node runtime config** lives in the operator's `.env`; the CLI never creates
  or modifies it.
- **Env overrides (12-factor):** `ODAL_PROFILE`, `ODAL_VAULT_URL`, `ODAL_API_KEY`
  take precedence over the files — so CI never needs anything written to disk.
- **Defaults:** vault `http://localhost:8001/vault`, identity
  `http://localhost:8001/identity`, resolver `http://localhost:8003`.
- **Operator runbook:** `docs/guides/OPERATOR-SETUP.md` — full production setup,
  environment variables, key management, backup, and troubleshooting.

## Profiles & environments (dev vs prod)

`odal` holds multiple node targets side by side as **named profiles** — like
`kubectl` contexts or AWS CLI profiles. Each profile records its service URLs and
a `kind` (`dev` or `prod`); the active profile is shown in a banner on every
console screen so you always know which node you're operating on (prod is
rendered loudly).

- **Active profile selection** (highest precedence first): `--profile <name>` →
  `ODAL_PROFILE` → the saved current profile → `default`.
- **`kind` drives behaviour:** `odal up`/`down`/`update` always operate the full
  self-host stack (`docker-compose.yml` — node + resolver + infra). The kind
  selects how: `dev` (localhost) **builds** the node image from your source tree
  and tolerates dev-default secrets; `prod` (remote) **pulls** the published
  image and runs a `.env` secret preflight. The kind also sets the banner colour.
  (The infra-only `docker-compose.dev.yml` is for engine development —
  `just infra` + `cargo run` — and is not driven by `odal`.)

```sh
odal profile list                          # all profiles (active marked *)
odal profile create prod --vault-url https://node.acme.example/vault
odal profile use prod                      # switch the active profile
odal --profile dev status                  # one-off override
odal profile show                          # active profile (api key masked)
```

---

## Dual-mode operation

`odal` has two modes depending on how it is invoked:

| Invocation | Mode | Use case |
|---|---|---|
| `odal` (no arguments, interactive terminal) | **Console** | Day-to-day operation; guided, menu-driven |
| `odal <command> [flags]` | **Stateless / scripting** | CI/CD, automation, one-shot ops |

Both modes call the same action core — behavior and output are identical; only
the input-gathering layer differs.

### Console

Running `odal` with no arguments and a TTY launches the **Console**: a persistent
menu-driven REPL with a top-level menu of grouped actions that stays open until
you quit. It is the recommended interface for operators.

```
  ⬢  Odal Node — Management Console           v0.1.0
  http://localhost:8001/vault

  ? What would you like to do?  (↑↓ · ⏎ select · Esc to quit)

  ❯ Infrastructure      start · stop · status · update images
    Passports           import · validate · publish · export
    Operator            view · edit configuration
    API keys            create · list · revoke
    Schema              check for updates
    Quit
```

Key behaviours:

- **Guided forms** — each action prompts for its inputs with help text and
  sensible defaults; Esc at any prompt cancels back to the submenu.
- **Confirmation before irreversible actions** — Suspend, Archive, and bulk
  Publish each show a plain-language consequence statement before proceeding.
- **Suggested next steps** — after a successful Import the console offers to
  Validate immediately; after a clean Validate it offers to Publish.
- **Stateless hint** — after each action the equivalent `odal` flag command is
  shown (`≡ odal passport import …`) so operators learn the scriptable form.
- **Remote-node awareness** — when `vault_url` points at a non-localhost address
  (managed microVM), Start / Stop / Update images are hidden from the
  Infrastructure submenu; those commands are meaningless when the platform owns
  the infrastructure.
- **First-run setup** — if no API key is configured, the Console automatically
  launches guided setup on first run. Re-enter any time via "Setup / Reconfigure"
  in the menu, or run `odal --reconfigure` from the shell.
- **Non-TTY guard** — if stdin is not a terminal or `CI=true` is set, running
  `odal` without a subcommand prints help and exits with code 2 instead of
  hanging on a prompt. (`--reconfigure` bypasses the guard since it is a
  deliberate invocation.)

### Stateless / scripting mode

Pass any subcommand to bypass the Console entirely. Exit codes and
stdout are suitable for CI/CD pipelines. All flags are documented below.

---

## Quick start (fresh node → first passport)

Run `odal` with no arguments to launch the guided setup — connect, start, and
configure your node without leaving the Console.

For scripting and CI, all steps are also available as subcommands:

```sh
odal profile create prod --vault-url https://node.acme.example/vault
odal profile use prod
odal init                            # scaffold docker/docker-compose.yml for the active profile
# create .env in the deployment root (DATABASE_POSTGRES_PASS, DATABASE_APP_PASS,
# KEY_STORE_PASSPHRASE, DID_WEB_BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD)
odal up                              # build/pull + start the full stack (node + resolver + infra)
odal status                          # verify services healthy
odal bootstrap                       # mint the first API key (idempotent — refuses if already done)
odal operator set \
  --legal-name "Acme GmbH" --country DE \
  --address "1 Allee, Berlin" \
  --contact-email ops@acme.example   # set the legal operator identity (required before publish)
odal passport import products.csv    # create draft passports
odal passport validate               # check drafts against sector schema
odal passport publish                # sign + publish (mints GS1 Digital Link / QR)
```

> **Bootstrap mints the first key and nothing more.** The legal operator identity
> is set separately (`odal operator set`) and is **enforced at publish time**, not
> at key-mint — so onboarding the technical key and the legal identity are
> decoupled. Re-running `bootstrap` on an already-claimed node is **refused**
> (use `odal key create` for additional keys).

---

## Command reference

### Infrastructure

| Command | Purpose | Auth |
|---|---|---|
| `odal init` | Scaffold `docker/docker-compose.yml`; save connection config | none |
| `odal up` | Start the full stack (node + resolver + infra); dev builds from source, prod pulls + runs a `.env` secret preflight | none |
| `odal down` | Stop the full stack | none |
| `odal update` | Pull latest container images | none |
| `odal status` | Health of vault, identity, resolver | API key |

### Onboarding & auth

| Command | Purpose | Auth |
|---|---|---|
| `odal bootstrap` | Mint the first API key (idempotent; refuses if claimed) | local admin |
| `odal operator show` | Print current operator config | API key |
| `odal operator set [--field value …]` | Update operator fields | API key |
| `odal key create <name>` | Mint API key (secret shown once) | API key |
| `odal key list` | List API keys (prefix only) | API key |
| `odal key revoke <id>` | Deactivate an API key | API key |

### Profiles / environments

| Command | Purpose | Auth |
|---|---|---|
| `odal profile list` | List profiles (active marked `*`) | none |
| `odal profile show [name]` | Show a profile (API key masked) | none |
| `odal profile use <name>` | Switch the active profile | none |
| `odal profile create <name> [--vault-url] [--kind] [--force]` | Add a profile | none |
| `odal profile remove <name>` | Delete a profile (+ its credential) | none |
| `odal profile rename <old> <new>` | Rename a profile (+ its credential) | none |

### Passport lifecycle

| Command | Purpose | Auth |
|---|---|---|
| `odal passport import <file>` | Create draft passports from CSV/TSV/JSON | API key |
| `odal passport validate` | Check drafts for required fields | API key |
| `odal passport publish [id]` | Sign + publish all drafts (or one) | API key |
| `odal passport suspend <id>` | Suspend a published passport (serves 410) | API key |
| `odal passport archive <id>` | Archive (terminal state) | API key |
| `odal passport history <id>` | Passport audit trail | API key |
| `odal passport export [--format] [--status] [-o]` | Export passports (JSON/CSV) | API key |

### Schema

| Command | Purpose | Auth |
|---|---|---|
| `odal schema check` | Check for a sector-schema update | none |

---

## Detailed usage

### `odal init`

Saves connection config for the active profile to `~/.config/odal/config.toml`
and scaffolds `docker/docker-compose.yml` in the current directory if it does not
already exist. Never overwrites an existing compose file. Intended for scripting —
interactive operators should run `odal` instead.

### `odal bootstrap`

Authenticates with the node's local admin (`ADMIN_USERNAME`/`ADMIN_PASSWORD`),
mints the **first** API key, and saves it to `~/.config/odal/credentials.toml`
under the active profile.

**Idempotent and guarded:** before minting, it checks `GET /api/v1/node/state`.
If the node is already claimed (an active key exists) it **refuses** rather than
silently minting a duplicate — pass `--force` to mint an additional key anyway,
or use `odal key create <name>`.

The legal operator identity is *not* required here — bootstrap only handles the
technical key. Set the identity with `odal operator set` (or pass the same flags
to bootstrap as a convenience); it is **enforced at publish time**. Optional
identity flags:

```sh
odal bootstrap \
  --legal-name "Acme GmbH" --country DE \
  --address "1 Allee, Berlin" --contact-email ops@acme.example \
  --did-web-url https://acme.example/.well-known/did.json
```

### `odal passport import <file>`

One passport per record. `.csv`/`.tsv`: `sectorData` is built from headers
(sector defaults to `battery`; add a `sector` column for others like `textile`).
`.json`: a single object or array, posted verbatim. Each record is created as a
**draft** and validated server-side; results are reported per row.

### `odal passport publish [id]`

Signs each draft with Ed25519 (using the operator key stored in the key store),
publishes it, retention-locks it, and mints its GS1 Digital Link. Pass an ID to
publish a single draft; omit to publish all.

### `odal passport export`

Walks the full set (paginated) and writes JSON (default) or CSV to a file
(`-o file`) or stdout. Filter with `--status draft|active|suspended|archived`.
CSV cells are formula-injection-neutralised.

A bare filename (`-o report.csv`) is written to `~/.config/odal/exports/`, so
exports never land in — or get committed from — the working directory. Pass a
path with a directory component (`-o ./report.csv`, `-o /tmp/report.csv`) to
write exactly there.

---

## Notes

- **What's stored where & why.** The CLI is a remote client, so — like `kubectl`
  or `aws` — it must persist *where* the node is and *how* to authenticate.
  Connection settings (non-secret) live per-profile in `config.toml`; API keys
  (secret) live in `credentials.toml` (0600). Both can be overridden from the
  environment (`ODAL_VAULT_URL` / `ODAL_API_KEY` / `ODAL_PROFILE`) so a CI runner
  needs nothing on disk.
- Auth: API-key commands send `Authorization: Bearer odal_sk_…`. `bootstrap` uses
  the local admin credential (`Bearer base64(user:pass)`) because no key exists yet.
- The node applies all migrations automatically on every boot; no manual migration
  step is needed.
- `odal up`/`down`/`update` pick the compose file by the active profile's kind
  (dev → `docker-compose.dev.yml`, prod → `docker-compose.yml`) and search the
  current directory and its parents. Run from anywhere inside your deployment tree.
