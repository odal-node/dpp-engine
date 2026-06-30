# Odal Node Installer

**License:** BSL-1.1

---

## What This Is

A one-click setup script that scaffolds a complete self-hosted Odal Node stack
using Docker Compose.

---

## Usage

```bash
curl -sSL https://odal-node.io/install.sh | bash
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--no-cli` | — | Skip installing the `odal` CLI |
| `--port PORT` | `8001` | Override the node port |
| `--dir DIR` | `~/.odal` | Installation directory |
| `--version VERSION` | `latest` | Odal Node image tag to install |

Example — custom port, no CLI:
```bash
curl -sSL https://odal-node.io/install.sh | bash -s -- --port 9001 --no-cli
```

---

## What the Script Does

1. Checks prerequisites (`docker`, `docker compose`)
2. Creates `~/.odal/` (or `--dir`)
3. Downloads `docker-compose.yml`
4. Generates a random PostgreSQL password, KeyStore passphrase, and API key
5. Writes `.env` with the generated secrets
6. Runs `docker compose up -d`
7. Polls `/health` endpoints until all services are healthy
8. Optionally installs the `odal` CLI binary
9. Prints a summary: node URL, resolver URL, API key, next steps

The script is **idempotent** — re-running it against an existing installation
will skip secret generation and reuse the existing `.env`.

---

## What Gets Deployed

| Service | Port | Description |
|---|---|---|
| `dpp-node` | 8001 | MVP binary (vault + identity + integrator) |
| `dpp-resolver` | 8003 | Public QR resolution |
| `postgres` | 5432 | PostgreSQL database |

The node exposes sub-routes: `/vault/*`, `/identity/*`, `/integrator/*`.

---

## Files

| File | Description |
|---|---|
| `install.sh` | One-click installer script |
| `docker-compose.yml` | Production Docker Compose file |
| `README.md` | This file |

---

## Manual Setup

If you prefer not to pipe from the internet:

```bash
git clone https://github.com/odal-node/dpp-engine
cd dpp-engine/installer
cp ../. env.example .env
# Edit .env with your preferred passwords
docker compose up -d
```

---

## Architecture

See [../docs/](../docs/) for full architecture documentation.
