# =============================================================================
# justfile — Odal Node (dpp-engine) task runner
# Install: cargo install just cargo-nextest cargo-audit
# Some recipes need Docker (infra, integration tiers, image builds).
# Usage:   just <recipe>
# =============================================================================

set dotenv-load

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------

# Run unit tests (no Docker) with nextest
test:
    cargo nextest run --workspace

# Run the Docker-backed integration tiers (dal, vault, plugin-host, node)
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo nextest run -p dpp-dal         --features integration-tests
    cargo nextest run -p dpp-vault       --features integration-tests
    cargo nextest run -p dpp-plugin-host --features integration-tests   # fuel test: Linux only
    cargo nextest run -p dpp-node        --features integration-tests

# Run the PostgreSQL integration lane (pg_integration T1–T7; needs Docker)
test-pg:
    cargo nextest run -p dpp-dal --features integration-tests --test pg_integration

# Run clippy (all warnings are errors)
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Clippy the feature-gated integration test code (the normal gate skips it)
lint-integration:
    cargo clippy -p dpp-dal -p dpp-vault -p dpp-plugin-host -p dpp-node --all-targets --features integration-tests -- -D warnings

# Format all code
fmt:
    cargo fmt --all

# Check formatting without modifying files (CI-safe)
fmt-check:
    cargo fmt --all --check

# Forbid println!/eprintln!/dbg! in service-crate src (use tracing:: instead)
debug-check:
    #!/usr/bin/env bash
    set -euo pipefail
    if grep -rn --include="*.rs" \
         -e '\bprintln!' -e '\beprintln!' -e '\bdbg!' \
         --exclude-dir=tests --exclude-dir=benches \
         crates/*/src; then
        echo "ERROR: println!/eprintln!/dbg! in service crate src — use tracing:: instead"
        exit 1
    fi

# Run security audit against the RustSec advisory database
audit:
    cargo audit

# Build documentation (engine does not gate docs with -D warnings yet)
doc:
    cargo doc --workspace --no-deps

# Fast gate (no Docker) — mirrors CI jobs: fmt, clippy, debug-prints, test-unit, audit
check: fmt-check lint debug-check test audit

# Full local CI mirror — adds integration-feature clippy + the Docker tiers (needs Docker running)
ci: check lint-integration test-integration test-pg

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# Release build for all workspace crates
build:
    cargo build --workspace --release

# Build the node image (context = parent dir with dpp-core/ + dpp-engine/ as siblings)
docker-node:
    docker build -f docker/node.Dockerfile -t ghcr.io/odal-node/dpp-node:dev ..

# Build the resolver container image (same sibling-repo context as above)
docker-resolver:
    docker build -f docker/resolver.Dockerfile -t ghcr.io/odal-node/dpp-resolver:dev ..

# Build the node image from the sibling ../dpp-core SOURCE (pre-publish dev:
# the engine uses core API that isn't on crates.io yet). Same parent context;
# BUILD_MODE=local flips node.Dockerfile to patch in the sibling core.
docker-node-local:
    docker build -f docker/node.Dockerfile --build-arg BUILD_MODE=local -t ghcr.io/odal-node/dpp-node:dev ..

# Build the resolver image from the sibling ../dpp-core source (pre-publish dev)
docker-resolver-local:
    docker build -f docker/resolver.Dockerfile --build-arg BUILD_MODE=local -t ghcr.io/odal-node/dpp-resolver:dev ..

# Bring up the full self-host stack, building node/resolver from crates.io.
up:
    docker compose -f docker/docker-compose.yml up -d --build

# Bring up the full stack, building node/resolver from the sibling ../dpp-core
# source (pre-publish dev — use until dpp-core's changes are published).
up-local:
    docker compose -f docker/docker-compose.yml -f docker/docker-compose.local.yml up -d --build

# ---------------------------------------------------------------------------
# Run / dev (dpp-engine is a service; these have no analogue in dpp-core)
# ---------------------------------------------------------------------------

# Start local infrastructure (PostgreSQL + Redis + NATS) via Docker Compose
infra:
    docker compose -f docker/docker-compose.dev.yml up -d

# Stop local infrastructure
infra-down:
    docker compose -f docker/docker-compose.dev.yml down

# Wipe + recreate the dev DB (drops pg-data volume) — fixes migration checksum errors
reset-db:
    docker compose -f docker/docker-compose.dev.yml down -v
    docker compose -f docker/docker-compose.dev.yml up -d

# One-time DB + role provisioning for a MANAGED / external Postgres (RDS, Cloud
# SQL, DBA-provisioned). Creates the `odal` database and sets the odal_app
# password, then you run `just migrate`. NOT needed for the bundled container —
# its image auto-creates the DB on first init. Override the superuser URL and
# app password via env:
#   SUPER_URL=postgres://postgres:PASS@host:5432/postgres DATABASE_APP_PASS=... just db-bootstrap
db-bootstrap SUPER_URL='postgres://postgres:dev_only_password@localhost:5432/postgres':
    psql "{{SUPER_URL}}" -v ON_ERROR_STOP=1 \
      -v app_pass="${DATABASE_APP_PASS:-dev_only_password}" \
      -f ops/bootstrap/bootstrap.sql

# Apply schema migrations. There is no standalone migrator: the node runs the
# embedded sqlx migrations (ops/pg) at boot whenever DATABASE_MIGRATE_URL is set
# (see crates/dpp-node/src/main.rs). So "migrating" = booting the node once with
# that var present. This target makes that explicit for a privileged URL.
#   DATABASE_MIGRATE_URL=postgres://postgres:PASS@host:5432/odal just migrate
migrate:
    DATABASE_MIGRATE_URL="${DATABASE_MIGRATE_URL:-postgres://postgres:dev_only_password@localhost:5432/odal}" \
      cargo run -p dpp-node

# Run the MVP node (vault + identity + integrator on one port). Needs a .env.
node:
    cargo run -p dpp-node

# Run the standalone public resolver
resolver:
    cargo run -p dpp-resolver

# Run the management CLI (debug build): `just cli -- bootstrap`, `just cli -- status`, …
cli *ARGS:
    cargo run -p dpp-cli -- {{ARGS}}

# Launch the interactive console (release build — use this for real operator use)
console:
    cargo run --release -p dpp-cli

# Bootstrap a fresh node (operator config + first API key).
# Requires ADMIN_USERNAME / ADMIN_PASSWORD in .env (auto-loaded).
# Pass operator fields as flags:
#   just bootstrap -- --legal-name "Acme" --country DE --address "..." --contact-email "x@acme.de"
# For interactive setup run `odal` (no args) or `just console` instead.
bootstrap *ARGS:
    cargo run -p dpp-cli -- bootstrap {{ARGS}}

# ---------------------------------------------------------------------------
# Core dependency source (dpp-core: local checkout vs published crates)
# ---------------------------------------------------------------------------

# Build against the sibling ../dpp-core working tree (enables the patch override).
core-local:
    cp .cargo/config.toml.example .cargo/config.toml
    @echo "dpp-core -> local ../dpp-core (patch active). 'just core-published' reverts."

# Build against the published dpp-core crates from the registry (removes the override).
core-published:
    rm -f .cargo/config.toml
    @echo "dpp-core -> published registry versions (Cargo.toml)."

# Build sector Wasm plugin(s) from the sibling ../dpp-core checkout and copy
# them into ./plugins (gitignored). Dev convenience for the `core-local` flow.
# Auto-discovers sector-* crates so it can't drift from dpp-core's plugin list.
# NOTE: these artifacts are UNSIGNED — fine for local `just node` with
# ALLOW_UNSIGNED_PLUGINS=true. Production plugins must come signed from the
# dpp-core release pipeline (see dpp-core PLUGIN-HOST.md §7), not from here.
# Usage:  just build-plugins            # all sectors
#         just build-plugins battery    # one or more ("battery" or "sector-battery")
build-plugins *PLUGINS:
    #!/usr/bin/env bash
    set -euo pipefail
    CORE_DIR="../dpp-core"
    if [ ! -d "$CORE_DIR/plugins" ]; then
        echo "ERROR: $CORE_DIR/plugins not found — this recipe needs the sibling"
        echo "dpp-core checkout (the same one 'just core-local' patches against)."
        exit 1
    fi
    DEST="$(pwd)/plugins"
    mkdir -p "$DEST"
    SECTORS="{{PLUGINS}}"
    if [ -z "$SECTORS" ]; then
        SECTORS="$(ls -d "$CORE_DIR"/plugins/sector-* | xargs -n1 basename)"
    fi
    for raw in $SECTORS; do
        name="${raw#sector-}"
        dir="$CORE_DIR/plugins/sector-${name}"
        if [ ! -d "$dir" ]; then echo "skip: no such plugin '$dir'"; continue; fi
        echo "Building sector-${name}..."
        ( cd "$dir" && cargo build --target wasm32-wasip1 --release )
        art="$(ls "$dir/target/wasm32-wasip1/release/"*.wasm | head -n1)"
        cp "$art" "$DEST/sector-${name}.wasm"
        echo "  -> plugins/sector-${name}.wasm"
    done
    echo "Done. Unsigned; set ALLOW_UNSIGNED_PLUGINS=true for local 'just node'."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# Clean build artefacts
clean:
    cargo clean
