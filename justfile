# =============================================================================
# justfile — Odal Node (dpp-engine) task runner
# Install: cargo install just cargo-nextest cargo-audit cargo-deny
# Some recipes need Docker (infra, integration tiers, image builds).
# Usage:   just <recipe>
# =============================================================================

set dotenv-load

# Pinned Redocly CLI release. CI pins the same string; the two must stay equal
# or they will disagree about what the spec is allowed to contain.
REDOCLY_VERSION := "2.46.2"

# ---------------------------------------------------------------------------
# Why the gate's checks live in scripts/ rather than as shebang recipes
#
# `just` runs a recipe whose body starts with `#!` as a script, and on Windows it
# translates the interpreter path with `cygpath`. Where `cygpath` is not on PATH
# the recipe dies with "Could not find `cygpath` executable" and takes `just
# check` down with it — which makes CLAUDE.md's "never commit before `just check`
# is green" unsatisfiable. That is a real failure and it is why this started, but
# state it accurately: it depends on the Git Bash install, not on Windows as
# such. A checkout with `cygpath` present (it ships at `/usr/bin/cygpath` in a
# full Git for Windows) runs the shebang recipes fine, so this is a portability
# hazard rather than a platform-wide break.
#
# The reasons that hold everywhere, and are why the change is worth making
# regardless of which shell you have:
#
# - A script can be run and tested on its own (`bash scripts/x.sh`), which a
#   recipe body cannot. `scripts/check-audit-register.sh` already had a
#   `.test.sh` beside it for exactly that reason.
# - The rule and its allow-list get one home, next to the code that enforces
#   them, instead of being embedded in a task runner.
# - No interpreter translation happens at all, so the hazard above cannot recur.
#
# `set shell` is not the fix: it applies to recipes *without* a shebang, and
# those run each line in its own shell, which breaks any script using a variable.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------

# Run unit tests (no Docker) with nextest
test:
    cargo nextest run --workspace

# Compile the Docker-backed integration tests without running them.
#
# `test` above omits `--features integration-tests`, so those suites are never
# built locally — a stale import in one of them compiles fine here and fails in
# CI, which is exactly what happened when the credential types moved to
# `dpp-vc`. Running them needs Docker; *compiling* them does not, so the local
# gate can at least prove they still build.
check-integration:
    bash scripts/check-integration.sh

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

# Simulate the whole eIDAS sealing loop and print every record it produces
# (needs Docker). Publish -> outbox -> drain -> seal on the passport, with real
# Postgres, real Ed25519 signing and the real adapter over real HTTP; only the
# provider endpoint is a local stand-in, and it verifies the HMAC by recomputing
# it over the bytes it received. Use this to inspect what a seal actually looks
# like before eID Easy sandbox credentials exist.
seal-sim:
    cargo test -p dpp-node --features integration-tests --test seal_outbox -- --nocapture --test-threads=1

# The database-level half of the same feature: migration 0028, the retention
# guard, the (passport_id, payload_hash) key and the payload_hash CHECK.
test-seal-db:
    cargo nextest run -p dpp-dal --features integration-tests --test pg_seal_outbox

# Run clippy (all warnings are errors)
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Clippy the feature-gated integration test code (the normal gate skips it)
lint-integration:
    cargo clippy -p dpp-dal -p dpp-vault -p dpp-plugin-host -p dpp-node --all-targets --features integration-tests -- -D warnings

# Validate api/openapi.yaml (needs Node; no install — npx fetches on demand).
#
# Redocly is already the tool behind the generated api/openapi.html, so this is
# the same validator that renders the spec. `.redocly.lint-ignore.yaml` baselines
# the problems the spec has today so this passes now and fails on NEW ones —
# shrink that file, never regenerate it, or the gate stops meaning anything.
#
# The version is pinned and CI pins the same one. With `@latest` the two
# disagree about what is valid the moment Redocly publishes, and a spec that did
# not change starts failing. Bump both together or not at all.
#
# Not in `just check`: this needs Node and the network, which nothing else in
# that gate does. CI is what enforces it.
#
# Lints the BUNDLE, not the multi-file root. `.redocly.lint-ignore.yaml` is
# keyed by filename and JSON pointer; the bundle has the same document shape the
# baseline was written against, so those pointers still resolve. Linting the
# root instead would report every problem against a `paths/*.yaml` file and
# force the baseline to be regenerated.
openapi-check: openapi-bundle
    git diff --exit-code -- api/openapi.bundled.yaml
    npx --yes @redocly/cli@{{ REDOCLY_VERSION }} lint api/openapi.bundled.yaml

# Regenerate the single-file bundle from the multi-file tree.
#
# api/openapi.bundled.yaml is a committed build artifact: the docs site verifies
# its vendored copy with `git show <commit>:<path>`, which reads a blob out of
# history and so cannot see a file that only exists after a build step.
# `redocly bundle` is byte-deterministic, so `openapi-check` can prove the
# committed bundle still matches the tree with a plain diff.
openapi-bundle:
    npx --yes @redocly/cli@{{ REDOCLY_VERSION }} bundle api/openapi.yaml -o api/openapi.bundled.yaml

# Regenerate the browsable spec (api/openapi.html, git-ignored build artifact).
openapi-html:
    npx --yes @redocly/cli@{{ REDOCLY_VERSION }} build-docs api/openapi.bundled.yaml -o api/openapi.html

# Capture a frozen stored-doc fixture for the compatibility guard (needs Docker).
#
# Creates and publishes a passport through the real vault, then writes the row's
# `doc` to crates/dpp-dal/tests/fixtures/passport_docs/{sector}/v{version}.json.
# The version comes from the stored document, not from an argument — the point is
# to record what the system wrote, not what we expected it to write.
#
# Run this when a sector's schema_version moves, BEFORE bumping dpp-domain: a
# fixture captured after the bump can only catch the bump after next. It refuses
# to overwrite an existing fixture, because a frozen document that gets rewritten
# has stopped being evidence about the release that produced it.
capture-fixture SECTOR:
    cargo test -p dpp-vault --features integration-tests \
        --test capture_doc_fixture capture_{{SECTOR}} -- --ignored --exact --nocapture

# Format all code
fmt:
    cargo fmt --all

# Check formatting without modifying files (CI-safe)
fmt-check:
    cargo fmt --all --check

# Forbid println!/eprintln!/dbg! in service-crate src (use tracing:: instead)
debug-check:
    bash scripts/debug-check.sh

# Forbid raw "dpp.passport."/"dpp.import." subject literals outside dpp-common::event
# (event_type/NATS-subject strings must come from the `subjects` constants, or a
# renamed subject silently stops matching subscribers).
#
# The service crates are listed explicitly rather than globbed, matching the CI
# job of the same name. A `crates/*/src` glob also covers crates that cannot
# comply: `dpp-types` is pure data and depends only on dpp-domain/dpp-rules, so
# reaching the constants would mean taking a dependency on dpp-common and
# inverting the layering. Globbing made this recipe fail where CI passed, which
# is worse than not checking those crates — a local gate that cries wolf is one
# people stop running.
subjects-check:
    bash scripts/subjects-check.sh

# Every table with a live DELETE grant must be named in ops/pg/README.md.
#
# "The app role cannot DELETE" is the sentence a reader uses to reason about
# whether an application-level compromise can destroy evidence, and it drifted:
# CLAUDE.md and .env.example both said "one sanctioned exception" while three
# tables carried the grant. Both now point at the README; this keeps it true.
#
# The list lives in the README rather than in 0010 because a migration cannot be
# edited once applied (see migrations-check) and this list must be.
grants-check:
    bash scripts/grants-check.sh

# Refuse a modification to a migration that already exists on the default branch.
#
# `sqlx::migrate!` checksums every file, so editing an applied one makes a node
# that has already run it refuse to boot — a hard failure with no in-product
# remedy. `reset-db` below exists because this has already happened once (0015,
# a comment-only change during a repo-wide sweep). "Append-only" was written
# down as "never renumbered", which a comment sweep respects while breaking the
# checksum, so this checks the property that actually matters.
migrations-check:
    bash scripts/migrations-check.sh

# Forbid un-guarded outbound HTTP client construction in service crate src.
#
# The rule, the allow-list and the reasoning live in scripts/outbound-check.sh —
# one home, and a script that can be run and tested on its own.
outbound-check:
    bash scripts/outbound-check.sh

# Forbid public type/fn/const definitions in mod.rs (index files should be
# `mod`/`pub use` only — the re-layout's whole point). Two allocation-plan
# exceptions are named and excluded: service/mod.rs (PassportService + its
# builders) and validate/mod.rs (dispatch fn + its error type).
mod-rs-check:
    bash scripts/mod-rs-check.sh

# The API description's version must match the workspace crate version. Pure
# text comparison — no Node, so unlike openapi-check this belongs in the gate.
spec-version-check:
    bash scripts/spec-version-check.sh

# Run security audit against the RustSec advisory database. --deny yanked/
# unmaintained so those stop passing silently (a yanked crate is a
# maintainer's explicit "don't use this") — kept separate from vulnerability
# denial (already the default) so the two classes can be tuned independently.
audit:
    cargo audit --deny yanked --deny unmaintained
    bash scripts/check-audit-register.sh
    bash scripts/check-audit-register.test.sh
    cargo deny check bans licenses sources

# Build documentation (engine does not gate docs with -D warnings yet)
doc:
    cargo doc --workspace --no-deps

# Fast gate (no Docker) — mirrors CI jobs: fmt, clippy, debug-prints, test-unit, audit
check: fmt-check lint debug-check subjects-check mod-rs-check harness-check spec-version-check outbound-check grants-check migrations-check check-plugins test check-integration audit

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
        # The sector plugins share ONE cargo workspace, so cargo writes to
        # plugins/target — not plugins/sector-<name>/target. This read the
        # per-crate path, which stale target dirs from an older layout still
        # populate, so `ls | head -n1` found a months-old binary, `cp` succeeded,
        # and the recipe reported success while shipping it. Name the artifact
        # instead of globbing, so a miss is an error rather than a wrong file.
        art="$CORE_DIR/plugins/target/wasm32-wasip1/release/sector_${name}.wasm"
        if [ ! -f "$art" ]; then
            echo "ERROR: cargo reported success but $art does not exist."
            exit 1
        fi
        # A build that produced nothing is the failure this recipe exists to
        # make impossible. One find pass, not a per-file loop.
        if [ -n "$(find "$dir/src" "$dir/Cargo.toml" -newer "$art" | head -n1)" ]; then
            echo "ERROR: $art is older than its own source — the build did not run."
            exit 1
        fi
        cp "$art" "$DEST/sector-${name}.wasm"
        echo "  -> plugins/sector-${name}.wasm"
    done
    echo "Done. Unsigned; set ALLOW_UNSIGNED_PLUGINS=true for local 'just node'."

# Fail when an installed plugin binary is older than the source it was built
# from. `build-plugins` copies unsigned dev artifacts in, and nothing else
# notices when one goes stale — the battery plugin ran two months behind its
# source because the copy step read a directory cargo had stopped writing to.
#
# Skips cleanly when the sibling checkout is absent, so CI (which has no
# ../dpp-core and loads signed artifacts anyway) stays green.
check-plugins:
    #!/usr/bin/env bash
    set -euo pipefail
    CORE_DIR="../dpp-core"
    if [ ! -d "$CORE_DIR/plugins" ]; then
        echo "check-plugins: no sibling dpp-core checkout — skipped."
        exit 0
    fi
    shopt -s nullglob
    stale=0
    for art in plugins/*.wasm; do
        name="$(basename "$art" .wasm)"; name="${name#sector-}"
        dir="$CORE_DIR/plugins/sector-${name}"
        [ -d "$dir" ] || continue
        if [ -n "$(find "$dir/src" "$dir/Cargo.toml" -newer "$art" | head -n1)" ]; then
            echo "STALE: $art is older than $dir/src — run 'just build-plugins ${name}'"
            stale=1
        fi
    done
    if [ "$stale" -ne 0 ]; then exit 1; fi
    echo "check-plugins: all installed plugin binaries are newer than their sources."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# Clean build artefacts
clean:
    cargo clean

# Refuse a forked copy of shared test scaffolding.
#
# Rust cannot share `#[cfg(test)]` code across crates, so copying is the path of
# least resistance and nothing signals when it happens: the Postgres harness
# reached eight copies and six divergent implementations before anyone counted.
# Both it and the in-memory PassportRepository double now live behind dpp-dal's
# `test-harness` feature; this is the signal that was missing.
harness-check:
    bash scripts/harness-check.sh

# Run only the tests a change can affect.
#
# Maps changed files to their crates and hands nextest an `rdeps()` filterset.
# Measured against the 1,041-test workspace: a dpp-resolver edit selects 67
# tests, dpp-integrator 247, dpp-vault 471, dpp-dal 511.
#
# An iteration aid, not a gate. It reasons about crate boundaries, not
# behaviour, and falls back to the full suite whenever a change is not
# attributable to one crate. Run `just check` before pushing regardless.
test-changed BASE="origin/main":
    bash scripts/test-changed.sh {{ BASE }}
