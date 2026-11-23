#!/usr/bin/env bash
# Measure what the tests execute: one `cargo llvm-cov` run over the unit tests and
# the Docker-backed suites, merged into one report.
#
# # Why this exists
#
# CLAUDE.md asks that a documented error condition be produced by a test, and
# `documented_error_codes_are_the_ones_handlers_return` checks the codes a handler
# can emit against the spec. Neither says whether any test drives a handler into
# those branches. No coverage was collected across the unit tests and the Docker
# tiers together, and a report of either alone says a branch is untested when the
# other tier runs it. This runs both and merges the profiles (#641).
#
# `scripts/coverage-gaps.sh` reads the report this writes.
#
# # Usage
#
#   COV_OUT=<dir> bash scripts/shared-test-pg.sh bash scripts/coverage.sh
#
# or `just coverage`. Run from the repository root, with Docker running and
# nothing else building: about 25 minutes on a 6-core machine. Needs
# `cargo install cargo-llvm-cov --version 0.9.1 --locked` and
# `rustup component add llvm-tools-preview`. Writes `coverage.json`,
# `coverage.lcov` and `summary.txt` to `COV_OUT` (default `target/coverage`).
#
# # What it runs
#
# The steps of the `test-unit` and `test-integration` jobs in
# `.github/workflows/ci.yml`, each under `cargo llvm-cov nextest --no-report` so
# every one builds instrumented into `target/llvm-cov-target` and leaves its
# profiles there; the final `report` merges all of them. The tiers are the ones
# `just test` and `just _test-integration-tiers` run.
#
# Differences from CI, each on purpose:
#   * `--no-fail-fast`: a failing test must not hide the coverage of the tests
#     after it. Failures are named in the log, and the last line lists the tiers
#     that had any.
#   * the `odal` binary is built by `cargo llvm-cov run` (CI: `cargo build`), so it
#     is instrumented and sits beside `dpp-node`, where `operator_paths.rs` looks.
#   * the S3 server listens on a port of its own, bound to loopback.
#
# # What it cannot see
#
# `operator_paths.rs` starts the real `dpp-node` and `odal` with `env_clear()`, so
# the variable that names the profile file does not reach those two processes and
# what they execute is not collected.
#
# `cargo llvm-cov show-env` is not a way around the script: in 0.9.1 it builds
# into `target/`, not `target/llvm-cov-target`, and instruments through a rustc
# wrapper rather than flags, so it would mix instrumented artefacts into the
# ordinary build directory.
set -euo pipefail

OUT="${COV_OUT:-target/coverage}"
mkdir -p "$OUT"
FAILED=()

command -v cargo-llvm-cov > /dev/null || {
    echo "coverage: cargo-llvm-cov is not installed." >&2
    echo "          cargo install cargo-llvm-cov --version 0.9.1 --locked" >&2
    echo "          rustup component add llvm-tools-preview" >&2
    exit 1
}
: "${ODAL_TEST_PG_ADMIN_URL:?run this inside scripts/shared-test-pg.sh: without a shared Postgres every database test boots its own container}"

step() {
    echo "=== $(date -u +%H:%M:%S) $* | HEAD $(git rev-parse --short=8 HEAD) | rs/lock changes vs HEAD: $(git status --porcelain -- '*.rs' Cargo.toml '*/Cargo.toml' Cargo.lock | wc -l)"
}

# Run a measured step; a failure is recorded and the run goes on.
tier() {
    local name="$1"
    shift
    step "$name"
    "$@" || { echo "TIER-FAILED: $name"; FAILED+=("$name"); }
}

# --- The S3 test server, as CI starts it (ci.yml "Start S3 test server") -------
# The image is the one the tests pin for their own containers.
s3_image="$(sed -nE 's/.*const S3_IMAGE: .*= \("([^"]+)", "([^"]+)"\).*/\1:\2/p' crates/dpp-node/tests/s3_backup.rs)"
[ -n "$s3_image" ] || { echo "coverage: no S3_IMAGE in crates/dpp-node/tests/s3_backup.rs" >&2; exit 1; }
s3_name="odal-coverage-s3-$$"
s3_port="${ODAL_COV_S3_PORT:-59000}"
cleanup() { docker rm -f -v "$s3_name" > /dev/null 2>&1 || true; }
trap cleanup EXIT

access_key=$(openssl rand -hex 16)
secret_key=$(openssl rand -hex 16)
step "s3 server $s3_image on 127.0.0.1:$s3_port"
docker run -d --rm --name "$s3_name" \
    -p "127.0.0.1:$s3_port:9000" \
    --add-host version.rustfs.com:127.0.0.1 \
    -e RUSTFS_ACCESS_KEY="$access_key" \
    -e RUSTFS_SECRET_KEY="$secret_key" \
    "$s3_image" > /dev/null
s3_ready=false
for _ in $(seq 1 60); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$s3_port/health/ready" > /dev/null 2>&1; then
        s3_ready=true
        break
    fi
    sleep 1
done
if [ "$s3_ready" != true ]; then
    echo "coverage: the s3 server did not become ready in 60s" >&2
    docker logs "$s3_name" >&2 || true
    exit 1
fi
export ODAL_TEST_S3_ENDPOINT="http://127.0.0.1:$s3_port"
export ODAL_TEST_S3_ACCESS_KEY="$access_key"
export ODAL_TEST_S3_SECRET_KEY="$secret_key"

# --- The SDK ABI fixture, as CI builds it (ci.yml "Build the SDK ABI fixture") -
# Built here, before any coverage flag is in the environment: the wasm guest cannot
# be instrumented.
step "wasm fixture"
rustup target list --installed | grep -qx wasm32-wasip1 || rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 \
    --manifest-path crates/dpp-plugin-host/tests/fixtures/abi-echo/Cargo.toml

step "clean"
cargo llvm-cov clean --workspace

# --- ci.yml test-unit ----------------------------------------------------------
# CI runs the OpenAPI contract test as its own step and then re-runs it inside
# `--workspace`; one workspace run covers both.
tier unit cargo llvm-cov nextest --no-report --locked --workspace --no-tests=fail --no-fail-fast

# --- ci.yml test-integration -----------------------------------------------------
tier dal cargo llvm-cov nextest --no-report --locked -p dpp-dal \
    --features integration-tests --no-tests=fail --no-fail-fast

tier vault cargo llvm-cov nextest --no-report --locked -p dpp-vault \
    --features integration-tests --no-tests=fail --no-fail-fast

tier plugin-host cargo llvm-cov nextest --no-report --locked -p dpp-plugin-host \
    --features integration-tests,wasm-fixture-tests --no-tests=fail --no-fail-fast

# `operator_paths.rs` drives the real `odal`, another package's binary.
tier odal-build cargo llvm-cov run --no-report --locked -p dpp-cli --bin odal -- --version

tier node cargo llvm-cov nextest --no-report --locked -p dpp-node \
    --features integration-tests --no-tests=fail --no-fail-fast

# --- The merged report ------------------------------------------------------------
step "report"
cargo llvm-cov report --json --output-path "$OUT/coverage.json"
cargo llvm-cov report --lcov --output-path "$OUT/coverage.lcov"
cargo llvm-cov report --summary-only > "$OUT/summary.txt"
step "done; tiers with failures: ${FAILED[*]:-none}"
