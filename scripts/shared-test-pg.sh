#!/usr/bin/env bash
# Run a command against one shared Postgres instead of a container per test.
#
# `start_pg` used to boot a fresh `postgres:17` on every call, from 170 call
# sites. Measured on this workspace, the 171 tests that did so consumed **86% of
# all test time** at 12-16s apiece — nearly all of it container boot, a 1500ms
# settle, and re-running every migration for a schema that never varies.
#
# Sharing one server in-process is not possible: nextest runs each test in its
# own process, so the server has to outlive the process and be discovered
# through the environment. This starts it, points `ODAL_TEST_PG_ADMIN_URL` at
# it, and removes it afterwards however the command exits.
#
# The harness clones a per-test database from a migrated template on that
# server, so tests stay isolated. Measured: ~190ms per clone against 12-16s per
# container.
#
# Suites that must control which migrations run — `start_pg_before` — still
# start their own container, and should: a test of a migration needs a server
# the migration has not been applied to.
#
# Usage: bash scripts/shared-test-pg.sh <command...>
set -euo pipefail

container="odal-shared-test-pg-$$"
port="${ODAL_TEST_PG_PORT:-55432}"

cleanup() {
    docker rm -f "$container" > /dev/null 2>&1 || true
}
trap cleanup EXIT

echo "shared-test-pg: starting $container on port $port"
MSYS_NO_PATHCONV=1 docker run -d --rm \
    --name "$container" \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=test \
    -e POSTGRES_DB=postgres \
    -p "$port:5432" \
    postgres:17 > /dev/null

# Poll rather than sleep a fixed interval: the fixed 1500ms every copy of the
# old harness carried was a guess that had to be right on the slowest machine
# and was wasted on every other one.
ready=false
for _ in $(seq 1 60); do
    if MSYS_NO_PATHCONV=1 docker exec "$container" pg_isready -U postgres > /dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done

if [ "$ready" != true ]; then
    echo "shared-test-pg: postgres did not become ready" >&2
    exit 1
fi

export ODAL_TEST_PG_ADMIN_URL="postgres://postgres:test@127.0.0.1:$port/postgres"
echo "shared-test-pg: ODAL_TEST_PG_ADMIN_URL is set; running: $*"

"$@"
