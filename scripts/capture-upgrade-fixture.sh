#!/usr/bin/env bash
# Capture a release's upgrade fixture: a database that release's real binaries
# wrote, for `crates/dpp-node/tests/operator_paths.rs` to upgrade to the build
# under test.
#
# Why the binaries of the release, not this build: what an upgrade meets is
# whatever the previous release actually stored, in the shape its own dpp-core
# serialised. A fixture written by the current code would agree with the current
# code by construction. The 0.15.0 upgrade defect (a status change on a passport
# published under dpp-core 0.20.0 was refused by the retention guard) sat for two
# and a half weeks because nothing exercised exactly this.
#
# Run it when a release is tagged, and commit the result. `operator_paths.rs`
# fails a release pull request when the release before it has no fixture, so the
# step cannot be skipped quietly.
#
# Usage: bash scripts/capture-upgrade-fixture.sh <version> [<bin-dir>]
#
#   <version>  the release, e.g. 0.15.0. Tag v<version> must exist locally.
#   <bin-dir>  a directory holding that release's `dpp-node` and `odal`. Without
#              it, the tag is built in a temporary worktree with its own
#              toolchain, which takes a while.
#
# Writes crates/dpp-node/tests/fixtures/upgrade/v<version>/:
#   dump.sql     `pg_dump --inserts` of the node's database
#   public.json  every 200 public read at capture time, by passport id, as the
#                exact body bytes
#
# Needs docker, curl and jq. The ports are overridable: CAPTURE_PG_PORT
# (default 56432) and CAPTURE_NODE_PORT (default 58091).
set -euo pipefail

version="${1:?usage: capture-upgrade-fixture.sh <version> [<bin-dir>]}"
bin_dir="${2:-}"
# Absolute: the script runs the binaries from inside its own scratch directory.
if [ -n "$bin_dir" ]; then bin_dir="$(cd "$bin_dir" && pwd)"; fi
tag="v$version"
repo="$(git rev-parse --show-toplevel)"
out="$repo/crates/dpp-node/tests/fixtures/upgrade/$tag"
pg_port="${CAPTURE_PG_PORT:-56432}"
node_port="${CAPTURE_NODE_PORT:-58091}"
base="http://127.0.0.1:$node_port"
vault="$base/vault/api/v1"

git -C "$repo" rev-parse --verify --quiet "refs/tags/$tag" > /dev/null \
    || { echo "capture: tag $tag does not exist" >&2; exit 1; }

work="$(mktemp -d)"
tree="$work/tree"
container="odal-capture-$$"
node_pid=""

cleanup() {
    [ -n "$node_pid" ] && kill "$node_pid" 2> /dev/null || true
    docker rm -f -v "$container" > /dev/null 2>&1 || true
    git -C "$repo" worktree remove --force "$tree" > /dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# The release's own tree, for its bootstrap SQL and demo corpus, and its
# binaries when none were given.
git -C "$repo" worktree add --detach "$tree" "$tag" > /dev/null
if [ -z "$bin_dir" ]; then
    echo "capture: building $tag (this takes a while)"
    (cd "$tree" && cargo build --locked -p dpp-node -p dpp-cli)
    bin_dir="$tree/target/debug"
fi
for bin in dpp-node odal; do
    [ -x "$bin_dir/$bin" ] || { echo "capture: $bin_dir/$bin is missing" >&2; exit 1; }
done
"$bin_dir/odal" --version | grep -qx "odal $version" \
    || { echo "capture: $bin_dir/odal is not $version" >&2; exit 1; }

secret() { head -c 24 /dev/urandom | base64 | tr -d '/+='; }
admin_user="capture-admin"
admin_pass="$(secret)"
db_pass="$(secret)"

docker run -d --name "$container" -p "127.0.0.1:$pg_port:5432" \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$db_pass" -e POSTGRES_DB=odal \
    -e DATABASE_APP_PASS="$db_pass" \
    -v "$tree/ops/bootstrap/pg-init.sh:/docker-entrypoint-initdb.d/10-roles.sh:ro" \
    -v "$tree/ops/bootstrap/bootstrap.sql:/opt/odal/bootstrap.sql:ro" \
    postgres:17 > /dev/null
ready=false
for _ in $(seq 1 60); do
    if docker logs "$container" 2>&1 | grep -q 'PostgreSQL init process complete' \
        && docker exec "$container" pg_isready -U postgres -d odal > /dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
[ "$ready" = true ] || { echo "capture: postgres did not become ready" >&2; exit 1; }

# An empty environment, run from an empty directory: the node reads `.env` from
# its working directory and every parent, and a developer's would leak in.
mkdir -p "$work/node" "$work/home" "$work/plugins"
(
    cd "$work/node"
    exec env -i PATH="$PATH" HOME="$work/home" \
        DATABASE_URL="postgres://odal_app:$db_pass@127.0.0.1:$pg_port/odal" \
        DATABASE_MIGRATE_URL="postgres://postgres:$db_pass@127.0.0.1:$pg_port/odal" \
        KEY_STORE_PATH="$work/keystore.enc" KEY_STORE_PASSPHRASE="$(secret)" \
        DID_WEB_BASE_URL="$base" RESOLVER_BASE_URL="http://127.0.0.1:1" \
        PORT="$node_port" NODE_PORT="$node_port" METRICS_ADDR="" \
        PLUGINS_DIR="$work/plugins" ADMIN_USERNAME="$admin_user" ADMIN_PASSWORD="$admin_pass" \
        "$bin_dir/dpp-node"
) > "$work/node.log" 2>&1 &
node_pid=$!
curl -s --retry 60 --retry-connrefused --retry-delay 1 --max-time 5 "$base/vault/ready" > /dev/null \
    || { tail -20 "$work/node.log" >&2; exit 1; }

odal() { (cd "$work/node" && HOME="$work/home" ADMIN_PASSWORD="$admin_pass" "$bin_dir/odal" "$@"); }
odal init --node-url "$base" --resolver-url "http://127.0.0.1:1" > /dev/null
odal bootstrap --legal-name "Upgrade Fixture GmbH" --country DE \
    --address "Musterstrasse 1, 10115 Berlin" --contact-email ops@example.com \
    --admin-user "$admin_user" > /dev/null
odal facility add --name "Demo Plant" --scheme gln --value 4012345000009 \
    --country DE --address "Werkstrasse 2, 10115 Berlin" --default > /dev/null
# A registrable primary: from 0.16.0 a battery does not publish under a VAT
# number. The v0.14.0 and v0.15.0 fixtures were seeded with one, as those
# releases allowed, and the upgrade test makes the documented move to an LEI.
odal operator-id add --scheme lei --value 984500ODALEXAMPLE069 --primary > /dev/null
key="$(sed -n 's/^default = "\(.*\)"$/\1/p' "$work/home/.config/odal/credentials.toml")"
auth="authorization: Bearer $key"
json='content-type: application/json'

# One passport in each state an upgrade has to carry: published, suspended,
# superseded with its successor, retired, and draft, plus a keyed request.
ODAL_API_KEY="$key" ODAL_VAULT_URL="$base/vault" bash "$tree/ops/demo/passports/load.sh" > "$work/load.out"
id_of() { awk -v f="$1" '$1 == f { print $3 }' "$work/load.out"; }
expect() {
    local want="$1"; shift
    local got
    got="$(curl -sS -o /dev/null -w '%{http_code}' "$@")"
    [ "$got" = "$want" ] || { echo "capture: expected $want, got $got: $*" >&2; exit 1; }
}
expect 200 -X POST "$vault/dpp/$(id_of 06-battery-portable-nimh.json)/suspend" \
    -H "$auth" -H "$json" -d '{"reason":"upgrade fixture"}'
expect 201 -X POST "$vault/dpp/$(id_of 02-battery-industrial-lfp.json)/amend" \
    -H "$auth" -H "$json" -d '{"patch":{"productName":"LFP stationary pack, corrected"},"reason":"upgrade fixture"}'
odal passport import "$tree/ops/demo/datasets/01-textile-small-valid.csv" > /dev/null
odal --idempotency-key upgrade-fixture-facility facility add --name "Second Plant" \
    --scheme gln --value 4012345000016 --country DE > /dev/null
draft="$(docker exec "$container" psql -U postgres -d odal -tAc \
    "SELECT id FROM odal.passport WHERE status = 'draft' ORDER BY id LIMIT 1")"
# `retire` since 0.15.0; `archive` before it.
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$vault/dpp/$draft/retire" -H "$auth")"
[ "$code" = 200 ] || expect 200 -X POST "$vault/dpp/$draft/archive" -H "$auth"

mkdir -p "$out"
echo '{}' > "$work/public.json"
# Only a `200` is captured, since only a served view has bytes to compare. Every
# other answer is printed rather than skipped in silence: a suspended passport's
# `410` is expected, and so is the `404` a retired draft that was never published
# answers. (A release before #570 answered `500` for it, so capturing one still
# prints that.) A failed request means the node is not answering, and nothing
# captured after that could be trusted, so it stops the capture.
for id in $(docker exec "$container" psql -U postgres -d odal -tAc \
    "SELECT id FROM odal.passport WHERE status <> 'draft' ORDER BY id"); do
    code="$(curl -sS -o "$work/body" -w '%{http_code}' "$base/vault/public/dpp/$id" || true)"
    case "$code" in
        200)
            jq --arg id "$id" --rawfile body "$work/body" '. + {($id): $body}' \
                "$work/public.json" > "$work/public.next"
            mv "$work/public.next" "$work/public.json"
            ;;
        000)
            echo "capture: the node did not answer the public read of $id" >&2
            exit 1
            ;;
        *) echo "capture: not captured, $id answered $code" ;;
    esac
done
jq -S . "$work/public.json" > "$out/public.json"

kill "$node_pid"
wait "$node_pid" 2> /dev/null || true
node_pid=""

# `--inserts` because the test loads this through sqlx, which cannot run COPY's
# inline data. pg_dump's `\restrict` lines are psql meta-commands for the same
# reason, and are dropped.
{
    echo "-- dpp-engine $tag ($(git -C "$repo" rev-parse --short "$tag^{commit}")), captured by"
    echo "-- scripts/capture-upgrade-fixture.sh on $(date -u +%Y-%m-%d). Do not edit: re-capture."
    echo "-- Written by dpp-node sha256:$(sha256sum "$bin_dir/dpp-node" | cut -d' ' -f1)"
    docker exec "$container" pg_dump -U postgres -d odal --no-owner --inserts \
        | grep -v -e '^\\restrict ' -e '^\\unrestrict '
} > "$out/dump.sql"

echo "capture: wrote $out ($(jq length "$out/public.json") public reads)"
