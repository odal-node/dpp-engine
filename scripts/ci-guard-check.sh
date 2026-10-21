#!/usr/bin/env bash
# Every guard script in scripts/ must run in CI, or say why it does not.
#
# `just check` is the gate a contributor runs and CI is the gate a pull request
# meets. They are two hand-written lists, and nothing related them: six guard
# scripts ran in `just check` and in no workflow, so a pull request that broke
# one passed CI and was stopped only if its author happened to run `just check`.
# Two checks that did run in both were not the same check, either: the copy CI
# carried listed eight of twelve crates by hand.
#
# The rule: every `scripts/*.sh` that is not a self-test (`*.test.sh`) is named
# on a line of a workflow under `.github/workflows/` that is not a comment, or is
# listed below as local-only, with the reason. A script named only in a comment
# does not count; that is documentation, not a run. A listed script that no
# longer exists is an error too, so an exception cannot outlive what it excuses.
#
# What this cannot see: a guard whose body lives in the justfile rather than in a
# script. `check-plugins` is the one, and it is local-only by nature. It compares
# the modification times of a built plugin and its source, and a fresh checkout
# gives every file the moment it was checked out.
#
# Do not widen the list below to make a new script pass. A script that guards the
# repository belongs in CI; the entries are for what cannot or should not run
# there. A list that grows is this check failing at its job.
set -euo pipefail

ROOT="${CI_GUARD_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

# "<script>|<why it does not run in CI>"
local_only=(
  "coderabbit-check.sh|validates .coderabbit.yaml against a schema fetched over the network, and reads a file a service owns; a local aid, not a gate on the code"
  "shared-test-pg.sh|starts a local Postgres for \`just test-integration\`; CI's integration job has its own service container"
  "test-changed.sh|an iteration aid that skips tests on purpose; CI runs the whole suite"
)

status=0

# What the workflows run: every line that is not a comment.
workflow_lines="$(cat .github/workflows/*.yml | grep -v '^[[:space:]]*#' || true)"

is_local_only() {
  local entry
  for entry in "${local_only[@]}"; do
    [ "${entry%%|*}" = "$1" ] && return 0
  done
  return 1
}

for entry in "${local_only[@]}"; do
  name="${entry%%|*}"
  if [ ! -f "scripts/$name" ]; then
    echo "ERROR: $name is listed as local-only but scripts/$name does not exist — remove the entry." >&2
    status=1
  fi
done

for path in scripts/*.sh; do
  name="$(basename "$path")"
  case "$name" in *.test.sh) continue ;; esac
  # A here-string, not a pipe: under `pipefail`, `grep -q` exiting at the first
  # match can SIGPIPE the writer, and the pipeline then reads as "not found".
  if grep -qF "scripts/$name" <<< "$workflow_lines"; then
    continue
  fi
  if is_local_only "$name"; then
    continue
  fi
  echo "ERROR: scripts/$name is run by no workflow." >&2
  echo "       Add a job that runs it, as the neighbouring guards do, or list it in" >&2
  echo "       scripts/ci-guard-check.sh as local-only and say why." >&2
  status=1
done

exit "$status"
