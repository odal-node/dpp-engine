#!/usr/bin/env bash
# Self-test for scripts/ci-guard-check.sh.
#
# A gate nobody has watched fail is a gate nobody knows works, and this one
# exists because a family of guards passed for months while running nowhere that
# mattered. Each case builds a synthetic tree (the gate reads `scripts/` and
# `.github/workflows/` relative to CI_GUARD_ROOT) and asserts what it says.
# No network, no cargo.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/ci-guard-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# A tree the gate must accept: one guard that a workflow runs, one self-test, and
# each of the scripts the gate lists as local-only.
scaffold() {
    local root="$1"
    mkdir -p "$root/scripts" "$root/.github/workflows"
    touch "$root/scripts/a-check.sh" "$root/scripts/a-check.test.sh" \
        "$root/scripts/coderabbit-check.sh" "$root/scripts/shared-test-pg.sh" \
        "$root/scripts/test-changed.sh"
    cat > "$root/.github/workflows/ci.yml" <<'EOF'
jobs:
  a:
    steps:
      - run: bash scripts/a-check.sh
EOF
}

run_case() {
    local name="$1" expect="$2" mutate="$3"
    local root="$TMP/$name"
    scaffold "$root"
    ( cd "$root" && eval "$mutate" )
    if CI_GUARD_ROOT="$root" bash "$GATE" >/dev/null 2>&1; then
        got="accept"
    else
        got="reject"
    fi
    if [ "$got" = "$expect" ]; then
        echo "ok:   $name ($got)"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate said $got, expected $expect"
        fail=$((fail + 1))
    fi
}

# The clean tree is accepted. Without this case the others would pass against a
# gate that rejects everything.
run_case "a_tree_where_every_guard_runs_is_accepted" accept "true"

# 1. The failure that was found: a guard script nothing runs.
run_case "a_guard_no_workflow_runs_is_refused" reject \
    'touch scripts/b-check.sh'

# 2. Mentioned in a comment is documentation, not a run.
run_case "a_guard_named_only_in_a_comment_is_refused" reject \
    'touch scripts/b-check.sh && printf "%s\n" "      # see scripts/b-check.sh" >> .github/workflows/ci.yml'

# 3. A guard in any workflow file counts, not only ci.yml.
run_case "a_guard_run_by_another_workflow_is_accepted" accept \
    'touch scripts/b-check.sh && printf "%s\n" "jobs:" "  b:" "    steps:" "      - run: bash scripts/b-check.sh" > .github/workflows/other.yml'

# 4. Self-tests are run through the guard they test, and need no job of their own.
run_case "an_unreferenced_self_test_is_accepted" accept \
    'touch scripts/b-check.test.sh'

# 5. The clean tree holds all three local-only scripts with no workflow running
#    them, and is accepted, so the listed scripts need none. They must not carry
#    the verdict either: take away the one reference the guard has and it is
#    refused.
run_case "removing_the_only_reference_is_refused" reject \
    'printf "%s\n" "jobs: {}" > .github/workflows/ci.yml'

# 6. An exception cannot outlive the script it excuses.
run_case "a_stale_local_only_entry_is_refused" reject \
    'rm scripts/test-changed.sh'

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
