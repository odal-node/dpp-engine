#!/usr/bin/env bash
# Self-test for scripts/migrations-check.sh.
#
# A gate nobody has watched fail is a gate nobody knows works, and this one has a
# second way to be wrong: it depends on the shape of the git checkout it runs in.
# Run in CI it printed "skipping" and exited 0 on every pull request, because the
# CI checkout tracks one ref and never has `origin/main`. A green tick that checks
# nothing is the failure a grep gate's self-test cannot see, so each case below
# builds a real repository in the shape CI hands over and asserts what the gate
# says about it.
#
# `upstream` is the repository on the other side of `origin`. `merge-edit` and
# `merge-add` are the merge commits CI checks out for a pull request that edits an
# applied migration and one that only adds a new one. No network, no cargo.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/migrations-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t

pass=0
fail=0

UP="$TMP/upstream"
git init -q -b main "$UP"
mkdir -p "$UP/ops/pg"
echo "SELECT 1; -- applied" > "$UP/ops/pg/0001_init.sql"
git -C "$UP" add -A && git -C "$UP" commit -qm "base"
echo "SELECT 2;" > "$UP/ops/pg/0002_more.sql"
git -C "$UP" add -A && git -C "$UP" commit -qm "more on main"

# A pull request that edits a migration main already has, and its merge commit.
git -C "$UP" checkout -qb pr-edit main~1
echo "SELECT 1; -- edited after it was applied" > "$UP/ops/pg/0001_init.sql"
git -C "$UP" commit -qam "edit an applied migration"
git -C "$UP" checkout -qb merge-edit main
git -C "$UP" merge -q --no-ff pr-edit -m "merge pr-edit"

# A pull request that only adds one.
git -C "$UP" checkout -qb pr-add main~1
echo "SELECT 3;" > "$UP/ops/pg/0003_new.sql"
git -C "$UP" add -A && git -C "$UP" commit -qm "add a migration"
git -C "$UP" checkout -qb merge-add main
git -C "$UP" merge -q --no-ff pr-add -m "merge pr-add"
git -C "$UP" checkout -q main

# What the gate says about a checkout. `ci` is "ci" to run it as GitHub Actions
# does (CI is set), anything else to run it as a developer would.
verdict() {
    local dir="$1" ci="$2"
    if ( cd "$dir" && env -u CI -u MIGRATION_BASE ${ci:+CI=true} bash "$GATE" >/dev/null 2>&1 ); then
        echo accept
    else
        echo reject
    fi
}

check() {
    local name="$1" expect="$2" dir="$3" ci="${4:-}"
    local got
    got="$(verdict "$dir" "$ci")"
    if [ "$got" = "$expect" ]; then
        echo "ok:   $name ($got)"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate said $got, expected $expect"
        fail=$((fail + 1))
    fi
}

# A full clone, as `fetch-depth: 0` makes: every branch and all of the history.
git clone -q "file://$UP" "$TMP/full-edit" && git -C "$TMP/full-edit" checkout -q origin/merge-edit
git clone -q "file://$UP" "$TMP/full-add" && git -C "$TMP/full-add" checkout -q origin/merge-add
# CI's default checkout: one ref, one commit, so no `origin/main` and no history.
git clone -q --depth 1 --branch merge-edit "file://$UP" "$TMP/shallow-edit"
# One ref but complete history: the gate has to fetch `origin/main` itself.
git clone -q --single-branch --branch merge-edit "file://$UP" "$TMP/single-edit"
# A repository with no remote at all.
git init -q -b main "$TMP/no-remote" && git -C "$TMP/no-remote" commit -q --allow-empty -m init
# A branch that shares no history with main, so there is no merge base.
git clone -q "file://$UP" "$TMP/unrelated" && git -C "$TMP/unrelated" checkout -q --orphan unrelated
mkdir -p "$TMP/unrelated/ops/pg" && echo "SELECT 9;" > "$TMP/unrelated/ops/pg/0009_x.sql"
git -C "$TMP/unrelated" add -A && git -C "$TMP/unrelated" commit -qm "unrelated"

# 1. The point of the gate: an applied migration was edited.
check "an_edited_applied_migration_is_refused" reject "$TMP/full-edit" ci

# 2. Without this case the others would pass against a gate that rejects everything.
check "a_new_migration_is_accepted" accept "$TMP/full-add" ci

# 3. CI's own checkout: one commit, no history. The gate fetches the base, but a
#    merge base cannot be computed, so nothing can be checked and it must not pass.
check "a_ci_checkout_with_no_history_does_not_pass" reject "$TMP/shallow-edit" ci

# 4. The same on a developer's machine. A shallow clone cannot be checked either,
#    and is told so rather than given a pass.
check "a_shallow_clone_cannot_be_checked_and_says_so" reject "$TMP/shallow-edit"

# 5. One ref, full history: `git fetch origin main` alone leaves the answer in
#    FETCH_HEAD, so the gate has to ask for the tracking ref by name.
check "a_single_ref_clone_still_finds_the_base" reject "$TMP/single-edit" ci

# 6. No remote, so no base. In CI that is a check that did not run.
check "no_base_in_ci_is_an_error" reject "$TMP/no-remote" ci
check "no_base_outside_ci_is_skipped" accept "$TMP/no-remote"

# 7. Unrelated histories have no merge base, and `...` cannot be computed. That is
#    an error, not a reason to find no changes, here or in CI.
check "unrelated_histories_are_an_error" reject "$TMP/unrelated" ci
check "unrelated_histories_are_an_error_outside_ci" reject "$TMP/unrelated"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
