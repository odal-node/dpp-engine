#!/usr/bin/env bash
# Self-test for scripts/check-tree.sh and .githooks/pre-commit.
#
# Builds a synthetic git repository, runs the recording script, then exercises
# the pre-commit hook with both matching and non-matching trees. No network,
# no cargo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RECORD="$SCRIPT_DIR/check-tree.sh"
HOOK="$ROOT/.githooks/pre-commit"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

assert_pass() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "ok:   $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — expected success, got failure"
        fail=$((fail + 1))
    fi
}

assert_fail() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: $name — expected failure, got success"
        fail=$((fail + 1))
    else
        echo "ok:   $name"
        pass=$((pass + 1))
    fi
}

# ---------------------------------------------------------------------------
# Test 1: Recording a tree creates the checked-tree file
# ---------------------------------------------------------------------------
{
    repo="$TMP/test-record"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "hello" > file.txt
    git add file.txt
    git commit -q -m "initial"

    bash "$RECORD" >/dev/null
    [ -f ".git/checked-tree" ]
    assert_pass "recording creates checked-tree" true
}

# ---------------------------------------------------------------------------
# Test 2: Hook accepts a commit when the tree matches
# ---------------------------------------------------------------------------
{
    repo="$TMP/test-match"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "hello" > file.txt
    git add file.txt
    git commit -q -m "initial"

    # Record the current tree.
    bash "$RECORD" >/dev/null

    # Stage the same content (no changes) and write the index tree.
    git add -A
    COMMITTING="$(git write-tree)"
    CHECKED="$(cat .git/checked-tree)"

    assert_pass "recorded tree matches index tree" [ "$COMMITTING" = "$CHECKED" ]
}

# ---------------------------------------------------------------------------
# Test 3: Hook refuses when no tree was recorded
# ---------------------------------------------------------------------------
{
    repo="$TMP/test-no-record"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "hello" > file.txt
    git add file.txt
    git commit -q -m "initial"
    # Do NOT run check-tree.sh

    assert_fail "hook refuses without recorded tree" bash "$HOOK"
}

# ---------------------------------------------------------------------------
# Test 4: Hook refuses when the tree changed after recording
# ---------------------------------------------------------------------------
{
    repo="$TMP/test-mismatch"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "hello" > file.txt
    git add file.txt
    git commit -q -m "initial"

    # Record the tree.
    bash "$RECORD" >/dev/null

    # Now change the working tree and stage it.
    echo "world" > file.txt
    git add file.txt

    assert_fail "hook refuses tree mismatch" bash "$HOOK"
}

# ---------------------------------------------------------------------------
# Test 5: Hook refuses partial commit (only part of the checked tree)
# ---------------------------------------------------------------------------
{
    repo="$TMP/test-partial"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "a" > a.txt
    echo "b" > b.txt
    git add a.txt b.txt
    git commit -q -m "initial"

    # Make two changes.
    echo "a2" > a.txt
    echo "b2" > b.txt

    # Record the full working tree.
    bash "$RECORD" >/dev/null

    # Only stage one of the two changes — the index tree will differ from
    # the recorded tree.
    git add a.txt

    assert_fail "hook refuses partial commit" bash "$HOOK"
}

# ---------------------------------------------------------------------------
# Test 6: Re-running check-tree after fixing the tree allows the commit
# ---------------------------------------------------------------------------
{
    repo="$TMP/test-recover"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "hello" > file.txt
    git add file.txt
    git commit -q -m "initial"

    # Change the file.
    echo "world" > file.txt
    git add file.txt

    # Record the new tree.
    bash "$RECORD" >/dev/null

    # Now the index tree should match the recorded tree.
    assert_pass "hook accepts after re-recording" bash "$HOOK"
}

# ---------------------------------------------------------------------------
# Test 7: A clone's `git commit` runs the hook through core.hooksPath
# ---------------------------------------------------------------------------
# The tests above call the hook with `bash`, which runs it whatever its mode.
# Git does not: it skips a hook that is not executable, with only a hint, so a
# hook committed as 100644 refuses nothing in a fresh clone. The working copy's
# mode cannot be trusted to show that (a filesystem without Unix modes reports
# every file executable), so the hook is installed here with the mode the
# repository commits it with, and a real commit goes through it.
{
    repo="$TMP/test-installed"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    mkdir .githooks
    git -C "$ROOT" show :.githooks/pre-commit > .githooks/pre-commit
    case "$(git -C "$ROOT" ls-files -s .githooks/pre-commit)" in
        100755*) chmod 755 .githooks/pre-commit ;;
        *) chmod 644 .githooks/pre-commit ;;
    esac
    git config core.hooksPath .githooks
    echo "hello" > file.txt
    git add file.txt
    # No tree recorded, so the hook must refuse this commit, and only can if
    # git runs it.
    assert_fail "a clone's commit runs the hook" git commit -q -m "unchecked"
}

# ---------------------------------------------------------------------------
# Test 8: A tracked file an ignore rule names stays in the recorded tree
# ---------------------------------------------------------------------------
# Ignore rules do not apply to a file the index already tracks, so `git add -A`
# keeps it. They do apply to a file absent from the index, so a record built
# from an empty index would drop it, and the hook would then refuse a fully
# staged, unchanged commit.
{
    repo="$TMP/test-excluded"
    git init -q "$repo"
    cd "$repo"
    git config user.email "test@test"
    git config user.name "Test"
    echo "hello" > file.txt
    echo "local" > notes.local
    git add file.txt notes.local
    git commit -q -m "initial"
    echo "notes.local" >> .git/info/exclude

    bash "$RECORD" >/dev/null
    assert_pass "an excluded tracked file stays in the record" bash "$HOOK"
}

# ---------------------------------------------------------------------------
# Test 9: `just check` records the tree as its last step
# ---------------------------------------------------------------------------
# A record written before a later step fails would outlive the failure, and the
# hook would accept a tree `just check` did not pass.
{
    last="$(grep -E '^check:' "$ROOT/justfile" | awk '{ print $NF }')"
    assert_pass "check-tree is the last step of just check" [ "$last" = "check-tree" ]
}

echo ""
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
