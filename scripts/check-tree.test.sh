#!/usr/bin/env bash
# Self-test for scripts/check-tree.sh and .githooks/pre-commit.
#
# Builds a synthetic git repository, runs the recording script, then exercises
# the pre-commit hook with both matching and non-matching trees. No network,
# no cargo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RECORD="$SCRIPT_DIR/check-tree.sh"
HOOK="$(cd "$SCRIPT_DIR/.." && pwd)/.githooks/pre-commit"
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

echo ""
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
