#!/usr/bin/env bash
# Self-test for scripts/no-xml-entity-resolution.sh.
#
# The gate carries its own `--self-test`, and that covers the scan. This covers
# the gate as a program: that it actually runs against the real repository, that
# its exit statuses mean what the justfile and CI assume they mean, and that it
# does not flag the committed code it guards.
#
# The distinction matters. The built-in self-test plants files in a scratch tree
# and can pass in a checkout where the real crate has been renamed out from
# under it — that is precisely the vacuous pass this file is here to catch.

set -euo pipefail

GATE="$(dirname "$0")/no-xml-entity-resolution.sh"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

ok() {
    echo "ok:   $1"
    pass=$((pass + 1))
}

bad() {
    echo "FAIL: $1"
    fail=$((fail + 1))
}

# 1. The committed crate must pass its own gate. If this fails, either the code
#    reaches for the entity resolver or the note in Cargo.toml is already void.
if bash "$GATE" > /dev/null 2>&1; then
    ok "the committed dpp-seal passes the gate"
else
    bad "the committed dpp-seal is rejected by its own gate"
fi

# 2. The built-in self-test must pass on its own.
if bash "$GATE" --self-test > /dev/null 2>&1; then
    ok "the gate's built-in self-test passes"
else
    bad "the gate's built-in self-test fails"
fi

# 3. The gate must go red on the real thing — the assertion that makes this
#    file worth having. A copy of the actual repository with one line added,
#    rather than a scratch tree, so this exercises the same path `just check`
#    runs and would catch a gate wired to look somewhere else entirely.
#
#    Only the scanned crate and the script are copied; the rest of the
#    workspace is irrelevant to a grep and copying it would make the gate's
#    own test the slowest thing in `just check`.
mkdir -p "$TMP/repo/scripts" "$TMP/repo/crates"
cp -r "$REPO_ROOT/crates/dpp-seal" "$TMP/repo/crates/dpp-seal"
cp "$GATE" "$TMP/repo/scripts/"

printf '\nlet doc = Document::parse_with_options(xml, ParsingOptions { allow_dtd: true, ..Default::default() })?;\n' \
    >> "$TMP/repo/crates/dpp-seal/src/trustlist/parse.rs"

if bash "$TMP/repo/scripts/no-xml-entity-resolution.sh" > /dev/null 2>&1; then
    bad "a planted parse_with_options call in the real crate was NOT caught"
else
    ok "a planted parse_with_options call in the real crate is caught"
fi

# 4. Removing the planted line must make it green again. Without this, a gate
#    hard-wired to `exit 1` would satisfy every assertion above.
sed -i '$ d' "$TMP/repo/crates/dpp-seal/src/trustlist/parse.rs"
if bash "$TMP/repo/scripts/no-xml-entity-resolution.sh" > /dev/null 2>&1; then
    ok "removing the planted call makes the gate green again"
else
    bad "the gate stays red after the planted call is removed"
fi

# 5. A missing crate must exit 2 — "I could not look", distinct from "I looked
#    and it was clean". A rename that silently retired this check would show up
#    here and nowhere else.
rm -rf "$TMP/repo/crates/dpp-seal"
rc=0
bash "$TMP/repo/scripts/no-xml-entity-resolution.sh" > /dev/null 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then
    ok "a missing dpp-seal exits 2 rather than passing"
else
    bad "a missing dpp-seal exited $rc, not 2"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
