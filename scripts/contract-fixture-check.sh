#!/usr/bin/env bash
# Enforces the one invariant the OpenAPI contract test cannot enforce about
# itself: its fixtures must be EXHAUSTIVE struct literals.
#
# Why this needs a gate of its own
# --------------------------------
# `crates/dpp-node/tests/openapi_contract.rs` is what stops the API description
# from drifting away from the types that implement it. Its first line of defence
# is the Rust compiler: because every fixture writes out every field, adding a
# field to a checked struct fails to COMPILE here until someone sets it — and
# once it is set, the schema check fails until the spec documents it. That
# two-stage catch is the whole reason a forgotten field cannot ship.
#
# Struct-update syntax silently removes the first stage. Someone hitting
#
#     error[E0063]: missing field `foo` in initializer of `Passport`
#
# can make it go away in one keystroke by appending `..Default::default()`, and
# the build goes green with the new field undocumented and unchecked. Nothing in
# the test suite can notice: a fixture that omits a field looks exactly like a
# field that does not exist. The failure mode is silent, permanent, and looks
# like a fix — so it gets a gate.
#
# What counts as a violation
# --------------------------
# Any line in the `fixtures` module whose first non-whitespace characters are
# `..` — that is Rust struct-update syntax (`..Default::default()`,
# `..some_other_fixture()`). The anchor is deliberate: `..` also appears inside
# the JWS compact literals the fixtures use ("eyJhbGciOiJFZERTQSJ9..aaa"), and
# an unanchored match would flag those. `cargo fmt` runs in the same gate, so
# struct-update syntax is always at the start of a line.
#
# Only the `fixtures` module is scanned — the harness above it uses ordinary
# range syntax (`&src[..at]`), which is not a violation.
#
# Self-tested by scripts/contract-fixture-check.test.sh: a gate nobody has
# watched fail is a gate nobody knows works.

set -euo pipefail

FIXTURE_FILE="${1:-crates/dpp-node/tests/openapi_contract.rs}"
MARKER='^mod fixtures \{'

if [ ! -f "$FIXTURE_FILE" ]; then
    echo "ERROR: $FIXTURE_FILE not found."
    echo "The OpenAPI contract test is the gate that keeps api/ honest. If it was"
    echo "moved, update this script; if it was deleted, restore it."
    exit 1
fi

if ! grep -qE "$MARKER" "$FIXTURE_FILE"; then
    echo "ERROR: no 'mod fixtures {' block in $FIXTURE_FILE."
    echo "This gate scans that module. If it was renamed, update MARKER here —"
    echo "otherwise the gate silently checks nothing."
    exit 1
fi

# One pass, no per-line shell loop: those stall for ~a minute on Windows.
violations="$(awk "/$MARKER/,0" "$FIXTURE_FILE" | grep -nE '^[[:space:]]*\.\.' || true)"

if [ -n "$violations" ]; then
    echo "ERROR: struct-update syntax in the OpenAPI contract fixtures."
    echo
    echo "$violations"
    echo
    echo "These fixtures must list every field explicitly. '..Default::default()'"
    echo "(or '..another_fixture()') makes the compiler stop reporting fields you"
    echo "have not set — which is precisely the signal that forces a new field to"
    echo "be documented in api/ before it can ship."
    echo
    echo "If you got here from an E0063 'missing field' error: that error IS the"
    echo "gate working. Set the field in the fixture, then add it to the schema"
    echo "under api/components/schemas/ and run 'just openapi-bundle'."
    exit 1
fi

echo "OpenAPI contract fixtures are exhaustive (no struct-update syntax)."
