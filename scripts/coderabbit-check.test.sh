#!/usr/bin/env bash
# Self-test for scripts/coderabbit-check.sh.
#
# A gate nobody has watched fail is a gate nobody knows works. This one is a
# thin wrapper around someone else's validator reached over the network, which
# gives it two ways to pass while checking nothing: the fetch could return
# something that is not the schema, or the ajv flags could be wrong in a way
# that makes every document valid. Both look identical to a green run.
#
# It also pins the gate's BOUNDARY, which matters more here than usual: case 6
# asserts that a misspelled NESTED key is accepted, because the schema closes
# additional properties at the top level only. That is a limitation, not a
# feature — it is written down as a test so nobody reads a passing
# coderabbit-check as proof their keys are spelled right. If CodeRabbit ever
# closes the nested objects, case 6 fails, and the correct response is to delete
# the case and the caveat in coderabbit-check.sh, not to loosen anything.
#
# Needs the network, like the gate itself.

set -euo pipefail

GATE="$(dirname "$0")/coderabbit-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Single quotes: the `$schema=` must reach the file literally.
HEADER='# yaml-language-server: $schema=https://storage.googleapis.com/coderabbit_public_assets/schema.v2.json'

pass=0
fail=0

expect_reject() {
    local name="$1" file="$2"
    if bash "$GATE" "$file" >/dev/null 2>&1; then
        echo "FAIL: $name — gate accepted a config it must reject"
        fail=$((fail + 1))
    else
        echo "ok:   $name"
        pass=$((pass + 1))
    fi
}

expect_accept() {
    local name="$1" file="$2"
    if bash "$GATE" "$file" >/dev/null 2>&1; then
        echo "ok:   $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate rejected a config it must accept"
        fail=$((fail + 1))
    fi
}

# 1. The committed config must pass its own gate, or the gate is wrong about the
#    file it guards.
expect_accept "the committed .coderabbit.yaml validates" \
    "$(dirname "$0")/../.coderabbit.yaml"

# 2. A value outside an enum. This is the case the gate exists for, and the one
#    the original ajv run was proved against before its pass was trusted.
{
    echo "$HEADER"
    printf 'language: en-US\nreviews:\n  profile: bogus\n'
} > "$TMP/bad-enum.yaml"
expect_reject "an invalid 'profile' value is rejected" "$TMP/bad-enum.yaml"

# 3. A top-level key CodeRabbit does not know. This is the half of the typo
#    problem the schema does catch.
{
    echo "$HEADER"
    printf 'language: en-US\nreviewz:\n  profile: assertive\n'
} > "$TMP/toplevel-typo.yaml"
expect_reject "an unknown top-level key is rejected" "$TMP/toplevel-typo.yaml"

# 4. A wrong type where the schema wants an object.
{
    echo "$HEADER"
    printf 'language: en-US\nreviews: true\n'
} > "$TMP/bad-type.yaml"
expect_reject "a scalar where an object belongs is rejected" "$TMP/bad-type.yaml"

# 5. No schema header means no schema, and that must be loud rather than a
#    silent skip — a gate that quietly validates nothing is the failure this
#    whole file exists to prevent.
printf 'language: en-US\nreviews:\n  profile: assertive\n' > "$TMP/no-header.yaml"
expect_reject "a config with no schema header is rejected, not skipped" \
    "$TMP/no-header.yaml"

# 6. A missing file must be loud too.
expect_reject "a missing file is rejected" "$TMP/does-not-exist.yaml"

# 7. THE DOCUMENTED LIMITATION. A misspelled key nested under `reviews` is
#    accepted, because the schema does not close additional properties there.
#    `auto_reviews` is not a setting; a config carrying it would disable nothing
#    and report nothing. Pinned so the caveat in coderabbit-check.sh stays true.
{
    echo "$HEADER"
    printf 'language: en-US\nreviews:\n  auto_reviews:\n    enabled: false\n'
} > "$TMP/nested-typo.yaml"
expect_accept "a misspelled NESTED key is accepted — the schema is open there" \
    "$TMP/nested-typo.yaml"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
