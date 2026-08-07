#!/usr/bin/env bash
# Merge gate for check-audit-register.sh itself: proves the checker actually
# goes red in the directions that let RUSTSEC-2026-0098/-0099/-0104 and
# RUSTSEC-2026-0188 rot silently in the first place, without needing a real
# scratch branch each time.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

PASS=0
FAIL=0

expect_pass() {
  local name="$1" fixture="$2"
  if bash scripts/check-audit-register.sh "$fixture" >/dev/null 2>&1; then
    echo "ok   - $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL - $name (expected the checker to pass, it did not)"
    FAIL=$((FAIL + 1))
  fi
}

expect_fail() {
  local name="$1" fixture="$2"
  if bash scripts/check-audit-register.sh "$fixture" >/dev/null 2>&1; then
    echo "FAIL - $name (expected the checker to fail, it passed)"
    FAIL=$((FAIL + 1))
  else
    echo "ok   - $name"
    PASS=$((PASS + 1))
  fi
}

# Asserts the checker fails *for the stated reason*, not merely that it exits
# non-zero. `fail()` accumulates rather than exiting, so a fixture can trip
# several checks at once — and every entry now trips the staleness check, since
# the dependency graph currently raises no advisories at all. Matching the
# message is what keeps each case a test of its own check.
expect_fail_with() {
  local name="$1" fixture="$2" needle="$3" out
  out="$(bash scripts/check-audit-register.sh "$fixture" 2>&1 || true)"
  if grep -q "$needle" <<< "$out"; then
    echo "ok   - $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL - $name (no message matching '$needle')"
    FAIL=$((FAIL + 1))
  fi
}

# The register itself is empty whenever nothing in the graph raises an advisory,
# so the negative fixtures below are built from a self-contained base rather
# than by editing `.cargo/audit.toml`. Deriving them from the live file made
# them silently unrunnable the moment the last real entry was released: their
# `sed`/`awk` sanity greps found nothing and `set -e` killed the run.
BASE="$SCRATCH/base.toml"
cat > "$BASE" <<'EOF'
[advisories]
# --- RUSTSEC-2023-0071 -------------------------------------------------------
# crate:      rsa 0.9.10
# path:       sqlx-mysql -> sqlx   [ORPHANED]
# class:      not-in-graph
# rationale:  Test fixture. `rsa` is not in the resolved dependency graph.
# anchor:     cargo tree -i rsa --target all
# owner:      founder
# recorded:   2026-07-27
# expires:    2026-10-25
# release-on: test fixture — never merged into the real register
ignore = [
    "RUSTSEC-2023-0071",
]
EOF

# 1. The real register passes as-is.
expect_pass "corrected register passes" ".cargo/audit.toml"

# 2. Back-dating one real entry's `expires` field goes red.
BACKDATED="$SCRATCH/backdated.toml"
sed 's/^# expires:    2026-10-25$/# expires:    2020-01-01/' "$BASE" > "$BACKDATED"
grep -q "2020-01-01" "$BACKDATED" # sanity: the substitution actually landed
expect_fail_with "back-dated expires is rejected" "$BACKDATED" "suppression expired on"

# 3. Re-adding a complete, well-formed block for an advisory that no longer
#    fires (RUSTSEC-2026-0188, fixed at wasmtime-wasi 45.0.3 — see F2) is
#    caught as a stale suppression, not just a missing-field error.
STALE="$SCRATCH/stale.toml"
BLOCK='# --- RUSTSEC-2026-0188 -------------------------------------------------------
# crate:      wasmtime-wasi 45.0.2
# path:       dpp-plugin-host -> dpp-node   [SHIPPED]
# class:      reachable-but-mitigated
# rationale:  WASI hard links/renames bypass FilePerms for destination. The
#             plugin sandbox never grants filesystem capabilities the bypass
#             needs.
# anchor:     crates/dpp-plugin-host/src/runtime.rs::build_store
# owner:      founder
# recorded:   2026-07-27
# expires:    2026-10-25
# release-on: intentionally stale for the test fixture — do not merge'
awk -v block="$BLOCK" '
  /^ignore = \[/ {
    print block
    print "ignore = ["
    print "    \"RUSTSEC-2026-0188\","
    next
  }
  { print }
' "$BASE" > "$STALE"
grep -q "RUSTSEC-2026-0188" "$STALE" # sanity: the insertion actually landed
expect_fail_with "stale (already-fixed) advisory is rejected" "$STALE" \
  "RUSTSEC-2026-0188: does not appear in a raw"

# 4. A `class: not-in-graph` claim for a crate that IS in the graph is caught.
#    Takes the real rsa entry (correctly `not-in-graph`, so every other field
#    stays valid) and swaps only its `crate:` to `serde_json`, which every
#    build resolves — so the graph check is the only thing that can fail.
WRONGCLASS="$SCRATCH/wrongclass.toml"
awk '
  /^# crate:      rsa/ { print "# crate:      serde_json"; next }
  { print }
' "$BASE" > "$WRONGCLASS"
grep -q "^# crate:      serde_json" "$WRONGCLASS" # sanity: the swap actually landed
expect_fail_with "not-in-graph claim for an in-graph crate is rejected" "$WRONGCLASS" \
  "resolves in the default dependency graph"

# 5. The regression the shipped-graph check exists for: a crate absent under
#    default features but present in the artefact the Dockerfile actually
#    builds (`-p dpp-node --features s3`). Three rustls-webpki advisories once
#    sat behind a green `not-in-graph` claim for exactly this reason — the
#    claim was checked against a build nobody ships. Reuses the real rsa entry
#    (already `not-in-graph`, so every other field stays valid) with only its
#    `crate:` swapped to `aws-sdk-s3`, which is optional by default and on in
#    the image — so the shipped-graph check is the only thing that can fail.
SHIPPEDONLY="$SCRATCH/shipped-only.toml"
awk '
  /^# crate:      rsa/ { print "# crate:      aws-sdk-s3"; next }
  { print }
' "$BASE" > "$SHIPPEDONLY"
grep -q "^# crate:      aws-sdk-s3" "$SHIPPEDONLY" # sanity: the swap landed
expect_fail_with "not-in-graph claim true only outside the shipped build is rejected" \
  "$SHIPPEDONLY" "resolves in the shipped"

echo ""
echo "check-audit-register.test: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
