#!/usr/bin/env bash
# Enforces the structured-header contract on every `.cargo/audit.toml` ignore
# entry. A suppressed advisory cannot outlive the argument that suppressed
# it: each entry bundles a reachability claim, an availability claim, and an
# implicit expiry — left as prose, none of the three ever gets re-checked.
# This makes all three mechanical.
#
# Each ignore entry must be preceded by a block of this shape:
#
#   # --- RUSTSEC-XXXX-XXXX ------------------------------------------------
#   # crate:      <name> <version>
#   # path:       <dependency path, free text>
#   # class:      not-in-graph | dev-only | build-time-only |
#   #             reachable-but-mitigated | reachable-accepted
#   # rationale:  <free text, may wrap on continuation lines>
#   # anchor:     <path::SYMBOL that makes `class` true, or "—" for
#   #             reachable-accepted, which has no automated check>
#   # owner:      <who signed off>
#   # recorded:   <YYYY-MM-DD>
#   # expires:    <YYYY-MM-DD>
#   # release-on: <the condition that would let this entry be deleted>
#
# Checks (any failure is fatal):
#   1. every ID in [advisories].ignore has a block, every block has all nine
#      fields, and every block's ID is itself in the ignore list
#   2. no block's `expires` date has passed
#   3. no ignored ID is stale — it must still be reported by a "raw" cargo
#      audit run (no .cargo/audit.toml in scope, i.e. outside this repo)
#   4. each block's `class` claim actually holds against the dependency graph
#      (not-in-graph / dev-only / build-time-only / reachable-but-mitigated);
#      reachable-accepted has no automated check by design (manual sign-off)
#
# Usage: scripts/check-audit-register.sh [path/to/audit.toml]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

AUDIT_TOML="${1:-.cargo/audit.toml}"
STATUS=0
fail() { echo "FAIL: $*" >&2; STATUS=1; }

REQUIRED_FIELDS=(crate path class rationale anchor owner recorded expires release-on)

# ── Parse the file into BLOCK / FIELD / IGNORED records ─────────────────────
PARSED="$(awk '
  /^# --- RUSTSEC-[0-9]{4}-[0-9]{4} / {
    match($0, /RUSTSEC-[0-9]{4}-[0-9]{4}/)
    id = substr($0, RSTART, RLENGTH)
    print "BLOCK\t" id
    next
  }
  id != "" && /^# [a-z][a-z-]*:[ \t]/ {
    line = $0
    sub(/^# /, "", line)
    idx = index(line, ":")
    key = substr(line, 1, idx - 1)
    val = substr(line, idx + 1)
    sub(/^[ \t]+/, "", val)
    sub(/[ \t]+$/, "", val)
    print "FIELD\t" id "\t" key "\t" val
    next
  }
  /^ignore = \[/ { inlist = 1; next }
  inlist && /^\]/ { inlist = 0; next }
  inlist {
    line = $0
    gsub(/[",]/, "", line)
    gsub(/^[ \t]+|[ \t]+$/, "", line)
    if (line != "") print "IGNORED\t" line
  }
' "$AUDIT_TOML")"

declare -A FIELD
BLOCK_IDS=()
IGNORED_IDS=()

while IFS=$'\t' read -r kind a b c; do
  case "$kind" in
    BLOCK) BLOCK_IDS+=("$a") ;;
    FIELD) FIELD["$a|$b"]="$c" ;;
    IGNORED) IGNORED_IDS+=("$a") ;;
  esac
done <<< "$PARSED"

contains() { local needle="$1"; shift; for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done; return 1; }

# ── Check 1: every ignored ID has a complete block, and vice versa ─────────
for id in "${IGNORED_IDS[@]}"; do
  contains "$id" "${BLOCK_IDS[@]}" || fail "$id: in [advisories].ignore but has no structured header block"
done
for id in "${BLOCK_IDS[@]}"; do
  contains "$id" "${IGNORED_IDS[@]}" || fail "$id: has a structured header block but is not in [advisories].ignore"
  for f in "${REQUIRED_FIELDS[@]}"; do
    [[ -n "${FIELD[$id|$f]:-}" ]] || fail "$id: missing '$f:' field in its structured header"
  done
done

# ── Check 2: no expired entry ────────────────────────────────────────────────
today_epoch=$(date +%s)
for id in "${BLOCK_IDS[@]}"; do
  exp="${FIELD[$id|expires]:-}"
  [[ -z "$exp" ]] && continue # already reported above
  exp_epoch=$(date -d "$exp" +%s 2>/dev/null) || { fail "$id: expires '$exp' is not a valid YYYY-MM-DD date"; continue; }
  if (( exp_epoch < today_epoch )); then
    fail "$id: suppression expired on $exp — re-verify the reachability claim, then renew or remove it"
  fi
done

# ── Check 3: no stale suppression (raw cargo-audit outside repo scope) ─────
RAW_DIR="$(mktemp -d)"
trap 'rm -rf "$RAW_DIR"' EXIT
cp Cargo.lock "$RAW_DIR/Cargo.lock"
# The `cd` is what makes this run "raw": cargo-audit resolves .cargo/audit.toml
# relative to the working directory, so from a scratch dir it reports the
# unsuppressed set. `|| true` is scoped to the audit alone, not to `cd &&
# audit` — cargo-audit exits non-zero whenever it finds anything, which is
# expected here, but a failed `cd` must not be swallowed the same way: it would
# leave RAW_OUTPUT empty and every suppression would read as stale.
if ! RAW_OUTPUT="$(cd "$RAW_DIR" && { cargo audit --file Cargo.lock -q 2>&1 || true; })"; then
  fail "could not enter scratch dir '$RAW_DIR' to run the unsuppressed audit"
  RAW_OUTPUT=""
fi
# `|| true` because a clean raw audit is a legitimate outcome, not an error:
# grep exits 1 when it matches nothing, `set -o pipefail` promotes that to the
# whole pipeline, and `set -e` then killed this script with no message and no
# exit code anyone could act on. That is the exact moment every suppression has
# just become stale, so it has to report rather than die.
RAW_IDS="$(grep -o 'RUSTSEC-[0-9]\{4\}-[0-9]\{4\}' <<< "$RAW_OUTPUT" | sort -u || true)"

for id in "${IGNORED_IDS[@]}"; do
  grep -qx "$id" <<< "$RAW_IDS" || fail "$id: does not appear in a raw (no .cargo/audit.toml) cargo-audit run — the advisory no longer fires; delete this entry, don't just leave it suppressed"
done

# Confirms `pkgspec` (a bare crate name, or `name@version` to disambiguate a
# crate with multiple resolved versions) is absent from the dependency graph
# under the given edge mode ($3: "all" for every edge, "normal" to exclude
# dev- and build-dependencies). `cargo tree` has two distinct "absent" shapes
# that both mean the same thing here and must both count as confirmed: exit 0
# with empty stdout (a bare name simply isn't in the graph), and a non-zero
# exit whose stderr says "did not match any packages" (a version-pinned spec
# naming a version that isn't resolved at all — the ambiguity that motivates
# pinning `name@version` in the first place, see git history). Any other
# non-zero exit (e.g. "is ambiguous", meaning the spec still matches more
# than one resolved version) is a real problem, not a pass. Calls fail()
# itself with a specific reason whenever it cannot confirm absence.
graph_absent_in() {
  local id="$1" pkgspec="$2" edge_mode="$3" build_label="$4"; shift 4
  local out err_file err
  # Built as an array rather than interpolated from a string: `cargo tree` needs
  # `-e normal` as two argv entries, and an unquoted "$edge_flag" relied on word
  # splitting to produce them (shellcheck SC2086).
  local -a edge=()
  [[ "$edge_mode" == "normal" ]] && edge=(-e normal)
  err_file="$(mktemp)"
  if out="$(cargo tree -i "$pkgspec" "${edge[@]}" --target all "$@" 2>"$err_file")"; then
    rm -f "$err_file"
    if [[ -n "$out" ]]; then
      fail "$id: '$pkgspec' resolves in the $build_label dependency graph"
      return 1
    fi
    return 0
  fi
  err="$(cat "$err_file")"
  rm -f "$err_file"
  if grep -q "did not match any packages" <<< "$err"; then
    return 0
  fi
  fail "$id: could not verify '$pkgspec' against the $build_label graph — $err"
  return 1
}

# A reachability claim has to hold for the artefact operators actually run,
# not just for `cargo build` with no flags. The published image builds
# `-p dpp-node --features s3` (docker/node.Dockerfile), so a crate that is
# absent by default but present there is still shipped — which is exactly how
# three rustls-webpki advisories once sat behind a green `not-in-graph` claim.
# Every absence claim is therefore checked against both graphs. Keep
# SHIPPED_BUILD in step with the Dockerfile.
SHIPPED_BUILD=(-p dpp-node --features s3)

graph_absent() {
  local id="$1" pkgspec="$2" edge_mode="$3" ok=0
  graph_absent_in "$id" "$pkgspec" "$edge_mode" "default" || ok=1
  graph_absent_in "$id" "$pkgspec" "$edge_mode" "shipped (${SHIPPED_BUILD[*]})" \
    "${SHIPPED_BUILD[@]}" || ok=1
  return "$ok"
}

# ── Check 4: class claims hold against the dependency graph ────────────────
for id in "${BLOCK_IDS[@]}"; do
  class="${FIELD[$id|class]:-}"
  crate="${FIELD[$id|crate]:-}"
  # `crate:` is "<name> <version>" — use name@version so an `-i` lookup can't
  # land on the wrong one of two resolved versions of the same crate.
  crate_name="${crate%% *}"
  pkgspec="$crate_name"
  [[ "$crate" == *" "* ]] && pkgspec="${crate_name}@${crate#* }"
  anchor="${FIELD[$id|anchor]:-}"

  case "$class" in
    not-in-graph)
      graph_absent "$id" "$pkgspec" "all" || true
      ;;
    dev-only|build-time-only)
      graph_absent "$id" "$pkgspec" "normal" || true
      ;;
    reachable-but-mitigated)
      # anchor is "path/to/file.rs::SYMBOL"
      anchor_path="${anchor%%::*}"
      anchor_symbol="${anchor##*::}"
      if [[ ! -f "$anchor_path" ]]; then
        fail "$id: anchor file '$anchor_path' does not exist"
      elif ! grep -q "$anchor_symbol" "$anchor_path"; then
        fail "$id: anchor symbol '$anchor_symbol' not found in '$anchor_path'"
      fi
      ;;
    reachable-accepted)
      : # manual sign-off; no automated check by design
      ;;
    *)
      fail "$id: unrecognised class '$class' (expected not-in-graph, dev-only, build-time-only, reachable-but-mitigated, or reachable-accepted)"
      ;;
  esac
done

if [[ "$STATUS" -eq 0 ]]; then
  echo "check-audit-register: ${#BLOCK_IDS[@]} entries, all current."
fi
exit "$STATUS"
