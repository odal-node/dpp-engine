#!/usr/bin/env bash
# The audit gate for what `cargo audit` denies.
#
# A vulnerability and an unmaintained crate always fail it. A yanked crate fails
# it too, unless `.cargo/yanked-register.txt` names that exact crate and version
# with an owner, a reason and an expiry that has not passed.
#
# Why it exists. `cargo audit --deny yanked` has no way to leave one crate
# alone: `--ignore` takes advisory IDs and a yanked crate has none. So when a
# crate we cannot replace is yanked, the choice was between a red audit on every
# pull request, which blocks every merge including a security fix, and dropping
# `--deny yanked` for everything. This is the third option: keep the flag, and
# make each exception a named, dated, expiring line.
#
# Checks (any failure is fatal):
#   1. every yanked crate cargo audit reports is in the register at that version
#   2. every register entry has all of its fields, a well-formed date range, an
#      `expires` that has not passed, and an `expires` within 60 days of
#      `recorded`
#   3. no register entry is stale: each must still match a reported yanked crate
#   4. every vulnerability and unmaintained crate is accounted for as a failure,
#      and cargo audit's own count of what it denied matches what was read, so a
#      change in its output format cannot make a finding disappear
#
# Usage: scripts/check-yanked.sh [register] [saved-audit-output]
#   With a saved output the script reads it instead of running cargo audit,
#   which is how check-yanked.test.sh drives it. YANKED_TODAY=YYYY-MM-DD pins the
#   date for the same reason.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

REGISTER="${1:-.cargo/yanked-register.txt}"
OUTPUT_FILE="${2:-}"
TODAY="${YANKED_TODAY:-$(date +%F)}"
MAX_DAYS=60
STATUS=0
fail() { echo "FAIL: $*" >&2; STATUS=1; }

# ── What cargo audit says ───────────────────────────────────────────────────
audit_rc=0
if [ -n "$OUTPUT_FILE" ]; then
  out="$(cat "$OUTPUT_FILE")"
  # A saved run has no exit status; cargo audit prints an `error:` line exactly
  # when it exits non-zero.
  if grep -q '^error:' <<< "$out"; then audit_rc=1; fi
else
  out="$(cargo audit --deny yanked --deny unmaintained --color never 2>&1)" || audit_rc=$?
fi
printf '%s\n' "$out"
echo

# One line per finding: crate|version|kind|advisory id. `kind` is what the
# `Warning:` line says, and `vulnerability` when there is none.
findings="$(awk '
  function flush() {
    if (crate != "") print crate "|" ver "|" (kind == "" ? "vulnerability" : kind) "|" id
    crate = ""; ver = ""; kind = ""; id = ""
  }
  { gsub(/[ \t\r]+$/, "") }
  /^Crate:/   { flush(); sub(/^Crate:[ \t]*/, "");   crate = $0; next }
  /^Version:/ { sub(/^Version:[ \t]*/, "");          ver = $0;   next }
  /^Warning:/ { sub(/^Warning:[ \t]*/, "");          kind = $0;  next }
  /^ID:/      { sub(/^ID:[ \t]*/, "");               id = $0;    next }
  END { flush() }
' <<< "$out")"

yanked="$(awk -F'|' '$3 == "yanked" { print $1 " " $2 }' <<< "$findings")"
seen_denied_warnings="$(awk -F'|' '$3 == "yanked" || $3 == "unmaintained"' <<< "$findings" | grep -c . || true)"
seen_vulnerabilities="$(awk -F'|' '$3 == "vulnerability"' <<< "$findings" | grep -c . || true)"

said_denied_warnings="$(grep -oE '^error: [0-9]+ denied warning' <<< "$out" | grep -oE '[0-9]+' || true)"
said_vulnerabilities="$(grep -oE '^error: [0-9]+ vulnerabilit' <<< "$out" | grep -oE '[0-9]+' || true)"
said_denied_warnings="${said_denied_warnings:-0}"
said_vulnerabilities="${said_vulnerabilities:-0}"

if [ "$audit_rc" -ne 0 ]; then
  if [ "$said_denied_warnings" -eq 0 ] && [ "$said_vulnerabilities" -eq 0 ]; then
    fail "cargo audit failed without reporting a finding this script can read (see its output above)"
  fi
  if [ "$seen_denied_warnings" -ne "$said_denied_warnings" ]; then
    fail "cargo audit denied $said_denied_warnings warning(s) and this script read $seen_denied_warnings"
  fi
  if [ "$seen_vulnerabilities" -ne "$said_vulnerabilities" ]; then
    fail "cargo audit found $said_vulnerabilities vulnerabilit(ies) and this script read $seen_vulnerabilities"
  fi
fi

# Vulnerabilities and unmaintained crates are never tolerated here. A
# vulnerability that cannot be fixed is an `ignore` entry in .cargo/audit.toml,
# with the reachability argument that file demands.
while IFS='|' read -r crate ver kind id; do
  [ -z "$crate" ] && continue
  case "$kind" in
    vulnerability) fail "$crate $ver has ${id:-an advisory}; fix it, or record it in .cargo/audit.toml" ;;
    unmaintained)  fail "$crate $ver is unmaintained (${id:-no id}); replace it, or record it in .cargo/audit.toml" ;;
  esac
done <<< "$findings"

# ── The register ────────────────────────────────────────────────────────────
# One line per entry: crate|version|recorded|expires|missing fields.
records="$(awk '
  function flush(   i, n, miss, req) {
    if (!started) return
    n = split("version path rationale owner recorded expires release-on", req, " ")
    miss = ""
    for (i = 1; i <= n; i++) if (f[req[i]] == "") miss = miss " " req[i]
    print crate "|" f["version"] "|" f["recorded"] "|" f["expires"] "|" miss
    delete f; crate = ""; started = 0
  }
  { gsub(/\r$/, "") }
  /^[ \t]*#/ || /^[ \t]*$/ { next }
  /^crate:/ { flush(); sub(/^crate:[ \t]*/, ""); gsub(/[ \t]+$/, ""); crate = $0; started = 1; cur = "crate"; next }
  /^[a-z-]+:/ {
    key = $0; sub(/:.*/, "", key)
    val = $0; sub(/^[a-z-]+:[ \t]*/, "", val); gsub(/[ \t]+$/, "", val)
    f[key] = val; cur = key; next
  }
  /^[ \t]+[^ \t]/ {
    v = $0; gsub(/^[ \t]+/, "", v); gsub(/[ \t]+$/, "", v)
    if (started && cur != "crate") f[cur] = f[cur] " " v
    next
  }
  END { flush() }
' "$REGISTER")"

date_ok() { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && date -d "$1" +%F >/dev/null 2>&1; }

registered=""
while IFS='|' read -r crate ver recorded expires missing; do
  [ -z "$crate" ] && continue
  label="register entry '$crate $ver'"
  if [ -n "$missing" ]; then
    fail "$label lacks:$missing"
    continue
  fi
  if grep -qxF "$crate $ver" <<< "$registered"; then
    fail "$label appears twice"
  fi
  registered+="$crate $ver"$'\n'
  if ! date_ok "$recorded" || ! date_ok "$expires"; then
    fail "$label needs recorded and expires as real YYYY-MM-DD dates (got '$recorded' and '$expires')"
    continue
  fi
  if [[ "$expires" < "$recorded" ]]; then
    fail "$label expires ($expires) before it was recorded ($recorded)"
  fi
  limit="$(date -d "$recorded + $MAX_DAYS days" +%F)"
  if [[ "$expires" > "$limit" ]]; then
    fail "$label runs past $limit, $MAX_DAYS days after it was recorded; a loan this long is a decision, and belongs somewhere else"
  fi
  if [[ "$expires" < "$TODAY" ]]; then
    fail "$label expired on $expires; confirm the crate is still stuck, or remove it"
  fi
done <<< "$records"

# ── Each side against the other ─────────────────────────────────────────────
while read -r crate ver; do
  [ -z "$crate" ] && continue
  if ! grep -qxF "$crate $ver" <<< "$registered"; then
    fail "$crate $ver is yanked and is not in $REGISTER; replace it, or add an entry that says why it cannot be and when it expires"
  fi
done <<< "$yanked"

while read -r crate ver; do
  [ -z "$crate" ] && continue
  if ! grep -qxF "$crate $ver" <<< "$yanked"; then
    fail "register entry '$crate $ver' matches no yanked crate cargo audit reported; remove it"
  fi
done <<< "$registered"

if [ "$STATUS" -eq 0 ]; then
  n="$(grep -c . <<< "$registered" || true)"
  echo "ok - the audit is clean apart from ${n:-0} registered yanked crate(s), none expired"
fi
exit "$STATUS"
