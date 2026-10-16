#!/usr/bin/env bash
# Merge gate for check-yanked.sh itself: proves the checker goes red in each
# direction it exists to, and green only for the one case it tolerates. It runs
# the checker against saved `cargo audit` output, never against the network, with
# the date pinned.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

export YANKED_TODAY=2026-10-20

PASS=0
FAIL=0

# ── cargo audit output, as it prints it (--color never) ─────────────────────
HEAD='    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1329 security advisories (from /home/runner/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (814 crate dependencies)'

YANKED_ZIP='Crate:     zip
Version:   8.6.0
Warning:   yanked
Dependency tree:
zip 8.6.0
├── dpp-integrator 0.14.0
│   └── dpp-node 0.14.0
└── calamine 0.36.1
    └── dpp-integrator 0.14.0
'

VULNERABLE='Crate:     wasmtime
Version:   49.0.2
Title:     Panic when invoking an async-lifted function via `call`
Date:      2026-10-14
ID:        RUSTSEC-2026-0353
URL:       https://rustsec.org/advisories/RUSTSEC-2026-0353
Severity:  5.9 (medium)
Solution:  Upgrade to >=48.0.6, <49.0.0 OR >=49.0.3
Dependency tree:
wasmtime 49.0.2
└── dpp-plugin-host 0.14.0
'

UNMAINTAINED='Crate:     paste
Version:   1.0.15
Warning:   unmaintained
Title:     paste - no longer maintained
Date:      2024-10-07
ID:        RUSTSEC-2024-0436
URL:       https://rustsec.org/advisories/RUSTSEC-2024-0436
Dependency tree:
paste 1.0.15
└── dpp-node 0.14.0
'

UNSOUND='Crate:     some-crate
Version:   0.3.1
Warning:   unsound
Title:     Unsound read
Date:      2026-01-01
ID:        RUSTSEC-2026-0001
URL:       https://rustsec.org/advisories/RUSTSEC-2026-0001
Dependency tree:
some-crate 0.3.1
└── dpp-node 0.14.0
'

# ── registers ───────────────────────────────────────────────────────────────
# One valid entry; the variants below are derived from it by `sed`, and each
# derivation is asserted, so a fixture that stopped differing cannot pass quietly.
VALID_ENTRY='crate:      zip
version:    8.6.0
path:       dpp-integrator -> calamine -> zip
rationale:  Yanked upstream and held in by calamine, which
            requires zip ^8.6.
owner:      LKSNDRTMLKV
recorded:   2026-10-16
expires:    2026-12-15
release-on: calamine releases a version that requires zip 9.'

EMPTY_REGISTER='# nothing is tolerated'

write() { printf '%s\n' "$2" > "$SCRATCH/$1"; }

write clean.out "$HEAD"
write zip.out "$HEAD
$YANKED_ZIP
error: 1 denied warning found!"
write vuln.out "$HEAD
$VULNERABLE
error: 1 vulnerability found!"
write vuln-and-zip.out "$HEAD
$VULNERABLE
$YANKED_ZIP
error: 1 denied warning found!
error: 1 vulnerability found!"
write unmaintained.out "$HEAD
$UNMAINTAINED
error: 1 denied warning found!"
write unsound.out "$HEAD
$UNSOUND
warning: 1 allowed warning found"
write two-zips.out "$HEAD
$YANKED_ZIP
$(sed 's/8\.6\.0/8\.6\.1/' <<< "$YANKED_ZIP")
error: 2 denied warnings found!"
write zip-other-version.out "$HEAD
$(sed 's/8\.6\.0/8\.6\.1/' <<< "$YANKED_ZIP")
error: 1 denied warning found!"
write unreadable.out "$HEAD
error: could not fetch the advisory database"
write miscounted.out "$HEAD
$YANKED_ZIP
error: 3 denied warnings found!"

write valid.reg "# header
$VALID_ENTRY"
write empty.reg "$EMPTY_REGISTER"
write expired.reg "$(sed 's/^expires:.*/expires:    2026-10-19/' <<< "$VALID_ENTRY")"
write too-long.reg "$(sed 's/^expires:.*/expires:    2027-06-01/' <<< "$VALID_ENTRY")"
write backwards.reg "$(sed 's/^expires:.*/expires:    2026-10-01/' <<< "$VALID_ENTRY")"
write bad-date.reg "$(sed 's/^expires:.*/expires:    soon/' <<< "$VALID_ENTRY")"
write no-owner.reg "$(grep -v '^owner:' <<< "$VALID_ENTRY")"
write no-release.reg "$(grep -v '^release-on:' <<< "$VALID_ENTRY")"
write twice.reg "$VALID_ENTRY

$VALID_ENTRY"
write other-version.reg "$(sed 's/^version:.*/version:    8.6.1/' <<< "$VALID_ENTRY")"

# Each derived fixture must actually differ from the valid one.
for f in expired too-long backwards bad-date no-owner no-release other-version; do
  if cmp -s "$SCRATCH/$f.reg" <(printf '%s\n' "$VALID_ENTRY"); then
    echo "FAIL - fixture $f.reg did not differ from the valid entry"
    exit 1
  fi
done

# ── assertions ──────────────────────────────────────────────────────────────
expect_pass() {
  local name="$1" reg="$2" out="$3"
  if bash scripts/check-yanked.sh "$SCRATCH/$reg" "$SCRATCH/$out" >/dev/null 2>&1; then
    echo "ok   - $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL - $name (expected the checker to pass, it did not)"
    FAIL=$((FAIL + 1))
  fi
}

# Fails for the stated reason, not merely non-zero: `fail()` accumulates, so a
# fixture can trip several checks at once.
expect_fail_with() {
  local name="$1" reg="$2" out="$3" needle="$4" got
  if got="$(bash scripts/check-yanked.sh "$SCRATCH/$reg" "$SCRATCH/$out" 2>&1)"; then
    echo "FAIL - $name (expected the checker to fail, it passed)"
    FAIL=$((FAIL + 1))
  elif grep -q "FAIL:.*$needle" <<< "$got"; then
    echo "ok   - $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL - $name (failed, but with no message matching '$needle')"
    FAIL=$((FAIL + 1))
  fi
}

expect_pass      "a clean audit and an empty register pass"                       empty.reg clean.out
expect_pass      "the registered yanked crate passes"                             valid.reg zip.out
expect_pass      "an allowed warning (unsound) is not a finding here"             empty.reg unsound.out

expect_fail_with "a yanked crate with no register entry fails"                    empty.reg zip.out            "zip 8.6.0 is yanked and is not in"
expect_fail_with "the same crate at another version fails"                        valid.reg zip-other-version.out "zip 8.6.1 is yanked and is not in"
expect_fail_with "and its old entry is then reported as stale"                    valid.reg zip-other-version.out "matches no yanked crate"
expect_fail_with "a second yanked crate beside the registered one fails"          valid.reg two-zips.out       "zip 8.6.1 is yanked and is not in"
expect_fail_with "an expired entry fails"                                         expired.reg zip.out          "expired on 2026-10-19"
expect_fail_with "an entry that outlasts 60 days fails"                           too-long.reg zip.out         "runs past 2026-12-15"
expect_fail_with "an entry that expires before it was recorded fails"             backwards.reg zip.out        "before it was recorded"
expect_fail_with "an entry with a date that is not a date fails"                  bad-date.reg zip.out         "real YYYY-MM-DD dates"
expect_fail_with "an entry with no owner fails"                                   no-owner.reg zip.out         "lacks: owner"
expect_fail_with "an entry with no release condition fails"                       no-release.reg zip.out       "lacks: release-on"
expect_fail_with "an entry listed twice fails"                                    twice.reg zip.out            "appears twice"
expect_fail_with "a stale entry fails once the crate is no longer yanked"         valid.reg clean.out          "matches no yanked crate"

expect_fail_with "a vulnerability fails"                                          empty.reg vuln.out           "wasmtime 49.0.2 has RUSTSEC-2026-0353"
expect_fail_with "a vulnerability fails even beside a registered yanked crate"    valid.reg vuln-and-zip.out   "wasmtime 49.0.2 has RUSTSEC-2026-0353"
expect_fail_with "an unmaintained crate fails"                                    valid.reg unmaintained.out   "paste 1.0.15 is unmaintained"
expect_fail_with "an audit that failed without a readable finding fails"          empty.reg unreadable.out     "without reporting a finding"
expect_fail_with "a count the checker cannot reproduce fails"                     valid.reg miscounted.out     "denied 3 warning"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
