#!/usr/bin/env bash
# Forbid un-guarded outbound HTTP client construction in service crate src.
#
# `dpp_common::outbound` is the one path that applies the resolving SSRF guard,
# refuses redirects, caps the body and times out. `reqwest::get`, `Client::new()`
# and `Client::builder()` build a client with none of those unless every control
# is restated by hand — and that is exactly how two call sites ended up fetching
# attacker-named hosts with no guard at all while an identical, correctly-hardened
# fetch sat in the next module.
#
# `Client::builder()` is banned alongside the other two rather than trusted
# because it is the constructor a correct-looking client is written with: it
# carries reqwest's default redirect policy (ten hops) and no timeout until a
# caller adds them, so a builder that sets only a timeout reads as hardened and
# is not. Banning the constructor makes every client either allow-listed here
# with a reason, or guarded.
#
# Operator-CHOSEN targets are a different trust class and legitimately build
# their own clients, so they are listed by file rather than caught by a blanket
# rule. Each entry is a target this operator configured, not one a stranger named.
#
# Test code is exempt (a test double needs no SSRF guard), detected by the repo
# convention that `#[cfg(test)]` modules sit at the bottom of a file: a match
# below the first `#[cfg(test)]` line is test code. Whole-file test modules
# (`tests.rs`, `*_tests.rs`) are skipped outright.
#
# Two `grep -r` passes and one `awk`, rather than a per-file loop. The loop shape
# spawned four processes per file across ~300 files, which on Windows is a
# minute of silence and reads as a hang — a gate people stop running.
set -euo pipefail

DIRS=(crates cli)

allow='crates/dpp-common/src/outbound.rs
crates/dpp-node/src/boot/tasks.rs
crates/dpp-node/src/infra/registry/client.rs
crates/dpp-integrator/src/infra/vault_client.rs
crates/dpp-resolver/src/main.rs
crates/dpp-seal/src/eideasy/client.rs
crates/dpp-vault/src/infra/identity_client.rs
cli/src/http.rs'

# Pass 1: first `#[cfg(test)]` line per file. Pass 2: every banned construction.
# `|| true` because grep exits 1 on no matches, which is the success case here.
cfg_lines=$(grep -rn --include='*.rs' -F '#[cfg(test)]' "${DIRS[@]}" 2>/dev/null || true)
hits=$(grep -rnE --include='*.rs' \
         -e 'reqwest::get\(' -e 'Client::new\(\)' -e 'Client::builder\(\)' \
         "${DIRS[@]}" 2>/dev/null || true)

violations=$(
    awk -F: -v allow="$allow" '
        BEGIN {
            split(allow, a, "\n")
            for (i in a) { gsub(/^[ \t]+|[ \t]+$/, "", a[i]); allowed[a[i]] = 1 }
        }
        # Normalise Windows backslashes so path comparisons hold everywhere.
        function norm(p) { gsub(/\\/, "/", p); return p }
        # Pass 1 records the earliest #[cfg(test)] line per file.
        NR == FNR {
            f = norm($1)
            if (!(f in cut) || $2 + 0 < cut[f]) cut[f] = $2 + 0
            next
        }
        {
            f = norm($1)
            if (f in allowed) next
            if (f ~ /(^|\/)tests\.rs$/ || f ~ /_tests\.rs$/) next
            # Only src/ is in scope; tests/ and benches/ are not service code.
            if (f !~ /\/src\//) next
            limit = (f in cut) ? cut[f] : 2147483647
            if ($2 + 0 < limit) print "  " f ":" $2
        }
    ' <(printf '%s\n' "$cfg_lines") <(printf '%s\n' "$hits")
)

if [ -n "$violations" ]; then
    echo "ERROR: unguarded outbound HTTP client in service src — use dpp_common::outbound"
    echo "       (operator-chosen targets that legitimately build their own client"
    echo "        belong in the allow-list in scripts/outbound-check.sh, with a reason)"
    echo "$violations"
    exit 1
fi
