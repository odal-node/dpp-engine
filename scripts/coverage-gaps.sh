#!/usr/bin/env bash
# From the report `scripts/coverage.sh` writes, list the error-producing sites in
# each HTTP handler and whether any test tier executed them (#641).
#
# # What a site is
#
# A handler is a top-level `fn <name>(` up to the next `}` in column 0, the same
# boundary `openapi_contract::handler_body` uses, in the files that contract test
# reads plus the router and middleware files. Inside it, a line holding one of
# `openapi_contract::CODE_TOKENS` is a site that can produce that code. The tokens
# are read from that test, so the two cannot disagree about what a handler can
# return; test modules are skipped.
#
# # Usage
#
#   bash scripts/coverage-gaps.sh <coverage.lcov> <source root> [<coverage.json>]
#
# or `just coverage-gaps`. Writes a TSV to stdout, one row per site:
#
#   status  kind  file  line  fn  code  region  basis  line_hits  source
#
# # Why the JSON
#
# A site is judged by the REGION that holds the token, read from the JSON export.
# llvm-cov counts a line by the regions that start on it, so a closure or a match
# arm that shares a line with code that ran reads as run, and an argument line in
# the middle of a multi-line call (`StatusCode::GONE,`) has no line entry at all.
# Without the JSON the lcov line count is used, and those two cases are wrong
# (needs `jq` when the JSON is given).
#
# # Columns
#
# status
#   UNRUN      no test tier executed the site
#   RUN        executed at least once
#   UNDECIDED  the report cannot say: a closure that only names a status
#              (`|_| StatusCode::BAD_GATEWAY`) is not instrumented, and nothing
#              counts it when it ends an expression; `ok_or(<error>)` builds its
#              error whether or not it is used, so a count over it is the calls.
#              Read these by hand.
#   NOREG      the report has no region over the token (never compiled into a test)
#   SHARED     the site is a shared refusal, not a handler's own (see kind)
# kind
#   SITE       the token builds the response; the count is the branch's
#   GUARD      `require_write(` / `require_admin(`: the count is the `return` that
#              follows the call, since the call line runs for every request
#   GATE       `RequireWrite` / `RequireAdmin` as an extractor: the refusal is one
#              line in the extractor, shared by every gated route, so no count can
#              be attributed to this route
#   HELPER     a site inside `handlers/error.rs` or `middleware/`: shared by callers
# region, line_hits
#   executions of the innermost region over the token (max over every function
#   record that contains it), and the lcov line count
# basis
#   in      the token is inside a counted region
#   hole    between two regions of one statement, which agree
#   hole?   between two regions that differ (`return resp;` sits between the
#           condition and the arm; `.map_err(|_| X)?` between the call and the `?`,
#           whose count is the errors taken): the smaller is taken. Read by hand.
#
# # What it does not see
#
# A refusal built outside the handler files, and a handler that delegates to a
# helper in another file: the helper's sites are listed under the helper's name,
# and joining them to the handler that calls it is left to the reader.
set -euo pipefail

LCOV="${1:?usage: coverage-gaps.sh <coverage.lcov> <source root> [<coverage.json>]}"
ROOT="$(cd "${2:?usage: coverage-gaps.sh <coverage.lcov> <source root> [<coverage.json>]}" && pwd -P)"
JSON="${3:-}"

if [ -n "$JSON" ]; then
    command -v jq > /dev/null || { echo "coverage-gaps: jq is needed to read $JSON" >&2; exit 1; }
fi

# `"<token>", <code>` pairs of CODE_TOKENS, as `token|code`, space separated.
CONTRACT="$ROOT/crates/dpp-node/tests/openapi_contract.rs"
TOKENS="$(awk '/^const CODE_TOKENS/ { on = 1; next } on && /^\];/ { exit } on && !/^[[:space:]]*\/\//' "$CONTRACT" \
    | grep -oE '\("[^"]+", [0-9]+\)' \
    | sed -E 's/^\("([^"]+)", ([0-9]+)\)$/\1|\2/' | tr '\n' ' ')"
[ -n "$TOKENS" ] || { echo "coverage-gaps: no CODE_TOKENS in $CONTRACT" >&2; exit 1; }

# The files the contract test reads for handlers, plus the middleware the codes
# also come from.
mapfile -t FILES < <(find "$ROOT/crates" -path '*/src/*' -name '*.rs' \
    \( -path '*/handlers/*' -o -name 'router.rs' -o -path '*/middleware/*' \) | sort)

REGIONS="$(mktemp)"
trap 'rm -f "$REGIONS"' EXIT
if [ -n "$JSON" ]; then
    # file, line start, col start, line end, col end, count, function index —
    # code regions (kind 0) of the files above only.
    jq -r '.data[0].functions | to_entries[] | .key as $i | .value | .filenames as $fn
           | .regions[] | select(.[7] == 0)
           | select($fn[.[5]] | test("/(handlers|middleware)/|/router\\.rs$"))
           | [$fn[.[5]], .[0], .[1], .[2], .[3], .[4], $i] | @tsv' "$JSON" > "$REGIONS"
fi

awk -F'\t' -v pairs="$TOKENS" -v usejson="${JSON:+1}" '
function rel(path,   i) {
    i = index(path, "/crates/")
    return i ? substr(path, i + 1) : path
}
BEGIN {
    ntok = split(pairs, pair, " ")
    for (i = 1; i <= ntok; i++) { split(pair[i], kv, "|"); tok[i] = kv[1]; code[i] = kv[2] }
}
# Pass 1: the lcov report, keyed by the path from `crates/` on.
FILENAME == ARGV[1] {
    if ($0 ~ /^SF:/) { sf = rel(substr($0, 4)); next }
    if ($0 ~ /^DA:/) { split(substr($0, 4), d, ","); hits[sf ":" d[1]] = d[2]; seen[sf] = 1 }
    next
}
# Pass 2: the regions, as encoded positions line*10000+col, grouped by function.
usejson && FILENAME == ARGV[2] {
    f = rel($1); k = ++nreg[f]
    rS[f, k] = $2 * 10000 + $3; rE[f, k] = $4 * 10000 + $5; rct[f, k] = $6; rfn[f, k] = $7
    if (!((f, $7) in fmin)) { fnids[f, ++nfn[f]] = $7; fmin[f, $7] = rS[f, k]; fmax[f, $7] = rE[f, k] }
    if (rS[f, k] < fmin[f, $7]) fmin[f, $7] = rS[f, k]
    if (rE[f, k] > fmax[f, $7]) fmax[f, $7] = rE[f, k]
    next
}
# Pass 3: every source file, buffered so a guard can look ahead.
FNR == 1 { if (nl) flush(); file = FILENAME; nl = 0 }
{ nl = FNR; L[FNR] = $0 }
END { if (nl) flush() }

# Executions at the token, from the innermost function record whose extent holds
# it (a closure, not the function around it), maximised over records of equal
# extent (generic instances, one per test binary). Inside that record the count
# is the innermost region over the token (basis "in"). A token in a call argument
# sits in a hole between two regions of one statement ("hole": the regions on
# either side agree). Across a branch the two sides differ and the smaller side is
# taken ("hole?"). -1 when no record holds the token. The basis is left in
# `rbasis`.
function region_count(f, T,   k, i, fn, S, E, sz, bsz, bct, pE, pct, nS, nct, lo, hi, ext, val, bas, best, mx, mbas, any) {
    for (k = 1; k <= nreg[f]; k++) {
        fn = rfn[f, k]; S = rS[f, k]; E = rE[f, k]
        if (S <= T && T < E) {
            sz = E - S
            if (!(fn in bsz) || sz < bsz[fn] || (sz == bsz[fn] && rct[f, k] > bct[fn])) { bsz[fn] = sz; bct[fn] = rct[f, k] }
        } else if (E <= T) {
            if (!(fn in pE) || E > pE[fn]) { pE[fn] = E; pct[fn] = rct[f, k] }
        } else if (!(fn in nS) || S < nS[fn]) { nS[fn] = S; nct[fn] = rct[f, k] }
    }
    any = 0
    for (i = 1; i <= nfn[f]; i++) {
        fn = fnids[f, i]; lo = fmin[f, fn]; hi = fmax[f, fn]
        if (!(lo <= T && T < hi)) continue
        if (fn in bct) { val = bct[fn]; bas = "in" }
        else if ((fn in pct) && (fn in nct)) {
            if (pct[fn] == nct[fn]) { val = pct[fn]; bas = "hole" }
            else { val = (pct[fn] < nct[fn]) ? pct[fn] : nct[fn]; bas = "hole?" }
        }
        else if (fn in pct) { val = pct[fn]; bas = "hole" }
        else if (fn in nct) { val = nct[fn]; bas = "hole" }
        else continue
        ext = hi - lo
        if (!any || ext < best) { best = ext; mx = val; mbas = bas; any = 1 }
        else if (ext == best && val > mx) { mx = val; mbas = bas }
    }
    rbasis = any ? mbas : "-"
    return any ? mx : -1
}

function flush(   i, k, r, h, inh, intest, src, line, kind, st, t, ln, col, j, emitted, rc, lh, bs) {
    r = rel(file)
    inh = 0
    for (i = 1; i <= nl; i++) {
        line = L[i]
        # a test module runs to the `}` in column 0 that closes it
        if (intest) { if (line ~ /^}/ || line ~ /^mod [a-z_0-9]+;/) intest = 0; continue }
        if (line ~ /^#\[cfg\(test\)\]/) { intest = 1; continue }
        t = line; sub(/^[ \t]+/, "", t)
        if (!inh && line ~ /^(pub(\([a-z]+\))? )?(async )?fn [a-z0-9_]+[(<]/) {
            match(line, /fn [a-z0-9_]+/); h = substr(line, RSTART + 3, RLENGTH - 3); inh = 1
            # a signature line carries RequireWrite/RequireAdmin as a parameter
            # type, and nothing else on it is a site
            if (!match(line, /Require(Write|Admin)/)) continue
        }
        if (inh) {
            if (t ~ /^\/\//) { if (line ~ /^}/) inh = 0; continue }
            split("", emitted)
            for (k = 1; k <= ntok; k++) {
                if (!index(line, tok[k])) continue
                # a definition line is not a use
                if (t ~ /^(pub(\([a-z]+\))? )?(async )?fn /  && tok[k] !~ /^Require/) continue
                if (emitted[code[k]]++) continue
                ln = i; col = index(line, tok[k]); kind = "SITE"
                if (tok[k] ~ /^require_/) {
                    kind = "GUARD"
                    for (j = i; j <= i + 4 && j <= nl; j++) if (L[j] ~ /return/) { ln = j; col = index(L[j], "return"); break }
                } else if (tok[k] ~ /^Require/) kind = "GATE"
                if (r ~ /(handlers\/error|middleware\/)/) kind = "HELPER"
                lh = ((r ":" ln) in hits) ? hits[r ":" ln] : "-"
                rc = usejson ? region_count(r, ln * 10000 + col) : -1; bs = usejson ? rbasis : "-"
                if (!(r in seen)) st = "NOREG"
                else if (usejson) st = (rc < 0) ? "NOREG" : (rc == 0 ? "UNRUN" : "RUN")
                else st = (lh == "-") ? "NOREG" : (lh == 0 ? "UNRUN" : "RUN")
                # A closure whose body is only the status is not instrumented at
                # all. Followed by `?` the count of the `?` is the errors taken and
                # the hole rule reads it; as the tail of an expression nothing
                # counts it, so the report cannot say.
                if (usejson && kind == "SITE" && bs != "in" && substr(L[ln], 1, col - 1) ~ /\|[^|]*\|[ \t]*$/ && L[ln] !~ /\)\?;?[ \t]*$/ && st != "NOREG") st = "UNDECIDED"
                # `ok_or(<error>)` builds the error whether or not it is used, so a
                # count over it is the calls, not the refusals; `ok_or_else` is lazy.
                if (usejson && kind == "SITE" && substr(L[ln], 1, col - 1) ~ /\.(ok_or|unwrap_or|map_or)\(/ && st != "NOREG") st = "UNDECIDED"
                if (kind == "GATE" || kind == "HELPER") st = (st == "NOREG" ? st : "SHARED")
                src = L[ln]; gsub(/^[ \t]+/, "", src); gsub(/\t/, " ", src)
                print st "\t" kind "\t" r "\t" ln "\t" h "\t" code[k] "\t" (rc < 0 ? "-" : rc) "\t" bs "\t" lh "\t" substr(src, 1, 110)
            }
            if (line ~ /^}/) inh = 0
        }
    }
}
' "$LCOV" ${JSON:+"$REGIONS"} "${FILES[@]}"
