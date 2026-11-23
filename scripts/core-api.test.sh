#!/usr/bin/env bash
# Self-test for the shadow check in scripts/core-api.sh.
#
# A gate nobody has watched fail is a gate nobody knows works. This one reads two
# source trees and matches types by shape, so it has more ways to be quietly
# wrong than a grep: a normaliser that stops folding case reads every camelCase
# mirror as a different type, and a join that stops looking at wire names misses
# the copy that renames a field. Either leaves the check green over a shadow.
#
# So each case below hands the matcher a small core and a small engine and asserts
# what it reports, and what it must not. No cargo, no nightly, no network: the
# matcher takes its three inputs as files.
set -euo pipefail

# shellcheck source=core-api.sh
source "$(cd "$(dirname "$0")" && pwd)/core-api.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

T=$'\t'
pass=0
fail=0

ok() {
  pass=$((pass + 1))
  echo "ok:   $1"
}
bad() {
  fail=$((fail + 1))
  echo "FAIL: $1" >&2
}

# ── The matcher ──────────────────────────────────────────────────────────────

# What core publishes. `Hidden` is declared in core and reachable by no public
# path, so the engine could not use it.
cat >"$TMP/public.tsv" <<EOF
dpp-domain${T}struct${T}Foo${T}dpp_domain::Foo${T}
dpp-domain${T}enum${T}Level${T}dpp_domain::Level${T}
dpp-domain${T}struct${T}Renamed${T}dpp_domain::Renamed${T}
dpp-domain${T}const${T}URN_PREFIX${T}dpp_domain::URN_PREFIX${T}
EOF

cat >"$TMP/core.tsv" <<EOF
dpp-domain${T}struct${T}Foo${T}f.rs:1${T}product_group,batch_id,identifier
dpp-domain${T}enum${T}Level${T}f.rs:9${T}Model,Batch,Serial
dpp-domain${T}const${T}URN_PREFIX${T}f.rs:20${T}"urn:odal-node:"
dpp-domain${T}struct${T}Hidden${T}f.rs:30${T}alpha,beta,gamma,delta
dpp-domain${T}struct${T}Renamed${T}f.rs:40${T}nothing=none,outside=out,tag
EOF

cat >"$TMP/engine.tsv" <<EOF
struct${T}Mirror${T}e.rs:1${T}productGroup,batchId,identifier
struct${T}Foo${T}e.rs:5${T}totally,different
enum${T}Tier${T}e.rs:9${T}Model,Batch,Serial
const${T}URN${T}e.rs:15${T}"urn:odal-node:"
struct${T}Unrelated${T}e.rs:20${T}one,two,three
struct${T}Duplicate${T}e.rs:30${T}alpha,beta,gamma,delta
struct${T}WireCopy${T}e.rs:40${T}none,out,tag
enum${T}Small${T}e.rs:50${T}Model,Batch
const${T}SHORT${T}e.rs:60${T}"ab"
EOF

join_shadows "$TMP/public.tsv" "$TMP/core.tsv" "$TMP/engine.tsv" >"$TMP/found.tsv"

# `relation engine-type core-type` for each finding, to assert against.
report="$(awk -F'\t' '{ print $1 " " $4 " " $7 }' "$TMP/found.tsv")"

expect() {
  if grep -qxF "$1" <<<"$report"; then ok "$2"; else bad "$2 (wanted: $1)"; fi
}
refuse() {
  if grep -qF "$1" <<<"$report"; then bad "$2 (found: $1)"; else ok "$2"; fi
}

expect "same-shape Mirror Foo" "a camelCase copy of a snake_case struct is the same shape"
expect "same-name Foo Foo" "a type with core's name is a finding whatever it holds"
expect "same-shape Tier Level" "an enum with core's variants is the same shape"
expect "same-shape WireCopy Renamed" "a member matches core's by the wire name serde gives it"
expect "same-value URN URN_PREFIX" "a constant with a value core already names is a finding"
refuse "Unrelated" "a type that shares nothing is not a finding"
refuse "Duplicate" "a copy of a type core does not publish is not a finding"
refuse "Small" "two variants of three is below the line"
refuse "SHORT" "a short constant value is too common to mean anything"

# ── The record ───────────────────────────────────────────────────────────────

one="same-shape${T}0.75${T}struct${T}Mirror${T}e.rs:1${T}dpp-domain${T}Foo${T}3${T}${T}"
printf '%s\n' "$one" >"$TMP/one.tsv"

verdict() {
  if compare_shadows "$TMP/one.tsv" "$1" 2>"$TMP/stderr"; then echo accept; else echo reject; fi
}

printf '# a comment\n\n' >"$TMP/empty.allow"
if [[ "$(verdict "$TMP/empty.allow")" == reject ]] && grep -q '^NEW:' "$TMP/stderr"; then
  ok "a shadow nobody recorded is refused, and called new"
else
  bad "an unrecorded shadow was accepted"
fi

printf 'same-shape\tMirror\tdpp-domain::Foo\tan adapter, on purpose\n' >"$TMP/recorded.allow"
if [[ "$(verdict "$TMP/recorded.allow")" == accept ]]; then
  ok "a recorded shadow is accepted"
else
  bad "a recorded shadow was refused"
fi

printf 'same-shape\tMirror\tdpp-domain::Foo\tan adapter\nsame-name\tGone\tdpp-domain::Gone\tfixed since\n' >"$TMP/stale.allow"
if [[ "$(verdict "$TMP/stale.allow")" == reject ]] && grep -q '^STALE:' "$TMP/stderr"; then
  ok "a record of a shadow that is gone is refused, so the list only shrinks"
else
  bad "a stale record was accepted"
fi

printf 'same-shape\tMirror\tdpp-domain::Foo\t\n' >"$TMP/noreason.allow"
if [[ "$(verdict "$TMP/noreason.allow")" == reject ]] && grep -q '^NO REASON:' "$TMP/stderr"; then
  ok "a record with no reason is refused"
else
  bad "a record with no reason was accepted"
fi

echo "core-api self-test: $pass passed, $fail failed."
[[ "$fail" -eq 0 ]]
