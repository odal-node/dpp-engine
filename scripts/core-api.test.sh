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
dpp-domain${T}struct${T}FieldErr${T}dpp_domain::FieldErr${T}
dpp-domain${T}struct${T}Token${T}dpp_domain::Token${T}
dpp-domain${T}const${T}MAX_RETRIES${T}dpp_domain::MAX_RETRIES${T}
dpp-domain${T}struct${T}Aliased${T}dpp_domain::Aliased${T}
EOF

cat >"$TMP/core.tsv" <<EOF
dpp-domain${T}struct${T}Foo${T}f.rs:1${T}product_group,batch_id,identifier
dpp-domain${T}enum${T}Level${T}f.rs:9${T}Model,Batch,Serial
dpp-domain${T}const${T}URN_PREFIX${T}f.rs:20${T}"urn:odal-node:"
dpp-domain${T}struct${T}Hidden${T}f.rs:30${T}alpha,beta,gamma,delta
dpp-domain${T}struct${T}Renamed${T}f.rs:40${T}nothing=none,outside=out,tag
dpp-domain${T}struct${T}FieldErr${T}f.rs:50${T}field,message
dpp-domain${T}struct${T}Token${T}f.rs:60${T}
dpp-domain${T}const${T}MAX_RETRIES${T}f.rs:70${T}10
dpp-domain${T}struct${T}Aliased${T}f.rs:90${T}red=crimson,blue
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
struct${T}Blocker${T}e.rs:70${T}field,message
struct${T}Lopsided${T}e.rs:80${T}field,hint
struct${T}Token${T}e.rs:90${T}
const${T}MAX_RETRIES${T}e.rs:100${T}3
struct${T}AliasPair${T}e.rs:110${T}red,crimson
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
expect "same-shape Blocker FieldErr" "a two-member type that is exactly core's is a finding"
refuse "Lopsided" "two members of which one is core's is not"
refuse "AliasPair" "two members that both answer to one of core's, with core's other member unmatched, are not a copy"
expect "same-name Token Token" "a tuple struct with core's name is a finding, though it has no named member"
expect "same-name-other-value MAX_RETRIES MAX_RETRIES" "a short value does not hide a name core owns with another value"

# ── The reader of source ─────────────────────────────────────────────────────
#
# The matcher above is fed rows. What produces them is `shapes`, which reads
# rustfmt-ed source, and a reader that quietly drops a kind of declaration leaves
# the check green over it: a tuple struct named for a core type escaped, once,
# because it was never turned into a row.

cat >"$TMP/sample.rs" <<'RS'
pub struct Wrapper(String);
pub struct Marker;
pub struct Empty {}
pub struct Wire {
    #[serde(rename = "kind")]
    pub variant: String,
    pub plain_name: u8,
}
pub enum Choice {
    A,
    #[serde(rename = "bee")]
    B(u8),
}
pub const NAME: &str = "a-long-enough-value";

#[cfg(test)]
mod tests {
    pub struct InTest {
        pub x: u8,
    }
}
RS

read_source="$(printf '%s\n' "$TMP/sample.rs" | shapes | awk -F'\t' '{ print $1 " " $2 " [" $4 "]" }')"

source_has() {
  if grep -qxF "$1" <<<"$read_source"; then ok "$2"; else bad "$2 (wanted: $1; read: $read_source)"; fi
}
source_has "struct Wrapper []" "a tuple struct is read, with no members"
source_has "struct Marker []" "a unit struct is read, with no members"
source_has "struct Empty []" "an empty braced struct is read, with no members"
source_has "struct Wire [variant=kind,plain_name]" "a serde rename is read as the member's wire name"
source_has "enum Choice [A,B=bee]" "variants are read, with a rename"
source_has 'const NAME ["a-long-enough-value"]' "a literal constant is read with its value"
if grep -q "InTest" <<<"$read_source"; then bad "a type after #[cfg(test)] was read"; else ok "a type after #[cfg(test)] is not read"; fi

# ── The words an enum puts on a wire ─────────────────────────────────────────
#
# `wire_words` has to say what serde says, or a literal that is core's word is
# missed (the word read as `Draft` for `draft`) and one that is not is invented.
# Each rename rule core uses is here, and each way a wire word is written by hand.

cat >"$TMP/words.rs" <<'RS'
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Camel {
    FirstThing,
    #[serde(rename = "re-used")]
    Reused,
    Payload(u8),
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "bundle", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
pub enum Shout {
    NotImplemented,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kebab {
    OtherMobilePhone,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plain {
    Model,
}

#[derive(Serialize, Deserialize)]
pub enum Bare {
    Original,
}

#[derive(Debug, Clone)]
pub enum NoSerde {
    Hidden,
}

#[derive(Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum Converted {
    Opaque,
}

pub enum Status {
    Draft,
    Published,
    Other(String),
}

impl Status {
    pub const fn wire_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "active",
            Self::Other(s) => s,
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft | Self::Published => f.write_str("shown"),
            Self::Other(_) => f.write_str("else"),
        }
    }
}

fn label(g: Plain) -> &'static str {
    match g {
        Plain::Model => "the-model",
    }
}

#[cfg(test)]
mod tests {
    #[derive(Serialize)]
    pub enum InTest {
        Ignored,
    }
}
RS

read_words="$(printf '%s\n' "$TMP/words.rs" | wire_words | awk -F'\t' '{ print $1 "::" $2 "=" $4 " (" $5 ")" }')"

word_has() {
  if grep -qxF "$1" <<<"$read_words"; then ok "$2"; else bad "$2 (wanted: $1; read: $read_words)"; fi
}
word_lacks() {
  if grep -q "$1" <<<"$read_words"; then bad "$2 (found: $1)"; else ok "$2"; fi
}
word_has "Camel::FirstThing=firstThing (serde)" "rename_all camelCase is applied to a variant"
word_has "Camel::Reused=re-used (serde)" "a variant rename wins over the enum's rule"
word_has "Shout::NotImplemented=NOT_IMPLEMENTED (serde)" "SCREAMING_SNAKE_CASE is read through a cfg_attr"
word_has "Kebab::OtherMobilePhone=other-mobile-phone (serde)" "kebab-case splits at each capital"
word_has "Plain::Model=model (serde)" "lowercase is applied"
word_has "Bare::Original=Original (serde)" "an enum with no rule writes the variant as spelt"
word_lacks "NoSerde" "an enum that is never serialised has no wire words"
word_lacks "Opaque" "an enum that converts through a string has no variant words on the wire"
word_lacks "Ignored" "an enum after #[cfg(test)] is not read"
word_has "Status::Draft=draft (arm)" "a match arm returning a literal is a wire word of its enum"
word_has "Status::Published=active (arm)" "the word is the literal, not the variant name"
word_has "Status::Published=shown (arm)" "an or-pattern gives each variant the literal"
word_has "Status::Other=else (arm)" "f.write_str of a literal is read as an arm"
word_lacks "Status::Other=s" "an arm that returns a value, not a literal, is no word"
word_has "Plain::Model=the-model (arm)" "a named type in an arm is read outside an impl"

# ── The literals an engine writes ────────────────────────────────────────────

cat >"$TMP/lits.rs" <<'RS'
#[serde(rename = "in-attribute")]
fn a() {
    let s = "draft"; // "in-comment"
    let q = '"'; let t = "after-quote";
    let r = r#"raw "inner" text"#;
    /* "in-block" */ let u = "after-block";
    let m = "two
lines";
    let e = "a\"b";
    let c = '\''; let v = "after-char";
    match x { "pattern" => 1, _ => 0 }
}
#[cfg(test)]
mod tests {
    fn t() { let _ = "in-test"; }
}
RS

lits_of="$(printf '%s\n' "$TMP/lits.rs" | literals | awk -F'\t' '{ print $2 }' | tr '\n' '~')"

lit_has() {
  if grep -qF "$1" <<<"$lits_of"; then ok "$2"; else bad "$2 (wanted: $1; read: $lits_of)"; fi
}
lit_lacks() {
  if grep -qF "$1" <<<"$lits_of"; then bad "$2 (found: $1)"; else ok "$2"; fi
}
lit_has "draft~" "a plain literal is read"
lit_has "after-quote~" "a quote character literal does not open a string"
lit_has 'raw "inner" text~' "a raw string keeps the quotes inside it"
lit_has "after-block~" "a literal after a block comment on the same line is read"
lit_has "two"$'\n'"lines~" "a literal over two lines is one"
lit_has 'a\"b~' "an escaped quote does not end a literal"
lit_has "after-char~" "an escaped quote character literal does not open a string"
lit_has "pattern~" "a match pattern is read"
lit_lacks "in-attribute" "a literal in an attribute is not read"
lit_lacks "in-comment" "a literal in a line comment is not read"
lit_lacks "in-block" "a literal in a block comment is not read"
lit_lacks "in-test" "a literal after #[cfg(test)] is not read"

# ── The join ─────────────────────────────────────────────────────────────────

# `crate type variant file:line word via`, as the words are handed to the join.
cat >"$TMP/join.words" <<EOF
dpp-domain${T}PassportStatus${T}Draft${T}f.rs:1${T}draft${T}arm
dpp-domain${T}Granularity${T}Draft${T}f.rs:2${T}draft${T}serde
dpp-domain${T}Hidden${T}Draft${T}f.rs:3${T}secret${T}serde
EOF
cat >"$TMP/join.public" <<EOF
dpp-domain${T}enum${T}PassportStatus${T}dpp_domain::PassportStatus${T}
dpp-domain${T}enum${T}Granularity${T}dpp_domain::Granularity${T}
EOF
printf 'e.rs:5\tdraft\tbefore\tafter\ne.rs:6\tsecret\tb\ta\ne.rs:7\tother\tb\ta\n' >"$TMP/join.lits"

joined="$(join_literals "$TMP/join.public" "$TMP/join.words" "$TMP/join.lits")"
if grep -q $'^e.rs:5\tdraft\t' <<<"$joined" && grep -q 'dpp-domain::PassportStatus::Draft' <<<"$joined" && grep -q 'dpp-domain::Granularity::Draft' <<<"$joined"; then
  ok "a word two public enums share names both"
else
  bad "a shared word did not name both enums ($joined)"
fi
if grep -q 'secret' <<<"$joined"; then bad "a word of an enum core does not publish was reported"; else ok "a word of an enum core does not publish is not a finding"; fi
if grep -q 'other' <<<"$joined"; then bad "a literal that is no enum's word was reported"; else ok "a literal that is no enum's word is not a finding"; fi

# ── The clusters ─────────────────────────────────────────────────────────────
#
# What the gate holds is a cluster, not a literal: the words a file writes of one
# enum, where one of them is a place the file decides on. A rule too loose fails the
# build for `ok`; one too tight lets a copy of an enum through.

# `tier place file:line word candidate n`, as `literal_report` writes it.
cat >"$TMP/report.tsv" <<EOF
A${T}pattern${T}a.rs:10${T}draft${T}dpp-domain::PassportStatus::Draft${T}1
A${T}value${T}a.rs:4${T}active${T}dpp-domain::PassportStatus::Published${T}1
C${T}pattern${T}b.rs:7${T}draft${T}dpp-domain::PassportStatus::Draft${T}1
A${T}value${T}c.rs:1${T}draft${T}dpp-domain::PassportStatus::Draft${T}1
A${T}key${T}c.rs:2${T}active${T}dpp-domain::PassportStatus::Published${T}1
A${T}list${T}d.rs:3${T}draft${T}dpp-domain::PassportStatus::Draft${T}1
A${T}list${T}d.rs:3${T}draft${T}dpp-domain::PassportStatus::Draft${T}1
A${T}list${T}e.rs:5${T}model${T}dpp-domain::Granularity::Model${T}1
A${T}compare${T}e.rs:9${T}batch${T}dpp-domain::Granularity::Batch${T}1
A${T}other${T}e.rs:2${T}item${T}dpp-domain::Granularity::Item${T}1
EOF
clusters="$(literal_clusters "$TMP/report.tsv" | awk -F'\t' '{ print $4 " " $6 "::" $7 " " $8 " " $5 }')"

cluster_has() {
  if grep -qxF "$1" <<<"$clusters"; then ok "$2"; else bad "$2 (wanted: $1; got: $clusters)"; fi
}
cluster_lacks() {
  if grep -q "^$1 " <<<"$clusters"; then bad "$2 (found: $1)"; else ok "$2"; fi
}
cluster_has "a.rs dpp-domain::PassportStatus 2 a.rs:4" "two words of one enum, one of them in a match pattern, are a finding, placed at the first line"
cluster_lacks "b.rs" "one word is not a finding, even in a match pattern"
cluster_lacks "c.rs" "two words that stand only as a JSON key and a value are not a finding"
cluster_lacks "d.rs" "one word read twice is still one word"
cluster_has "e.rs dpp-domain::Granularity 3 e.rs:2" "words in a list, a comparison and a bare place are one finding for the file and the enum"

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

# A cluster is held to the same record as a shadow, under its own relation, with the
# file where a type would be.
literal_clusters "$TMP/report.tsv" | grep $'\ta.rs\t' >"$TMP/words.found"

printf '# nothing\n' >"$TMP/words.none"
if ! compare_shadows "$TMP/words.found" "$TMP/words.none" 2>"$TMP/stderr" && grep -q '^NEW: a.rs writes 2 words of dpp-domain::PassportStatus as strings' "$TMP/stderr"; then
  ok "a cluster nobody recorded is refused, and the message names the file, the enum and the words"
else
  bad "an unrecorded cluster was accepted, or the message is wrong ($(cat "$TMP/stderr"))"
fi

printf 'same-words\ta.rs\tdpp-domain::PassportStatus\tpending: read it as the enum\n' >"$TMP/words.allow"
if compare_shadows "$TMP/words.found" "$TMP/words.allow" 2>/dev/null; then
  ok "a recorded cluster is accepted"
else
  bad "a recorded cluster was refused"
fi

printf 'same-words\tb.rs\tdpp-domain::PassportStatus\tpending: gone\n' >"$TMP/words.stale"
if ! compare_shadows "$TMP/words.none" "$TMP/words.stale" 2>"$TMP/stderr" && grep -q '^STALE:' "$TMP/stderr"; then
  ok "a record of a cluster that is gone is refused"
else
  bad "a stale cluster record was accepted"
fi

echo "core-api self-test: $pass passed, $fail failed."
[[ "$fail" -eq 0 ]]
