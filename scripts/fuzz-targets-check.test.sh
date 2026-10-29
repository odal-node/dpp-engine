#!/usr/bin/env bash
# Self-test for scripts/fuzz-targets-check.sh.
#
# Each case builds a synthetic tree (the gate reads fuzz/ and
# .github/workflows/fuzz.yml relative to FUZZ_TARGETS_ROOT) and asserts what the
# gate says about it. No network, no cargo.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/fuzz-targets-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# A tree the gate must accept: two targets, each built, run and documented, with
# a `name` outside any [[bin]] table and a comment inside the matrix list.
scaffold() {
    local root="$1"
    mkdir -p "$root/fuzz/fuzz_targets" "$root/.github/workflows"
    touch "$root/fuzz/fuzz_targets/first.rs" "$root/fuzz/fuzz_targets/second.rs"
    cat > "$root/fuzz/Cargo.toml" <<'EOF'
[package]
name = "not-a-target"

[[bin]]
name = "first"
path = "fuzz_targets/first.rs"

[dependencies]
name = "also-not-a-target"

[[bin]]
name    = "second"
path    = "fuzz_targets/second.rs"

[workspace]
EOF
    cat > "$root/.github/workflows/fuzz.yml" <<'EOF'
jobs:
  fuzz:
    strategy:
      matrix:
        target:
          # a comment between entries
          - first

          - second
    steps:
      - uses: actions/checkout
EOF
    printf '%s\n' '| `first` | one |' '| `second` | two |' > "$root/fuzz/README.md"
}

run_case() {
    local name="$1" expect="$2" mutate="$3"
    local root="$TMP/$name"
    scaffold "$root"
    ( cd "$root" && eval "$mutate" )
    if FUZZ_TARGETS_ROOT="$root" bash "$GATE" >/dev/null 2>&1; then
        got="accept"
    else
        got="reject"
    fi
    if [ "$got" = "$expect" ]; then
        echo "ok:   $name ($got)"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate said $got, expected $expect"
        fail=$((fail + 1))
    fi
}

# The clean tree is accepted. Without this case the others would pass against a
# gate that rejects everything.
run_case "a_tree_where_every_target_runs_is_accepted" accept "true"

# 1. The failure that was found in dpp-core: a target the job never runs.
run_case "a_target_the_matrix_omits_is_refused" reject \
    "sed -i '/- second/d' .github/workflows/fuzz.yml"

# 2. The reverse: the job runs a target nothing builds.
run_case "a_matrix_entry_nothing_builds_is_refused" reject \
    "sed -i 's/- second/- second\n          - third/' .github/workflows/fuzz.yml"

# 3. A target file no [[bin]] names never builds.
run_case "a_target_file_no_bin_names_is_refused" reject \
    'touch fuzz/fuzz_targets/orphan.rs'

# 4. A [[bin]] whose source file is gone.
run_case "a_bin_whose_path_is_missing_is_refused" reject \
    'rm fuzz/fuzz_targets/second.rs'

# 5. A target the README does not name.
run_case "an_undocumented_target_is_refused" reject \
    "sed -i '/second/d' fuzz/README.md"

# 6. Named in the README, but not as a row of the table.
run_case "a_target_named_only_outside_the_table_is_refused" reject \
    "sed -i 's/^| \`second\` | two |\$/Seed \`second\` from the CSVs./' fuzz/README.md"

# 7. The inline form reads as no list at all, and an empty list never agrees.
run_case "an_inline_matrix_list_is_refused" reject \
    "sed -i '/target:/,/- second/c\\        target: [first, second]' .github/workflows/fuzz.yml"

# 8. A manifest with no [[bin]] reads as no targets, which is refused rather
#    than compared.
run_case "a_manifest_with_no_bins_is_refused" reject \
    "sed -i 's/\[\[bin\]\]/[[example]]/' fuzz/Cargo.toml"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
