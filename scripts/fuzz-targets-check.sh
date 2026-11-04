#!/usr/bin/env bash
# Every fuzz target is built, run by the nightly fuzz job, and documented.
#
# The fuzz crate is its own workspace and builds only on nightly, so nothing in
# `just check` compiles its targets, and they run only through the matrix in
# `.github/workflows/fuzz.yml`. Three hand-kept lists describe one set of
# targets, and nothing related them:
#
#   - the `[[bin]]` tables in fuzz/Cargo.toml, which is what builds;
#   - the matrix's `target:` list, which is what runs;
#   - the table in fuzz/README.md, which says what each one guards.
#
# A target missing from the matrix never runs and nothing says so: dpp-core's
# `plugin_abi_envelope` sat in its manifest, never run, until the two lists were
# compared by hand. A file under fuzz/fuzz_targets/ that no
# `[[bin]]` names never builds, so it rots unseen. This fails for either, for a
# `[[bin]]` whose `path` does not exist, and for a target the README does not
# name. It also fails when either list reads as empty: two empty sets agree,
# and a format change that defeated the parsing would otherwise pass.
#
# The matrix must be written as a block list, one `- name` per line; the inline
# `[a, b]` form reads as empty and fails.
set -euo pipefail

ROOT="${FUZZ_TARGETS_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

MANIFEST=fuzz/Cargo.toml
WORKFLOW=.github/workflows/fuzz.yml
README=fuzz/README.md

status=0

# The value of `key = "..."` on every line inside a `[[bin]]` table.
bin_field() {
  awk -v key="$1" '
    /^[[:space:]]*\[/ { in_bin = ($0 ~ /^[[:space:]]*\[\[bin\]\][[:space:]]*$/); next }
    in_bin && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*"/, ""); sub(/".*$/, ""); print
    }
  ' "$MANIFEST" | sort
}

built="$(bin_field name)"
paths="$(bin_field path)"

# The entries of the matrix's `target:` block list; comments and blank lines
# between entries are skipped, and the list ends at the first other line.
run="$(awk '
  /^[[:space:]]*target:[[:space:]]*$/ { in_list = 1; next }
  in_list && /^[[:space:]]*(#.*)?$/ { next }
  in_list && /^[[:space:]]*- / { sub(/^[[:space:]]*- [[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; next }
  in_list { exit }
' "$WORKFLOW" | sort)"

if [ -z "$built" ]; then
  echo "ERROR: no [[bin]] name read from $MANIFEST." >&2
  status=1
fi
if [ -z "$run" ]; then
  echo "ERROR: no matrix \`target:\` list read from $WORKFLOW (write it one \`- name\` per line)." >&2
  status=1
fi
[ "$status" -eq 0 ] || exit "$status"

while IFS= read -r name; do
  echo "ERROR: fuzz target \`$name\` is built by $MANIFEST but the nightly job never runs it." >&2
  echo "       Add it to the matrix's \`target:\` list in $WORKFLOW." >&2
  status=1
done < <(comm -23 <(printf '%s\n' "$built") <(printf '%s\n' "$run"))

while IFS= read -r name; do
  echo "ERROR: $WORKFLOW runs fuzz target \`$name\`, which $MANIFEST does not build." >&2
  status=1
done < <(comm -13 <(printf '%s\n' "$built") <(printf '%s\n' "$run"))

while IFS= read -r path; do
  if [ ! -f "fuzz/$path" ]; then
    echo "ERROR: a [[bin]] in $MANIFEST names fuzz/$path, which does not exist." >&2
    status=1
  fi
done <<< "$paths"

for file in fuzz/fuzz_targets/*.rs; do
  [ -e "$file" ] || continue
  if ! grep -qxF "${file#fuzz/}" <<< "$paths"; then
    echo "ERROR: $file is named by no [[bin]] in $MANIFEST, so it is never built." >&2
    status=1
  fi
done

# A row of the targets table, whose first cell is the name. A mention anywhere
# else in the README does not count: the corpus section names two targets.
while IFS= read -r name; do
  if ! grep -qE "^\|[[:space:]]*\`${name}\`[[:space:]]*\|" "$README"; then
    echo "ERROR: $README has no row for fuzz target \`$name\` in its table of targets." >&2
    status=1
  fi
done <<< "$built"

exit "$status"
