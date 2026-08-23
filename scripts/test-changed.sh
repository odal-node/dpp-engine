#!/usr/bin/env bash
# Run only the tests a change can affect.
#
# Maps changed files to the crates that own them, then hands nextest an
# `rdeps()` filterset — every test in those crates and in everything that
# depends on them. Measured selectivity against the 1,041-test workspace:
# a dpp-resolver edit selects 67, dpp-integrator 247, dpp-vault 471, dpp-dal 511.
#
# This is an iteration aid, never a substitute for `just check` before pushing.
# It reasons about crate boundaries, not behaviour: a change that alters a
# runtime contract without touching the dependent crate's source is invisible to
# it, and so is anything reached only through a trait object.
#
# Falls back to the full suite whenever the blast radius is not a crate — a
# manifest, a migration, CI config, or a file it cannot attribute. Erring toward
# running everything is the only safe direction for a tool that decides what to
# skip.
#
# Usage:
#   just test-changed             # working tree + commits, against origin/main
#   just test-changed HEAD~3      # against another base
set -euo pipefail

base="${1:-origin/main}"

if ! git rev-parse --verify --quiet "$base" > /dev/null; then
    echo "test-changed: '$base' is not a revision this repo knows; falling back to main." >&2
    base="main"
fi

# Committed since the base, plus anything uncommitted — the point is to be
# useful mid-edit, not only after a commit.
changed=$(
    {
        git diff --name-only "$base"...HEAD
        git diff --name-only
        git diff --name-only --cached
        git ls-files --others --exclude-standard
    } | sort -u
)

if [ -z "$changed" ]; then
    echo "test-changed: nothing changed against $base."
    exit 0
fi

# Paths whose blast radius is not one crate. A migration reshapes the schema
# every DB-backed suite asserts against; a manifest can move any dependency
# edge; CI and nextest config change how the whole suite runs.
full_suite_globs='^(Cargo\.toml|Cargo\.lock|\.config/|\.github/|ops/|justfile|scripts/|deny\.toml|rust-toolchain\.toml)'

crates=""
unattributed=""
while IFS= read -r file; do
    [ -z "$file" ] && continue

    if printf '%s' "$file" | grep -qE "$full_suite_globs"; then
        echo "test-changed: '$file' can affect any crate — running the full suite."
        exec cargo nextest run --workspace --all-features
    fi

    case "$file" in
        crates/*)
            # crates/<name>/... -> <name>
            rest="${file#crates/}"
            crates="$crates ${rest%%/*}"
            ;;
        cli/*)
            crates="$crates dpp-cli"
            ;;
        api/*|docs/*|*.md)
            # Prose and the API description compile nothing.
            ;;
        *)
            unattributed="$unattributed $file"
            ;;
    esac
done <<< "$changed"

if [ -n "$unattributed" ]; then
    echo "test-changed: cannot attribute$unattributed to a crate — running the full suite."
    exec cargo nextest run --workspace --all-features
fi

# shellcheck disable=SC2086
crates=$(printf '%s\n' $crates | sort -u)

if [ -z "$crates" ]; then
    echo "test-changed: only non-compiling files changed; nothing to run."
    exit 0
fi

filter=""
while IFS= read -r c; do
    [ -z "$c" ] && continue
    if [ -n "$filter" ]; then
        filter="$filter + rdeps($c)"
    else
        filter="rdeps($c)"
    fi
done <<< "$crates"

echo "test-changed: $filter"
cargo nextest run --workspace --all-features -E "$filter"
