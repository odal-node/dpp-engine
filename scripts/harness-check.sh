#!/usr/bin/env bash
# Forbid re-copying shared test scaffolding that already has one home.
#
# Rust cannot share `#[cfg(test)]` code across crate boundaries, so copying is
# the path of least resistance and nothing signals when it happens. The Postgres
# harness reached eight copies that had drifted into six different
# implementations before anyone counted, and the in-memory PassportRepository
# double reached three. Both now live behind dpp-dal's `test-harness` feature.
#
# This is the signal that was missing. Each entry names a definition and the one
# file allowed to contain it; anywhere else is a fork.
#
# If the shared version cannot do what a suite needs, extend it in its home
# rather than adding an exception here. An exception list that grows is this
# check failing at its job.
set -euo pipefail

# "<home file>|<regex>|<what to do instead>"
rules=(
  "crates/dpp-dal/src/test_harness.rs|^async fn start_pg|use dpp_dal::test_harness::{start_pg, start_pg_raw, start_pg_before}"
  "crates/dpp-dal/src/in_memory_repo.rs|^impl PassportRepository for InMemoryPassportRepo|use dpp_dal::in_memory_repo::InMemoryPassportRepo"
)

status=0
for rule in "${rules[@]}"; do
    home="${rule%%|*}"
    rest="${rule#*|}"
    pattern="${rest%%|*}"
    remedy="${rest#*|}"

    # One recursive grep, not a per-file loop: a loop over several hundred files
    # stalls for a minute on Windows, which is how a gate stops being run.
    hits=$(grep -rlE "$pattern" --include="*.rs" crates cli 2>/dev/null | grep -v "^${home}$" || true)

    if [ -n "$hits" ]; then
        echo "ERROR: '$pattern' is defined outside $home:"
        while IFS= read -r hit; do
            echo "  $hit"
        done <<< "$hits"
        echo "  Use instead: $remedy"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    echo
    echo "Shared test scaffolding has one home. Extend it there rather than forking a copy."
    exit 1
fi

echo "harness-check: no forked copies of shared test scaffolding."
