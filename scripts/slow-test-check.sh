#!/usr/bin/env bash
# Fail when a test exceeds the time budget.
#
# Reads the JUnit XML nextest already writes, so it measures what actually
# happened rather than re-running anything, and cannot itself be flaky.
#
# # Why this exists
#
# A resolver test drifted to **50 seconds** — a debug-build loop asserting a
# bound that holds at any size — and nothing objected. It was the slowest test
# in the workspace by roughly 500x and was found only by a deliberate hunt for
# where CI time went. `slow-timeout` in `.config/nextest.toml` prints SLOW for
# the same case, but a warning in a log nobody reads is not a budget.
#
# # Why it runs on CI and not locally
#
# The budget is calibrated against CI, where the slowest single test is ~5s.
# The same suite on a dev machine behind Docker Desktop reaches 17s for tests
# that take 3.8s on a Linux runner, because container startup there goes through
# a VM. Enforcing that locally would fail honest work on the wrong machine;
# locally `slow-timeout` warns and that is the right strength.
#
# Usage: bash scripts/slow-test-check.sh <budget-seconds> <junit.xml...>
set -euo pipefail

budget="${1:?usage: slow-test-check.sh <budget-seconds> <junit.xml...>}"
shift

if [ "$#" -eq 0 ]; then
    echo "slow-test-check: no JUnit files given" >&2
    exit 1
fi

# Slow by design. Each entry needs a reason; "it got slow" is not one — fix the
# test. Kept here rather than inferred so growth is a reviewed decision.
#
# (Empty today: every test that starts its own container still lands under the
# budget on a Linux runner. The list exists so the first real exception is
# argued for rather than absorbed by raising the number.)
allowlist=()

violations=""
checked=0

for file in "$@"; do
    [ -f "$file" ] || continue

    # One testcase per line as "<seconds> <suite>::<name>", from the attributes
    # nextest writes. `time` always follows `name` and `classname` in its output.
    while IFS= read -r line; do
        # Anchored: a greedy `.*name="` matches inside `classname="` instead,
        # which reported every test as its own suite name.
        name=$(expr "$line" : '<testcase name="\([^"]*\)"' || true)
        class=$(expr "$line" : '.*classname="\([^"]*\)"' || true)
        secs=$(expr "$line" : '.*time="\([0-9.]*\)"' || true)
        [ -z "$secs" ] && continue
        checked=$((checked + 1))

        # Integer compare on whole seconds: the budget is a round number and
        # bash cannot compare decimals without a subprocess per test.
        whole=${secs%%.*}
        [ -z "$whole" ] && whole=0
        [ "$whole" -lt "$budget" ] && continue

        skip=false
        for allowed in ${allowlist[@]+"${allowlist[@]}"}; do
            if [ "$name" = "$allowed" ]; then
                skip=true
                break
            fi
        done
        [ "$skip" = true ] && continue

        violations="$violations
  ${secs}s  ${class}::${name}"
    done < <(grep -oE '<testcase [^>]*/?>' "$file")
done

if [ -n "$violations" ]; then
    echo "ERROR: tests over the ${budget}s budget:"
    while IFS= read -r v; do
        [ -n "$v" ] && echo "$v"
    done <<< "$violations"
    echo
    echo "Make the test faster, or — if it is slow for a reason that survives"
    echo "review — add it to the allowlist in scripts/slow-test-check.sh with that"
    echo "reason. Raising the budget is not the fix."
    exit 1
fi

echo "slow-test-check: $checked tests, none over ${budget}s."
