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
# # What it cannot see
#
# The number in the XML is fixture setup *plus* the test body. For a test that
# boots its own container, container startup is most of it, and that is not
# something the test controls — it is scheduling on a shared runner. Such a test
# does not fail this budget consistently; it fails it when the runner is busy,
# with a different set of tests over the line each time. That is why the
# allowlist below exists and why every entry has to say *why* the time is not
# the test's own.
#
# Usage: bash scripts/slow-test-check.sh <budget-seconds> <junit.xml...>
set -euo pipefail

budget="${1:?usage: slow-test-check.sh <budget-seconds> <junit.xml...>}"
shift

if [ "$#" -eq 0 ]; then
    echo "slow-test-check: no JUnit files given" >&2
    exit 1
fi

# Slow by design. Each entry is "suite::test|reason". "It got slow" is not a
# reason — fix the test. Kept here rather than inferred so growth is a reviewed
# decision.
#
# Matched on the full `suite::test` id, not the bare test name: two suites may
# name a test the same thing, and a bare name would exempt both.
#
# Every entry today is a test that boots its own container. The comment that
# used to sit here said the list was empty because "every test that starts its
# own container still lands under the budget on a Linux runner". That stopped
# being true — these came in between 0.2s and 2.0s over, in a different
# combination on each run, while the same commit passed on its sibling run.
allowlist=(
    "dpp-node::nats_event_bus::connect_creates_dpp_events_stream|boots a NATS container and waits for JetStream; the four tests in this suite cannot share one server because NatsEventBus::connect hard-codes the DPP_EVENTS stream over dpp.>, so they would consume each other's messages"
    "dpp-node::nats_event_bus::publish_event_is_persisted_in_jetstream|as above — boots its own NATS container"
    "dpp-node::nats_event_bus::multiple_event_types_route_to_correct_subjects|as above — boots its own NATS container"
    "dpp-node::nats_event_bus::event_envelope_uses_camel_case_on_wire|as above — boots its own NATS container"
    "dpp-node::registry_outbox::migration_0024_restores_registrations_lost_before_the_fix|start_pg_before boots a server the migration has not been applied to, which is the point of the test and cannot use the shared template"
)

violations=""
exemptions=""
seen_ids=""
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

        id="${class}::${name}"
        # Recorded for every test, not only the slow ones: an allowlist entry is
        # stale when its test no longer *exists*, which is a different fact from
        # its test being fast on this run. These tests sit within a second of the
        # budget, so they are routinely under it — warning on that would fire
        # most runs and teach everyone to ignore the warning.
        seen_ids="${seen_ids}${id}
"

        # Integer compare on whole seconds: the budget is a round number and
        # bash cannot compare decimals without a subprocess per test.
        whole=${secs%%.*}
        [ -z "$whole" ] && whole=0
        [ "$whole" -lt "$budget" ] && continue

        skip=false
        for entry in ${allowlist[@]+"${allowlist[@]}"}; do
            if [ "$id" = "${entry%%|*}" ]; then
                skip=true
                exemptions="$exemptions
  ${secs}s  ${id}
          ${entry#*|}"
                break
            fi
        done
        [ "$skip" = true ] && continue

        violations="$violations
  ${secs}s  ${id}"
    done < <(grep -oE '<testcase [^>]*/?>' "$file")
done

# An exemption is a hole in the budget, so it is printed rather than applied
# silently — the log should show what was let through and on what grounds.
if [ -n "$exemptions" ]; then
    echo "slow-test-check: allowed over the ${budget}s budget:"
    printf '%s\n\n' "$exemptions"
fi

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

# An entry naming a test that no longer exists protects nothing and reads as
# though it does. Renaming or deleting an allowlisted test should shrink this
# list, and neither does unless something says so.
for entry in ${allowlist[@]+"${allowlist[@]}"}; do
    allowed="${entry%%|*}"
    case "$seen_ids" in
        *"${allowed}"$'\n'*) ;;
        *) echo "::warning::slow-test-check: allowlist entry names a test that did not run — renamed or removed? ${allowed}" ;;
    esac
done

echo "slow-test-check: $checked tests, none over ${budget}s."
