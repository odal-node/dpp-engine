#!/usr/bin/env bash
# Self-test for scripts/changelog-check.sh.
#
# Each case builds a repository with a released section and an [Unreleased] one,
# commits a pull request's change on top, and asserts what the gate says about it.
# The cases that matter most are the refusals: a gate that accepts everything
# reads green on every pull request and checks nothing.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/changelog-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t

pass=0
fail=0

BASE_CHANGELOG='# Changelog

## [Unreleased]

### Fixed

- **An older fix.** (#3)

## [0.1.0] - 2026-01-01

### Added

- **The first release.** (#1)
'

# run_case <name> <accept|reject> <changelog-after-or-"unchanged"> [env assignments...]
run_case() {
    local name="$1" expect="$2" after="$3"
    shift 3
    local repo="$TMP/$name"
    git init -q -b main "$repo"
    printf '%s' "$BASE_CHANGELOG" > "$repo/CHANGELOG.md"
    echo "code" > "$repo/lib.rs"
    git -C "$repo" add -A && git -C "$repo" commit -qm base
    local base
    base="$(git -C "$repo" rev-parse HEAD)"
    echo "changed" > "$repo/lib.rs"
    if [ "$after" != unchanged ]; then
        printf '%s' "$after" > "$repo/CHANGELOG.md"
    fi
    git -C "$repo" add -A && git -C "$repo" commit -qm change

    local got
    if (cd "$repo" && env -i PATH="$PATH" PR_NUMBER=12 BASE_SHA="$base" "$@" \
        bash "$GATE" > /dev/null 2>&1); then
        got=accept
    else
        got=reject
    fi
    if [ "$got" = "$expect" ]; then
        echo "ok:   $name ($expect)"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate said $got, expected $expect"
        fail=$((fail + 1))
    fi
}

with_entry() {
    printf '%s' "$BASE_CHANGELOG" | awk -v entry="$1" '
        { print }
        /^### Fixed/ && !done { print ""; print entry; done = 1 }'
}

run_case an_entry_citing_the_pull_request_is_accepted accept \
    "$(with_entry '- **A new fix.** (#12)')"
run_case an_entry_in_a_list_of_numbers_is_accepted accept \
    "$(with_entry '- **A new fix.** (#9, #12)')"
run_case an_entry_citing_the_issue_it_closes_is_accepted accept \
    "$(with_entry '- **A new fix.** (#40)')" PR_BODY="Some text.
Closes #40"
run_case no_changelog_change_is_refused reject unchanged
run_case an_entry_citing_another_number_is_refused reject \
    "$(with_entry '- **A new fix.** (#13)')"
run_case a_number_that_only_starts_with_it_is_refused reject \
    "$(with_entry '- **A new fix.** (#120)')"
run_case an_issue_the_body_only_mentions_is_refused reject \
    "$(with_entry '- **A new fix.** (#40)')" PR_BODY="Related to #40"
run_case a_closing_keyword_with_a_colon_is_accepted accept \
    "$(with_entry '- **A new fix.** (#40)')" PR_BODY="Closes: #40"
# The base section already cites #3. A change that closes #3 and writes an
# entry citing nothing must not borrow that citation.
run_case an_issue_another_entry_already_cites_is_refused reject \
    "$(with_entry '- **A new fix.**')" PR_BODY="Closes #3"
run_case an_entry_this_change_rewrites_may_cite_the_issue_it_closes accept \
    "$(printf '%s' "$BASE_CHANGELOG" | sed 's/An older fix\./An older fix, corrected./')" \
    PR_BODY="Closes #3"
run_case a_citation_added_to_an_existing_entry_is_accepted accept \
    "$(printf '%s' "$BASE_CHANGELOG" | sed 's/(#3)/(#3, #12)/')"
run_case a_citation_under_a_released_version_is_refused reject \
    "$(printf '%s' "$BASE_CHANGELOG" | sed 's/- \*\*The first release.\*\* (#1)/- **The first release.** (#1, #12)/')"
run_case no_changelog_with_a_reason_is_accepted accept unchanged \
    PR_LABELS="ci,no-changelog" PR_BODY="Pins an action.
No changelog: a CI pin, nothing an operator sees"
run_case no_changelog_without_a_reason_is_refused reject unchanged \
    PR_LABELS="no-changelog" PR_BODY="Pins an action."
run_case a_dependabot_pull_request_is_accepted accept unchanged \
    PR_AUTHOR="dependabot[bot]"
# A real [Unreleased] section runs to tens of kilobytes, more than a pipe holds.
# Piping it into `grep -q`, which exits at the first match, broke the writer's
# pipe, and under `pipefail` a found citation then read as a failure: the gate
# refused its own pull request. A section this long reproduces that.
run_case an_entry_atop_a_long_unreleased_section_is_accepted accept \
    "$(with_entry '- **A new fix.** (#12)' | awk '
        { print }
        /\(#12\)/ { for (i = 0; i < 4000; i++) print "  A long earlier entry, line " i, "of padding." }')"
# Each reason line is a match, so the extraction writes all of them. Taking the
# first with `head -1` closed the pipe on a writer with more to send, and under
# `pipefail` a valid reason then failed the gate.
run_case a_reason_repeated_on_many_lines_is_accepted accept unchanged \
    PR_LABELS="no-changelog" PR_BODY="$(for i in $(seq 1 2000); do echo "No changelog: a CI pin, line $i."; done)"
run_case a_reason_atop_a_long_body_is_accepted accept unchanged \
    PR_LABELS="no-changelog" PR_BODY="No changelog: a CI pin
$(for i in $(seq 1 4000); do echo "More of the body, line $i."; done)"
run_case a_missing_base_commit_is_refused reject \
    "$(with_entry '- **A new fix.** (#12)')" BASE_SHA=0000000000000000000000000000000000000000

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
