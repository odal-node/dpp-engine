#!/usr/bin/env bash
# Every pull request records itself in CHANGELOG.md, or says why it does not.
#
# The changelog was prose with no link to the change behind each entry: of the
# 81 pull requests merged between 0.14.0 and 0.15.0 that Dependabot did not open,
# two were cited by number. Nothing could show that every merged change was
# described, or that every entry described a change that merged, so verifying a
# release meant rebuilding that map by hand from the git log. This makes the link
# at the one moment it is cheap: when the change is made.
#
# A pull request passes when one of these holds:
#
#   - The `## [Unreleased]` section of CHANGELOG.md cites it, and CHANGELOG.md is
#     part of the pull request. It is cited by its own number, or by the number
#     of an issue its body says it closes ("Closes #123"), since that one is known
#     before the pull request exists.
#   - It carries the `no-changelog` label, and its body has a line
#     `No changelog: <reason>`: a test-only change, a CI pin, a typo. The label
#     alone is not a reason.
#   - Dependabot opened it. A dependency bump is checked in the release's
#     verification record (docs/governance/RELEASE.md), not entry by entry.
#
# Inputs, from the pull_request event (.github/workflows/changelog.yml): PR_NUMBER,
# PR_AUTHOR, PR_LABELS (comma-separated), PR_BODY and BASE_SHA. Run from the root
# of the checkout CI makes, the pull request merged into its base, which has no
# `origin/main` to compare with: the base is named by its commit instead.
set -euo pipefail

: "${PR_NUMBER:?PR_NUMBER is the pull request number}"
: "${BASE_SHA:?BASE_SHA is the commit the pull request merges into}"
author="${PR_AUTHOR:-}"
labels=",${PR_LABELS:-},"
body="${PR_BODY:-}"

fail() {
    printf '::error::%s\n' "$1" >&2
    shift
    for line in "$@"; do printf '%s\n' "$line" >&2; done
    exit 1
}

if [ "$author" = "dependabot[bot]" ]; then
    echo "changelog-check: opened by Dependabot; the release's verification record checks the bump."
    exit 0
fi

if [[ "$labels" == *",no-changelog,"* ]]; then
    reason="$(printf '%s\n' "$body" \
        | sed -nE 's/^[[:space:]]*No changelog:[[:space:]]*(.*[^[:space:]])[[:space:]]*$/\1/p' \
        | head -1)"
    [ -n "$reason" ] || fail "no-changelog is set, but the body gives no reason." \
        "Add a line to the pull request body:  No changelog: <why this change needs no entry>"
    echo "changelog-check: no entry, because: $reason"
    exit 0
fi

git cat-file -e "$BASE_SHA^{commit}" 2> /dev/null \
    || fail "the base commit $BASE_SHA is not in this checkout." \
        "The workflow must fetch it (actions/checkout with fetch-depth: 0)."

if git diff --quiet "$BASE_SHA" HEAD -- CHANGELOG.md; then
    fail "CHANGELOG.md is not part of this pull request." \
        "Add an entry under '## [Unreleased]' that ends with (#$PR_NUMBER), or with the" \
        "issue this pull request closes. If the change needs no entry, add the" \
        "no-changelog label and a 'No changelog: <reason>' line to the body."
fi

numbers="$PR_NUMBER"
for issue in $(printf '%s\n' "$body" \
    | grep -oiE '(close[sd]?|fix(e[sd])?|resolve[sd]?)[[:space:]]+#[0-9]+' \
    | grep -oE '[0-9]+' || true); do
    numbers="$numbers $issue"
done

unreleased="$(awk '/^## \[Unreleased\]/ { on = 1; next } /^## \[/ { on = 0 } on' CHANGELOG.md)"
for n in $numbers; do
    if printf '%s\n' "$unreleased" | grep -qE "#$n([^0-9]|$)"; then
        echo "changelog-check: [Unreleased] cites #$n."
        exit 0
    fi
done

fail "CHANGELOG.md changed, but its [Unreleased] section cites none of: #${numbers// /, #}." \
    "End the entry with (#$PR_NUMBER), or with an issue the body closes ('Closes #123')." \
    "An entry under a released version does not count: this change is not in it."
