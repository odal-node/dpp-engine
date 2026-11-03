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
#   - An entry the pull request adds to, or rewrites in, the `## [Unreleased]`
#     section of CHANGELOG.md cites it. It is cited by its own number, or by the
#     number of an issue its body says it closes ("Closes #123", "Closes: #123"),
#     since that one is known before the pull request exists. A citation already
#     in the section does not count: another change wrote it.
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
    # `sed -n 1p`, not `head -1`: it reads every match before taking the first,
    # where `head` exits and breaks the pipe of a writer with more to send.
    reason="$(printf '%s\n' "$body" \
        | sed -nE 's/^[[:space:]]*No changelog:[[:space:]]*(.*[^[:space:]])[[:space:]]*$/\1/p' \
        | sed -n 1p)"
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
    | grep -oiE '(close[sd]?|fix(e[sd])?|resolve[sd]?):?[[:space:]]+#[0-9]+' \
    | grep -oE '[0-9]+' || true); do
    numbers="$numbers $issue"
done

# The [Unreleased] entries, one per line. An entry is a top-level `- ` item with
# everything under it, up to the next item or heading.
entries() {
    awk '/^## \[Unreleased\]/ { on = 1; next } /^## \[/ { on = 0 } on' \
        | awk '/^- / { if (e != "") print e; e = $0; next }
               /^#/ { if (e != "") print e; e = ""; next }
               e != "" { e = e " " $0 }
               END { if (e != "") print e }'
}

# Only an entry this pull request adds or rewrites counts. Reading the whole
# section let a citation another change wrote, of an issue this one also closes,
# pass a pull request that changed an unrelated line.
changed="$(LC_ALL=C comm -13 \
    <(git show "$BASE_SHA:CHANGELOG.md" | entries | LC_ALL=C sort) \
    <(entries < CHANGELOG.md | LC_ALL=C sort))"
for n in $numbers; do
    # A here-string, not a pipe: `grep -q` stops at the first match, and a writer
    # still feeding it a section larger than a pipe holds then fails, which under
    # `pipefail` turns a citation that was found into a refusal.
    if grep -qE "#$n([^0-9]|$)" <<< "$changed"; then
        echo "changelog-check: an [Unreleased] entry this change writes cites #$n."
        exit 0
    fi
done

fail "CHANGELOG.md changed, but no [Unreleased] entry it adds or rewrites cites any of: #${numbers// /, #}." \
    "End the entry with (#$PR_NUMBER), or with an issue the body closes ('Closes #123')." \
    "An entry under a released version does not count: this change is not in it."
