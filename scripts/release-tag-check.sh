#!/usr/bin/env bash
# A release tag publishes, so refuse one that is not a release of main.
#
# Pushing a `v*` tag runs release.yml, which builds both images from the tagged
# commit and pushes them as `X.Y.Z`, `X.Y` and `latest`. There is no dry run. On
# 2026-11-14 the 0.16.0 tag was made with `git tag -a v0.16.0` in a checkout
# whose HEAD was an unmerged feature branch, so it named that branch's commit:
# code that was not on main, with 0.15.0 still in its Cargo.toml. The publish
# was building it as 0.16.0 and `latest` when it was cancelled by hand. Nothing
# in the workflow asked whether the commit was the release.
#
# A tag passes when both hold:
#
#   - its commit is on main: main itself, or an ancestor of it. A hotfix is
#     merged to main before it is tagged (docs/governance/RELEASE.md), so this
#     holds for every release the process describes;
#   - it is `v` followed by the commit's own `[workspace.package] version`. The
#     version has one home, Cargo.toml, and a tag that disagrees with it names a
#     release the code does not say it is.
#
# Inputs: RELEASE_TAG (the tag's name, e.g. v0.16.0), RELEASE_COMMIT (the commit
# it points at) and MAIN_REF (default origin/main). Run from the root of a
# checkout with full history. A shallow one has no main to compare with, and the
# check then fails rather than passing unchecked.
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG is the tag being released, e.g. v0.16.0}"
: "${RELEASE_COMMIT:?RELEASE_COMMIT is the commit the tag points at}"
main_ref="${MAIN_REF:-origin/main}"

fail() {
    printf '::error::%s\n' "$1" >&2
    shift
    for line in "$@"; do printf '%s\n' "$line" >&2; done
    exit 1
}

case "$RELEASE_TAG" in
    v?*) ;;
    *) fail "the tag '$RELEASE_TAG' does not start with 'v'." \
        "A release is tagged v<version>, with the version Cargo.toml states." ;;
esac
tag_version="${RELEASE_TAG#v}"

git rev-parse --verify --quiet "$main_ref^{commit}" > /dev/null \
    || fail "$main_ref is not in this checkout, so the tag cannot be checked against it." \
        "The workflow must fetch main (actions/checkout with fetch-depth: 0)."
git rev-parse --verify --quiet "$RELEASE_COMMIT^{commit}" > /dev/null \
    || fail "the tagged commit $RELEASE_COMMIT is not in this checkout."

if ! git merge-base --is-ancestor "$RELEASE_COMMIT" "$main_ref"; then
    fail "$RELEASE_TAG points at $RELEASE_COMMIT, which is not on main." \
        "A release is tagged on its release pull request's merge commit, named by hash:" \
        "  git tag -a $RELEASE_TAG <merge-commit-sha> -m \"$RELEASE_TAG\"" \
        "Delete this tag (git push origin :refs/tags/$RELEASE_TAG), then tag that commit."
fi

cargo_toml="$(git show "$RELEASE_COMMIT:Cargo.toml" 2> /dev/null)" \
    || fail "the tagged commit $RELEASE_COMMIT has no Cargo.toml."
# The version under [workspace.package] only: a `version` key in another table
# (a dependency, a [package]) is not the release's.
cargo_version="$(awk '
    /^\[/ { in_pkg = ($0 == "[workspace.package]"); next }
    in_pkg && !found && /^version[[:space:]]*=/ {
        sub(/^version[[:space:]]*=[[:space:]]*"/, "")
        sub(/".*$/, "")
        print
        found = 1
    }' <<< "$cargo_toml")"
[ -n "$cargo_version" ] \
    || fail "the tagged commit's Cargo.toml states no [workspace.package] version."

if [ "$tag_version" != "$cargo_version" ]; then
    fail "$RELEASE_TAG does not match the version its commit's Cargo.toml states, $cargo_version." \
        "Tag the release pull request's merge commit: that pull request moves the version."
fi

echo "release-tag-check: $RELEASE_TAG is $RELEASE_COMMIT, on $main_ref, and Cargo.toml states $cargo_version."
