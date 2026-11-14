#!/usr/bin/env bash
# Self-test for scripts/release-tag-check.sh.
#
# Builds one repository with a main line and an unmerged branch, then asks the
# gate about tags on each. The refusals are the cases that matter: the gate runs
# only when a tag is pushed, so one that accepts everything would read green at
# the one moment it is needed.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/release-tag-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t

repo="$TMP/repo"
git init -q -b main "$repo"

# commit <message> <Cargo.toml contents>: commit on the current branch, print its id.
# Every commit changes `change`, so two in a row may state the same Cargo.toml.
commit() {
    printf '%s' "$2" > "$repo/Cargo.toml"
    printf '%s\n' "$1" > "$repo/change"
    git -C "$repo" add -A
    git -C "$repo" commit -qm "$1"
    git -C "$repo" rev-parse HEAD
}

workspace() {
    printf '[workspace]\nmembers = ["a"]\n\n[workspace.package]\nversion     = "%s"\nedition     = "2024"\n\n[workspace.dependencies]\nserde = { version = "9.9.9" }\n' "$1"
}

previous="$(commit "release 0.1.0" "$(workspace 0.1.0)")"
release="$(commit "release 0.2.0" "$(workspace 0.2.0)")"
later="$(commit "a fix after the release" "$(workspace 0.2.0)")"
other_table="$(commit "a [package] table first" "[package]
version = \"0.4.0\"

$(workspace 0.2.0)")"
no_version="$(commit "no workspace version" "$(printf '[workspace]\nmembers = ["a"]\n')")"
tip="$(commit "back to 0.2.0" "$(workspace 0.2.0)")"
git -C "$repo" update-ref refs/remotes/origin/main "$tip"

# Two unmerged branches: one at the release's version, so that "not on main" is
# refused on its own; and one like the tag of 2026-11-14, a feature branch that
# still states the previous version.
git -C "$repo" switch -q -c feature-at-release "$release"
unmerged="$(commit "unmerged work" "$(workspace 0.2.0)")"
git -C "$repo" switch -q -c feature-from-before "$previous"
stale_feature="$(commit "a feature branch from before the release" "$(workspace 0.1.0)")"

pass=0
fail=0

# run_case <name> <accept|reject> <tag> <commit> [main-ref]
run_case() {
    local name="$1" expect="$2" tag="$3" commit_id="$4" main_ref="${5:-origin/main}"
    local got
    if (cd "$repo" && env -i PATH="$PATH" RELEASE_TAG="$tag" RELEASE_COMMIT="$commit_id" \
        MAIN_REF="$main_ref" bash "$GATE" > /dev/null 2>&1); then
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

run_case "main's tip at its version" accept v0.2.0 "$tip"
run_case "a release commit main has moved past" accept v0.2.0 "$release"
run_case "a fix tagged after the release" accept v0.2.0 "$later"
run_case "a commit on a branch main never merged" reject v0.2.0 "$unmerged"
run_case "a feature branch that states the previous version" reject v0.2.0 "$stale_feature"
run_case "a tag ahead of the version the commit states" reject v0.3.0 "$tip"
run_case "a tag behind the version the commit states" reject v0.1.0 "$release"
run_case "a tag without its v" reject 0.2.0 "$tip"
run_case "the workspace version, not another table's" reject v0.4.0 "$other_table"
run_case "the workspace version, read past another table" accept v0.2.0 "$other_table"
run_case "a commit with no workspace version" reject v0.2.0 "$no_version"
run_case "a checkout without main" reject v0.2.0 "$tip" origin/absent
run_case "a commit the checkout does not hold" reject v0.2.0 0000000000000000000000000000000000000000

echo "release-tag-check.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
