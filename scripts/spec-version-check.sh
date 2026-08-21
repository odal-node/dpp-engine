#!/usr/bin/env bash
# Asserts that the OpenAPI description's `info.version` matches the workspace
# crate version.
#
# The spec used to be an internal file where a stale version cost nothing. It is
# not any more: `api/openapi.bundled.yaml` is a committed artifact, the
# documentation site vendors it, and the SDK version policy makes the spec's
# MAJOR.MINOR the API contract a generated client targets. A client pinned to
# "0.1.0" against an 0.12.0 engine is pinned to a number that never meant
# anything.
#
# Kept mechanical rather than written into the release checklist, for the same
# reason the OpenAPI lint was wired into CI: a step that only runs when someone
# remembers it does not run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spec="$root/api/openapi.yaml"
manifest="$root/Cargo.toml"

# `version` under [workspace.package] — the first bare `version =` in the file.
crate_version="$(
    awk -F'"' '/^version[[:space:]]*=/ { print $2; exit }' "$manifest"
)"

# `version:` nested under the top-level `info:` block.
spec_version="$(
    awk '
        /^info:/        { in_info = 1; next }
        /^[a-zA-Z]/     { in_info = 0 }
        in_info && $1 == "version:" { gsub(/"/, "", $2); print $2; exit }
    ' "$spec"
)"

if [ -z "$crate_version" ]; then
    echo "ERROR: could not read the workspace version from Cargo.toml" >&2
    exit 1
fi
if [ -z "$spec_version" ]; then
    echo "ERROR: could not read info.version from api/openapi.yaml" >&2
    exit 1
fi

if [ "$crate_version" != "$spec_version" ]; then
    cat >&2 <<EOF
ERROR: the API description's version does not match the workspace crate version.

  Cargo.toml [workspace.package] version : $crate_version
  api/openapi.yaml info.version          : $spec_version

Both move together on a release. Update info.version in api/openapi.yaml, then
run 'just openapi-bundle' so the committed bundle carries the same number.
EOF
    exit 1
fi

echo "spec-version-check: api/openapi.yaml and Cargo.toml agree on $crate_version."
