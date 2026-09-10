#!/usr/bin/env bash
# Validate .coderabbit.yaml against CodeRabbit's published configuration schema.
#
# This config is read by a service, not by this build. A key CodeRabbit does not
# recognise is not a build failure here — it is a setting that silently does
# nothing on every pull request from then on, and the symptom of a review
# setting that does nothing looks exactly like a quiet week. That failure mode
# has already been seen from the other direction: `auto_review.enabled: false`
# turned out to skip `pre_merge_checks` with it and pass the CodeRabbit status
# vacuously, which was caught only by reading the live check output.
#
# The schema is fetched fresh on every run rather than vendored. A pinned local
# copy of someone else's evolving document goes stale silently, and drift is the
# one thing a stale copy cannot show. (There was such a copy, at the parent
# directory of this checkout, unread since the day it was downloaded.) The
# validator IS pinned, for the same reason REDOCLY_VERSION is pinned in the
# justfile: with `@latest`, a file that did not change starts failing the day
# ajv publishes.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT. The schema sets
# `additionalProperties: false` at the top level only. So a top-level typo
# (`reviewz:`) is rejected, and a nested one (`reviews.auto_reviews:`) is
# accepted in silence — nested key SPELLING is not checked at all. Values are
# checked everywhere: enums, types and shapes, at every depth. Read a pass as
# "every value I wrote is a value CodeRabbit accepts", never as "every key I
# wrote is a key CodeRabbit reads". coderabbit-check.test.sh pins both halves of
# that boundary, so it will start failing if CodeRabbit ever closes the schema.
set -euo pipefail

# ajv 5.0.0 is the current ajv-cli major. `--spec=draft2020` is required: the
# schema declares draft 2020-12 and ajv's default export only speaks draft-07.
# `--strict=false` is required too — the schema carries `enumNames`, which is
# not a standard keyword and which ajv's strict mode refuses to compile. No
# `ajv-formats`: the schema asserts no `format` anywhere, so it would be a
# pinned dependency that never runs.
AJV_CLI_VERSION="5.0.0"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="${1:-$root/.coderabbit.yaml}"

if [ ! -f "$config" ]; then
    echo "ERROR: no such config file: $config" >&2
    exit 1
fi

# The schema URL has exactly one home: the `# yaml-language-server:` header at
# the top of the config, which is what the editor already validates against.
# Restating the URL here would be a second home for it, and the two would
# disagree the first time CodeRabbit moves the file — with the editor and this
# gate then checking different documents, which is worse than not checking.
# Reading it from the config also makes that header load-bearing rather than
# decorative: delete it and this gate fails loudly instead of skipping.
schema_url="$(sed -n '/^# yaml-language-server:/{s|.*\$schema=||;s|[[:space:]].*||;p;q;}' "$config")"

if [ -z "$schema_url" ]; then
    cat >&2 <<EOF
ERROR: $config has no schema header, so there is nothing to validate against.

The first line should be:

  # yaml-language-server: \$schema=https://storage.googleapis.com/coderabbit_public_assets/schema.v2.json

That one line is what both your editor and this gate read. Restore it rather
than hardcoding the URL in scripts/coderabbit-check.sh.
EOF
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! curl -sSf -o "$tmp/schema.json" "$schema_url"; then
    cat >&2 <<EOF

ERROR: could not fetch the CodeRabbit schema from
  $schema_url

This gate is deliberately online — it exists to catch drift against the
published schema, which a vendored copy cannot do. Nothing else in 'just check'
needs the network, which is why this is not in it. Re-run when connected.
EOF
    exit 1
fi

if ! npx --yes -p "ajv-cli@$AJV_CLI_VERSION" \
        ajv validate --spec=draft2020 --strict=false \
        -s "$tmp/schema.json" -d "$config"; then
    cat >&2 <<EOF

ERROR: $(basename "$config") does not validate against CodeRabbit's schema.

Read 'instancePath' above as the path to the offending key. An 'enum' error
means the value is not one CodeRabbit accepts; 'additionalProperties' means a
top-level key it does not know. Both mean the setting would be ignored or the
whole file rejected on the next pull request.

The schema is the authority, not the docs: fix the file to match it. If a key
you need is genuinely absent from the schema, CodeRabbit has not shipped it —
do not leave it in the file expecting it to start working.
EOF
    exit 1
fi

echo "coderabbit-check: $(basename "$config") validates against $schema_url"
