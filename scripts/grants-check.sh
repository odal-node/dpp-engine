#!/usr/bin/env bash
# Every table with a live DELETE grant must be named in ops/pg/README.md.
#
# "The app role cannot DELETE" is the sentence a reader uses to reason about
# whether an application-level compromise can destroy evidence, and it drifted:
# CLAUDE.md and .env.example both said "one sanctioned exception" while three
# tables carried the grant. Both now point at the README; this keeps it true.
#
# The list lives in the README rather than in migration 0010 because a migration
# cannot be edited once applied (see migrations-check.sh) and this list must be.
set -euo pipefail
granted=$(grep -hoE 'GRANT [A-Z, ]*DELETE[A-Z, ]* ON ([a-z_]+\.[a-z_]+)' ops/pg/*.sql \
            | grep -oE '[a-z_]+\.[a-z_]+$' | sort -u)
# Granted and later revoked (retire-not-delete) — not part of the live set.
revoked=$(grep -hoE 'REVOKE DELETE ON ([a-z_]+\.[a-z_]+)' ops/pg/*.sql \
            | grep -oE '[a-z_]+\.[a-z_]+$' | sort -u)
live=$(comm -23 <(echo "$granted") <(echo "$revoked"))
documented=$(sed -n '/^## The DELETE set/,/^## /p' ops/pg/README.md \
               | grep -oE '^odal\.[a-z_]+' | sort -u)
if ! diff <(echo "$live") <(echo "$documented") > /dev/null; then
    echo "ERROR: the live DELETE grants and ops/pg/README.md disagree."
    echo "  granted and not revoked:"; echo "$live" | sed 's/^/    /'
    echo "  documented in README:";    echo "$documented" | sed 's/^/    /'
    echo "  Add the table to the DELETE set in ops/pg/README.md, with why."
    exit 1
fi
