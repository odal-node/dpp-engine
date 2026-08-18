#!/usr/bin/env bash
# Refuse a modification to a migration that already exists on the base branch.
#
# `sqlx::migrate!` checksums every migration file, so editing an applied one
# makes a node that has already run it refuse to boot — a hard failure with no
# in-product remedy. `just reset-db` exists because this has already happened
# once (0015, a comment-only change during a repo-wide formatting sweep).
#
# "Append-only" was written down as "never renumbered", which a comment sweep
# obeys while still breaking the checksum. This checks the property that
# actually matters.
set -euo pipefail
base="${MIGRATION_BASE:-origin/main}"
git fetch -q origin main 2>/dev/null || true
if ! git rev-parse --verify -q "$base" > /dev/null; then
    echo "migrations-check: $base not available — skipping (set MIGRATION_BASE to override)"
    exit 0
fi
changed=$(git diff --name-only "$base"...HEAD -- ops/pg/ || true)
violations=""
for f in $changed; do
    # Present on the base branch => it has (or may have) already been applied.
    if git cat-file -e "$base:$f" 2>/dev/null; then
        violations="$violations $f"
    fi
done
if [ -n "$violations" ]; then
    echo "ERROR: migrations are append-only — these already exist on $base:$violations"
    echo "       sqlx checksums each file, so editing one stops an already-migrated"
    echo "       node from booting. Add a new numbered migration instead."
    exit 1
fi
