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
#
# Scoped to `*.sql`, and that scope is load-bearing rather than tidiness. This
# used to watch all of `ops/pg/`, which put it in direct contradiction with
# `grants-check`: that gate *requires* `ops/pg/README.md` to be edited whenever
# a table gains a DELETE grant, and this one then refused the edit. Any change
# adding such a table could satisfy one gate or the other and never both.
#
# The README is not a migration. `sqlx::migrate!` checksums the `.sql` files it
# runs and nothing else, so editing prose beside them cannot stop a node
# booting — which is the only failure this exists to prevent. The README says so
# itself: the grant list lives there *because* a migration cannot be edited and
# that list must be.
set -euo pipefail
base="${MIGRATION_BASE:-origin/main}"
git fetch -q origin main 2>/dev/null || true
if ! git rev-parse --verify -q "$base" > /dev/null; then
    echo "migrations-check: $base not available — skipping (set MIGRATION_BASE to override)"
    exit 0
fi
changed=$(git diff --name-only "$base"...HEAD -- 'ops/pg/*.sql' || true)
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
