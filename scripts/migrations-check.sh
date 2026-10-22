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
# An explicit refspec, not `git fetch origin main`: in a clone that tracks one ref
# — which is what CI's checkout makes — the short form leaves the answer in
# FETCH_HEAD and never creates `origin/main`, so the check below finds no base.
git fetch -q origin "+refs/heads/main:refs/remotes/origin/main" 2>/dev/null || true
if ! git rev-parse --verify -q "$base" > /dev/null; then
    # Locally a missing base is a repository that has not fetched yet. In CI it is
    # a check that did not run, and a check that cannot run must not pass: it was
    # a green tick on every pull request that checked nothing.
    if [ -n "${CI:-}" ]; then
        echo "ERROR: migrations-check: $base is not available, so nothing was checked." >&2
        echo "       The CI checkout needs fetch-depth: 0 (or set MIGRATION_BASE)." >&2
        exit 1
    fi
    echo "migrations-check: $base not available — skipping (set MIGRATION_BASE to override)"
    exit 0
fi
# `...` needs a merge base, which a shallow clone does not have. That is an error
# to report, not a reason to find no changes.
if ! changed=$(git diff --name-only "$base"...HEAD -- 'ops/pg/*.sql'); then
    echo "ERROR: migrations-check: cannot diff against $base — no merge base? (a shallow clone has none)" >&2
    exit 1
fi
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
