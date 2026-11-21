#!/usr/bin/env bash
# Record the tree id of the current working tree after a green `just check`.
#
# Uses a temporary index so the real index is left untouched — the author may
# have staged only part of the working tree, and we want to record the whole
# tree that `just check` verified. The pre-commit hook then compares the index
# tree with this record and refuses a commit if they differ.
#
# Stores the record under `git rev-parse --git-dir`, which keeps a separate
# record per worktree.
set -euo pipefail

GIT_PATH="$(git rev-parse --git-dir)"
TMP_INDEX="$(mktemp)"
trap 'rm -f "$TMP_INDEX"' EXIT

# Build a tree object from the working directory without touching the real index.
# Start with an empty index, then stage everything and write the tree.
GIT_INDEX_FILE="$TMP_INDEX" git read-tree --empty
GIT_INDEX_FILE="$TMP_INDEX" git add -A
TREE="$(GIT_INDEX_FILE="$TMP_INDEX" git write-tree)"

printf '%s\n' "$TREE" > "$GIT_PATH/checked-tree"
echo "Recorded checked tree: $TREE"
