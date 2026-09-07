#!/usr/bin/env bash
# Create (and by default publish) every demo passport in this directory against a
# local node. Requires an admin- or write-scoped API key in $ODAL_API_KEY.
#
#   ODAL_API_KEY=odal_sk_... ./load.sh            # create + publish
#   ODAL_API_KEY=odal_sk_... ./load.sh --draft    # create only, leave as Draft
#
# Override the target with ODAL_VAULT_URL (default http://localhost:8001/vault).
set -euo pipefail

VAULT_URL="${ODAL_VAULT_URL:-http://localhost:8001/vault}"
PUBLISH=1
[ "${1:-}" = "--draft" ] && PUBLISH=0

if [ -z "${ODAL_API_KEY:-}" ]; then
  echo "ODAL_API_KEY is not set — mint a write/admin key first (see README.md)." >&2
  exit 1
fi

cd "$(dirname "$0")"
shopt -s nullglob
fail=0

for f in [0-9]*-battery-*.json; do
  body=$(curl -sS -X POST "$VAULT_URL/api/v1/dpp" \
    -H "authorization: Bearer $ODAL_API_KEY" \
    -H 'content-type: application/json' \
    --data-binary "@$f")
  id=$(printf '%s' "$body" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

  if [ -z "$id" ]; then
    printf '  %-38s CREATE FAILED: %s\n' "$f" "$(printf '%s' "$body" | cut -c1-300)"
    fail=1
    continue
  fi

  if [ "$PUBLISH" -eq 1 ]; then
    code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
      "$VAULT_URL/api/v1/dpp/$id/publish" \
      -H "authorization: Bearer $ODAL_API_KEY")
    if [ "$code" = "200" ]; then
      printf '  %-38s published  %s\n' "$f" "$id"
    else
      printf '  %-38s PUBLISH FAILED (HTTP %s)  %s\n' "$f" "$code" "$id"
      fail=1
    fi
  else
    printf '  %-38s draft      %s\n' "$f" "$id"
  fi
done

exit $fail
