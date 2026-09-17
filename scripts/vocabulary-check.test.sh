#!/usr/bin/env bash
# Self-test for scripts/vocabulary-check.sh.
#
# A gate nobody has watched fail is a gate nobody knows works — and this one is
# three independent greps, so a green run proves nothing about any single rule.
# Each case below reintroduces exactly one of the three collisions the rename
# removed and asserts the gate refuses it.
#
# The gate reads relative paths (`crates/`, `cli/`, `api/paths/`), so each case
# builds a synthetic tree in a temp directory and runs the gate from inside it.
# No network, no cargo.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/vocabulary-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# Build a tree that the gate must accept: the real shape, clause 4.2 included.
scaffold() {
    local root="$1"
    mkdir -p "$root/crates/dpp-vault/src" "$root/cli/src" "$root/api/paths/vault"
    cat > "$root/crates/dpp-vault/src/router.rs" <<'EOF'
        .route("/dpp/{dppId}/retire", post(retire_handler))
        .route("/dpp/{dppId}/versions", get(versions_handler))
EOF
    cat > "$root/crates/dpp-vault/src/event.rs" <<'EOF'
    pub const PASSPORT_RETIRED: &str = "dpp.passport.retired";
EOF
    # Clause 4.2's own vocabulary, which must NOT trip the gate.
    cat > "$root/crates/dpp-vault/src/archiving_repo.rs" <<'EOF'
/// Archives every version. EN 18221 clause 4.2.
pub struct ArchivingPassportRepo;
EOF
    touch "$root/api/paths/vault/vault_api_v1_dpp_{dppId}_retire.yaml"
    touch "$root/api/paths/vault/vault_api_v1_dpp_{dppId}_versions.yaml"
}

run_case() {
    local name="$1" expect="$2" mutate="$3"
    local root="$TMP/$name"
    scaffold "$root"
    ( cd "$root" && eval "$mutate" )
    if ( cd "$root" && bash "$GATE" >/dev/null 2>&1 ); then
        got="accept"
    else
        got="reject"
    fi
    if [ "$got" = "$expect" ]; then
        echo "ok:   $name ($got)"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate said $got, expected $expect"
        fail=$((fail + 1))
    fi
}

# The clean tree, including clause 4.2's archiving repo, is accepted. Without
# this case the other three would pass against a gate that rejects everything.
run_case "a_clean_tree_is_accepted" accept "true"

# 1. A lifecycle route takes the word back.
run_case "a_route_path_naming_archive_is_refused" reject \
    'printf %s\\n "        .route(\"/dpp/{dppId}/archive\", post(h))" >> crates/dpp-vault/src/router.rs'

# 2. The route is renamed but its OpenAPI file keeps the old name, which is what
#    every generated client and the rendered description would still say.
run_case "a_stale_openapi_path_file_is_refused" reject \
    'touch "api/paths/vault/vault_api_v1_dpp_{dppId}_archive.yaml"'

# 3. An event subject takes the word back — breaking for subscribers, and
#    invisible until one stops matching.
run_case "an_event_subject_naming_archived_is_refused" reject \
    'printf %s\\n "    pub const P: \&str = \"dpp.passport.archived\";" >> crates/dpp-vault/src/event.rs'

# 4. The CLI is in scope too — the gate reads `cli/` as well as `crates/`.
run_case "a_route_in_the_cli_tree_is_refused" reject \
    'mkdir -p cli/src && printf %s\\n "        .route(\"/archive\", post(h))" > cli/src/r.rs'

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
