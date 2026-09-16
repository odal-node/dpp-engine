#!/usr/bin/env bash
# Enforces the claim that suppresses RUSTSEC-2023-0071.
#
# The `rsa` crate carries the Marvin Attack advisory, for which no fix exists
# or is expected: it is a timing sidechannel in RSA **private key** operations,
# recovering a key by timing an attacker's decryption or signing queries. The
# entry in `.cargo/audit.toml` suppresses it on one ground — this workspace
# holds no RSA private key and performs no RSA private-key operation, so there
# is nothing to recover and no oracle to time.
#
# That is a claim about the code, and the audit register's own header says a
# prose claim rots silently without something re-checking it. Its `anchor`
# field can only grep for a symbol; it cannot see a private key arriving three
# crates away. This can.
#
# Two things are checked, matching how such a key could actually appear:
#
#   1. No workspace crate declares `rsa` as a **direct** dependency. Reaching
#      it only through `x509-verify` is what keeps the use verification-only;
#      a direct dependency is how a signing or decryption path starts.
#   2. No workspace source names an RSA private-key type or operation.
#
# If either fires, the suppression is void: delete the ignore entry in
# `.cargo/audit.toml` and deal with the advisory on its merits, or remove the
# private key. Do not widen this script to accommodate the new code.
#
# ── This gate proves it can fail, every time it runs ────────────────────────
#
# It shipped able to pass while finding exactly what it looks for. `grep` exits
# **2** on a path error and **1** on no match; `if grep …; then` reads both as
# "nothing found", and the `2>/dev/null` hid the reason. `crates/*/tests`
# expands only to directories that exist, so a layout where none did would have
# handed grep a literal `crates/*/tests`, and the whole second check would have
# gone green while printing its matches to stdout.
#
# That is the worst shape a gate can have, so the exit status is now read
# explicitly — 0 found, 1 clean, anything else the scan did not run — and
# `--self-test` plants what the scan looks for in a scratch tree and fails if it
# is not caught. The self-test runs first on every invocation: a gate that has
# not demonstrated it can fail has not demonstrated anything.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Every workspace path that can hold first-party Rust. `cli/tests` was missing
# and is the reason this list is now one thing rather than spelled out twice.
source_roots() {
    local root="$1"
    printf '%s\n' "$root"/crates/*/src "$root"/crates/*/tests "$root"/cli/src "$root"/cli/tests
}

# `RsaPrivateKey` is the type; the two `SigningKey`s are the private-key signing
# APIs in `rsa`'s padding modules. `DecryptingKey` covers the decryption side,
# which is where the Marvin Attack was first demonstrated.
readonly PRIVATE_KEY_PATTERNS=(
    -e 'RsaPrivateKey'
    -e 'rsa::pkcs1v15::SigningKey'
    -e 'rsa::pss::SigningKey'
    -e 'rsa::pkcs1v15::DecryptingKey'
    -e 'rsa::oaep'
)

# Run one grep and turn its three outcomes into a verdict.
#
# Returns 0 when nothing was found, 1 when something was, and exits the script
# when the scan could not run at all. That last case is the point: a scan that
# errored has told us nothing, and telling us nothing must not read as a pass.
scan() {
    local what="$1"; shift
    local existing=()
    local p
    for p in "$@"; do
        [ -e "$p" ] && existing+=("$p")
    done
    if [ ${#existing[@]} -eq 0 ]; then
        echo "ERROR: $what has no paths to scan — this gate cannot run." >&2
        exit 2
    fi

    local rc=0
    grep -rn "${GREP_ARGS[@]}" -- "${existing[@]}" || rc=$?
    case $rc in
        0) return 1 ;;
        1) return 0 ;;
        *) echo "ERROR: $what could not be scanned (grep exit $rc)." >&2; exit 2 ;;
    esac
}

check_tree() {
    local root="$1"
    local status=0

    # ── 1. `rsa` must stay transitive ───────────────────────────────────────
    # Matches a dependency line, not a word in a comment or a feature named
    # "rsa" inside another crate's feature list.
    # Four ways a manifest can declare a direct dependency, and all four count.
    # The first version of this matched only `rsa = …`, which is one of them:
    #
    #   rsa = "0.9"                              inline
    #   rsa.workspace = true                     inherited from the workspace
    #   [dependencies.rsa]                       table form, incl. [target.….dependencies.rsa]
    #   renamed = { package = "rsa", … }         renamed, where the key is not "rsa" at all
    #
    # A regex rather than `cargo metadata` deliberately: this gate runs inside
    # `just check` on every commit, and shelling out to a full workspace resolve
    # to answer a question about four literal spellings would cost seconds to
    # gain nothing the self-test cannot prove. Each spelling is planted in the
    # self-test below, so a form this misses is a failing gate rather than a
    # silent one.
    GREP_ARGS=(
        --include=Cargo.toml -E
        '^[[:space:]]*rsa[[:space:]]*[=.]|^[[:space:]]*\[[^]]*dependencies\.rsa\]|package[[:space:]]*=[[:space:]]*"rsa"'
    )
    if ! scan "the direct-dependency check" "$root/crates" "$root/cli" "$root/Cargo.toml"; then
        echo "ERROR: a workspace crate depends on \`rsa\` directly." >&2
        echo "       RUSTSEC-2023-0071 is suppressed in .cargo/audit.toml on the ground that" >&2
        echo "       this workspace performs no RSA private-key operation. A direct dependency" >&2
        echo "       is how one starts. Re-argue the suppression or drop the dependency." >&2
        status=1
    fi

    # ── 2. No RSA private-key material in our own source ────────────────────
    GREP_ARGS=(--include='*.rs' "${PRIVATE_KEY_PATTERNS[@]}")
    local roots=()
    while IFS= read -r p; do roots+=("$p"); done < <(source_roots "$root")
    if ! scan "the source check" "${roots[@]}"; then
        echo "ERROR: RSA private-key material or a private-key operation in workspace source." >&2
        echo "       This voids the RUSTSEC-2023-0071 suppression in .cargo/audit.toml, whose" >&2
        echo "       whole ground is that no such key or operation exists here." >&2
        status=1
    fi

    return $status
}

# Plant what the scan looks for and fail if it is not caught.
#
# Both checks, because they fail differently: the dependency check has a fixed
# path list and the source check has a globbed one, and it was the globbed one
# that could silently stop running.
self_test() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    mkdir -p "$tmp/crates/planted/src" "$tmp/crates/planted/tests" "$tmp/cli/src" "$tmp/cli/tests"
    printf '[package]\nname = "planted"\n' > "$tmp/crates/planted/Cargo.toml"
    printf '[workspace]\n' > "$tmp/Cargo.toml"
    printf 'fn main() {}\n' > "$tmp/crates/planted/src/lib.rs"

    # One planted file per root that MUST be scanned.
    #
    # 🚨 This list is deliberately written out rather than taken from
    # `source_roots`, and that is the whole difference between a self-test and a
    # tautology. Derived from `source_roots`, dropping a root would stop the
    # scan looking there *and* stop the self-test planting there — the check
    # would pass, blind to precisely the regression it exists to catch. Written
    # out, it is the specification and `source_roots` is the implementation, and
    # a divergence fails here.
    #
    # Checked by dropping `cli/tests` from `source_roots`: derived, the gate
    # still passed; written out, it fails.
    #
    # Add a root here and in `source_roots`, in that order.
    local required_roots=(
        "crates/planted/src"
        "crates/planted/tests"
        "cli/src"
        "cli/tests"
    )
    local relative
    for relative in "${required_roots[@]}"; do
        printf 'use rsa::RsaPrivateKey;\n' > "$tmp/$relative/planted.rs"
        if check_tree "$tmp" > /dev/null 2>&1; then
            echo "SELF-TEST FAILED: a planted RsaPrivateKey in $relative was not caught." >&2
            echo "       That root is not reached by \`source_roots\`, so the gate does not" >&2
            echo "       look there. It cannot be trusted to fail, so it must not be trusted" >&2
            echo "       to pass." >&2
            return 1
        fi
        rm -f "$tmp/$relative/planted.rs"
    done

    # Every manifest location that must be scanned, crossed with every way a
    # direct dependency can be written.
    #
    # 🚨 Written out for the same reason the roots above are, and it is the same
    # trap: planting in one manifest and calling `check_tree` once proves only
    # that *some* path is scanned. Drop `cli` from the scan's path list and a
    # single-location self-test still passes, because `crates` caught it.
    local manifest_locations=(
        "Cargo.toml"
        "crates/planted/Cargo.toml"
        "cli/Cargo.toml"
    )
    local declarations=(
        'rsa = "0.9"'
        'rsa.workspace = true'
        '[dependencies.rsa]'
        'renamed = { package = "rsa", version = "0.9" }'
    )
    printf '[package]\nname = "planted-cli"\n' > "$tmp/cli/Cargo.toml"

    local location declaration original
    for location in "${manifest_locations[@]}"; do
        original="$(cat "$tmp/$location")"
        for declaration in "${declarations[@]}"; do
            printf '%s\n\n[dependencies]\n%s\n' "$original" "$declaration" > "$tmp/$location"
            if check_tree "$tmp" > /dev/null 2>&1; then
                echo "SELF-TEST FAILED: \`$declaration\` in $location was not caught." >&2
                echo "       Either that manifest is not scanned, or that spelling of a direct" >&2
                echo "       dependency is not matched. Both mean the gate can pass while the" >&2
                echo "       suppression it defends is void." >&2
                return 1
            fi
        done
        printf '%s\n' "$original" > "$tmp/$location"
    done

    return 0
}

if ! self_test; then
    exit 1
fi

if [[ "${1:-}" == "--self-test" ]]; then
    echo "no-rsa-private-key: self-test passed — the gate catches what it looks for."
    exit 0
fi

if check_tree "$REPO_ROOT"; then
    echo "no-rsa-private-key: rsa is transitive and verification-only."
    exit 0
fi
exit 1
