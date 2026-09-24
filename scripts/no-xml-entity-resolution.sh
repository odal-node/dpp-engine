#!/usr/bin/env bash
# Keep EU Trusted List XML on `roxmltree`'s default, DTD-refusing parse path.
#
# `crates/dpp-seal` parses trusted lists fetched over the network. Until
# roxmltree 0.21.0 that was safe as a property of the crate: it could not
# resolve entities at all, so there was nothing to argue about. 0.21.0 added
# `ParsingOptions::entity_resolver`, a hook that resolves **external** entities
# referenced by public ID and URI — which on a document arriving from the
# network is the definition of XXE. The parser would dereference a URI chosen
# by the document it is parsing.
#
# The code is safe today because of where it stops, not what it cannot do:
# every production call site uses `Document::parse`, which takes
# `ParsingOptions::default()` — `allow_dtd: false` and `entity_resolver: None`.
# Both have to be flipped to open the hole, and `allow_dtd` is the outer one:
# the tokenizer rejects a document carrying a DTD before any entity declaration
# is read, so the resolver is unreachable while it stays false.
#
# `Document::parse` is the only constructor that cannot reach the resolver, so
# "use `Document::parse`" and "never name `parse_with_options` or
# `ParsingOptions`" are the same rule. This enforces the second spelling,
# because it is the one grep can see.
#
# If this fires, the note in `crates/dpp-seal/Cargo.toml` is void. Do not add an
# exception here: make the argument for why this particular document may name
# its own URIs, and if it holds, rewrite that note first.
#
# Only `*.rs` is scanned. The Cargo.toml note names both symbols while
# explaining them, and a gate that cannot survive its own documentation is a
# gate someone deletes.
#
# ── This gate proves it can fail, every time it runs ────────────────────────
#
# `grep` exits 2 on a path error and 1 on no match, and `if grep …; then` reads
# both as "nothing found" — so a scan that never ran looks exactly like a clean
# one. The status is read explicitly here (0 found, 1 clean, anything else the
# scan did not run), and `--self-test` plants what the scan looks for and fails
# if it is not caught. The self-test runs first on every invocation, because a
# gate that has not shown it can fail has shown nothing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The crate that parses network-fetched XML. Scanned whole rather than just
# `src`: a test helper reaching for `parse_with_options` would put the call in
# the tree, and "it was only in a test" is how the first one always arrives.
readonly SCANNED_CRATE="crates/dpp-seal"

# The two names that open the door. `ParsingOptions` is listed as well as
# `parse_with_options` because a helper can build the options in one module and
# hand them to a call in another, and then no single line reads as the mistake.
readonly FORBIDDEN_PATTERNS=(
    -e 'parse_with_options'
    -e 'ParsingOptions'
)

# Returns 0 when nothing was found, 1 when something was, and exits the script
# when the scan could not run at all. That last case is the point: a scan that
# errored has told us nothing, and telling us nothing must not read as a pass.
check_tree() {
    local root="$1"
    local target="$root/$SCANNED_CRATE"

    if [ ! -d "$target" ]; then
        echo "ERROR: $SCANNED_CRATE does not exist — this gate cannot run." >&2
        echo "       It has not passed; it has failed to look. If the crate moved," >&2
        echo "       move SCANNED_CRATE with it." >&2
        exit 2
    fi

    local rc=0
    grep -rn --include='*.rs' "${FORBIDDEN_PATTERNS[@]}" -- "$target" || rc=$?
    case $rc in
        0) return 1 ;;
        1) return 0 ;;
        *) echo "ERROR: $SCANNED_CRATE could not be scanned (grep exit $rc)." >&2; exit 2 ;;
    esac
}

# Plant what the scan looks for and fail if it is not caught — and, just as
# importantly, plant what it must NOT flag. A gate that rejects the correct
# call is one somebody loosens until it rejects nothing.
self_test() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    local crate="$tmp/$SCANNED_CRATE"
    mkdir -p "$crate/src/trustlist" "$crate/tests"

    # A clean tree using the sanctioned call must pass, or every later
    # assertion below is satisfied by a gate that simply always fails.
    printf 'let doc = Document::parse(xml)?;\n' > "$crate/src/trustlist/parse.rs"
    if ! check_tree "$tmp" > /dev/null 2>&1; then
        echo "SELF-TEST FAILED: a clean tree using Document::parse was rejected." >&2
        echo "       The gate flags the very call it exists to require." >&2
        return 1
    fi

    # 🚨 Written out rather than derived from FORBIDDEN_PATTERNS, and that is
    # the difference between a self-test and a tautology: derived, dropping a
    # pattern would stop the scan looking for it *and* stop the self-test
    # planting it, and the gate would pass while blind to exactly the
    # regression it exists to catch. This list is the specification and
    # FORBIDDEN_PATTERNS is the implementation; a divergence fails here.
    #
    # Checked by deleting the `ParsingOptions` pattern: derived, the gate still
    # passed; written out, it fails.
    #
    # Each is planted in a different location, so this also proves the scan
    # recurses rather than reading one directory.
    local plant_at=(
        "src/trustlist/verify.rs|let doc = Document::parse_with_options(xml, opt)?;"
        "src/options.rs|fn opts() -> ParsingOptions<'static> { ParsingOptions::default() }"
        "tests/helper.rs|use roxmltree::ParsingOptions;"
    )
    local entry relative line
    for entry in "${plant_at[@]}"; do
        relative="${entry%%|*}"
        line="${entry#*|}"
        mkdir -p "$(dirname "$crate/$relative")"
        printf '%s\n' "$line" > "$crate/$relative"
        if check_tree "$tmp" > /dev/null 2>&1; then
            echo "SELF-TEST FAILED: \`$line\` in $relative was not caught." >&2
            echo "       Either that location is not scanned or that spelling is not" >&2
            echo "       matched. Both mean the gate can pass while external-entity" >&2
            echo "       resolution is live on network-fetched XML." >&2
            return 1
        fi
        rm -f "$crate/$relative"
    done

    # A missing crate must be loud, not vacuously green — the failure mode this
    # whole gate is shaped against. Asserted as exit 2 specifically, not merely
    # "non-zero": exit 1 is the verdict "scanned, and clean", and a rename that
    # started reporting that would be the silent pass, wearing a red hat.
    #
    # Run in a subshell because that path *exits* rather than returning, and an
    # `exit` here would end the self-test one assertion early — reported as a
    # pass, which is the same bug one level up.
    rm -rf "$crate"
    local rc=0
    ( check_tree "$tmp" ) > /dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "SELF-TEST FAILED: a missing $SCANNED_CRATE exited $rc, not 2." >&2
        echo "       A gate that cannot find what it guards must say so. Exit 0 or 1" >&2
        echo "       here means a rename silently retires this check." >&2
        return 1
    fi

    return 0
}

if ! self_test; then
    exit 1
fi

if [[ "${1:-}" == "--self-test" ]]; then
    echo "no-xml-entity-resolution: self-test passed — the gate catches what it looks for."
    exit 0
fi

if check_tree "$REPO_ROOT"; then
    echo "no-xml-entity-resolution: trusted list XML is parsed on roxmltree's DTD-refusing default."
    exit 0
fi
echo "ERROR: $SCANNED_CRATE names \`parse_with_options\` or \`ParsingOptions\`." >&2
echo "       Trusted lists are fetched over the network, and those are the two" >&2
echo "       names that can enable roxmltree's external-entity resolver — the" >&2
echo "       parser dereferencing a URI the parsed document chose. The note in" >&2
echo "       crates/dpp-seal/Cargo.toml rests on neither appearing here." >&2
exit 1
