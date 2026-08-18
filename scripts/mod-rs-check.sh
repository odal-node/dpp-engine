#!/usr/bin/env bash
# Forbid public type/fn/const definitions in mod.rs — index files should be
# `mod`/`pub use` only, which is the re-layout's whole point. Two allocation-plan
# exceptions are named and excluded: service/mod.rs (PassportService + its
# builders) and validate/mod.rs (dispatch fn + its error type).
set -euo pipefail
exceptions="crates/dpp-vault/src/domain/service/mod.rs crates/dpp-integrator/src/domain/validate/mod.rs"
violations=""
for f in $(find crates/*/src cli/src -name mod.rs); do
    skip=false
    for e in $exceptions; do
        [ "$f" = "$e" ] && skip=true
    done
    [ "$skip" = true ] && continue
    if grep -nE '^[[:space:]]*pub[[:space:]]+(struct|enum|trait|fn|const|static|type)\b' "$f" > /dev/null; then
        violations="$violations $f"
    fi
done
if [ -n "$violations" ]; then
    echo "ERROR: mod.rs defines public items (should be a pure index) in:$violations"
    exit 1
fi
