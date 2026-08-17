#!/usr/bin/env bash
# Forbid println!/eprintln!/dbg! in service-crate src (use tracing:: instead).
set -euo pipefail
if grep -rn --include="*.rs" \
     -e '\bprintln!' -e '\beprintln!' -e '\bdbg!' \
     --exclude-dir=tests --exclude-dir=benches \
     crates/*/src; then
    echo "ERROR: println!/eprintln!/dbg! in service crate src — use tracing:: instead"
    exit 1
fi
