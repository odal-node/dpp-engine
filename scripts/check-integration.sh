#!/usr/bin/env bash
# Compile the Docker-backed integration tests without running them.
#
# `just test` omits `--features integration-tests`, so those suites are never
# built locally — a stale import in one compiles fine here and fails in CI, which
# is exactly what happened when the credential types moved to `dpp-vc`. Running
# them needs Docker; *compiling* them does not, so the local gate can at least
# prove they still build.
set -euo pipefail
for c in dpp-dal dpp-vault dpp-plugin-host dpp-node; do
    cargo test --no-run --quiet -p "$c" --features integration-tests
done
