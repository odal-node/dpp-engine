#!/usr/bin/env bash
# Forbid raw "dpp.passport."/"dpp.import." subject literals outside
# dpp-common::event — event_type/NATS-subject strings must come from the
# `subjects` constants, or a renamed subject silently stops matching subscribers.
#
# The service crates are listed explicitly rather than globbed, matching the CI
# job of the same name. A `crates/*/src` glob also covers crates that cannot
# comply: `dpp-types` is pure data and depends only on dpp-domain/dpp-rules, so
# reaching the constants would mean taking a dependency on dpp-common and
# inverting the layering. Globbing made this fail where CI passed, which is worse
# than not checking those crates — a local gate that cries wolf is one people
# stop running.
set -euo pipefail
if grep -rn --include="*.rs" \
     -e '"dpp\.passport\.' -e '"dpp\.import\.' \
     --exclude-dir=tests --exclude-dir=benches \
     --exclude=event.rs \
     crates/dpp-common/src \
     crates/dpp-dal/src \
     crates/dpp-vault/src \
     crates/dpp-identity/src \
     crates/dpp-resolver/src \
     crates/dpp-integrator/src \
     crates/dpp-plugin-host/src \
     crates/dpp-node/src; then
    echo "ERROR: raw dpp.passport./dpp.import. subject literal outside dpp-common::event — use the subjects:: constants"
    exit 1
fi
