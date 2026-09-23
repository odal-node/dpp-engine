# scripts/

The checks `just check` runs, and the few helpers the `justfile` calls. Each
script's header comment says what it enforces and why; `just --list` shows which
recipe runs it. A `*.test.sh` beside a script proves that gate actually fails —
a check that has never been seen red proves nothing.

These are repository tooling, not something an operator runs.

## Installing a node

There is no one-click installer. The one that lived here fetched a script, a
compose file and a CLI binary that are not published anywhere, and pulled images
that are not public, so it could not install anything; it was removed rather than
repaired. A replacement is tracked for before 1.0, once there is something
published for it to install: #397.

To run a node today, follow [docs/guides/OPERATOR-SETUP.md](../docs/guides/OPERATOR-SETUP.md):
build `odal` from this repository, then `odal init` and `odal up`.
