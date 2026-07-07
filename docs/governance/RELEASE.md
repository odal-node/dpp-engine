# Release Process

This document describes how dpp-engine releases are prepared, validated,
and published.

## Distribution Model

dpp-engine is not published to crates.io. It is distributed as:

1. **Docker images** — the primary distribution for hosted and self-hosted deployments.
2. **Static binaries** — compiled release binaries attached to GitHub Releases.
3. **Source** — the repository itself (BSL-1.1 licensed).

## Release Cadence

There is no fixed schedule. Releases are cut when a meaningful set of changes
has accumulated and all checks pass. Security patches are published as soon
as the fix is verified.

## Pre-Release Checklist

Before tagging a release:

1. **All CI green** — `cargo fmt --all --check`, `cargo clippy --workspace`,
   `cargo test --workspace` pass locally.
2. **Integration tests pass** — `cargo test -p dpp-node --features integration-tests`
   with Docker running.
3. **CHANGELOG.md updated** — move items from `[Unreleased]` to a new version
   heading with today's date. Follow Keep a Changelog format.
4. **Migration files reviewed** — ensure any schema changes are included in
   `ops/pg/` and applied via `PgDal::migrate` or pre-applied by ops tooling.
5. **Bootstrap flow verified** — `odal bootstrap` provisions operator config +
   first API key cleanly against a fresh node.
6. **README accuracy** — verify the root README reflects the current API.
8. **Dependency review** — check for known vulnerabilities with `cargo audit`.
9. **dpp-core version pinned** — ensure the workspace uses a tagged release
   of dpp-core, not an unreleased commit.

## Release Command

```sh
# 1. Update version in root Cargo.toml
# 2. Update CHANGELOG.md

# 3. Commit the version bump
git add -A
git commit -m "chore: release v0.1.0"

# 4. Tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin main --tags

# 5. Build release binary
cargo build --release -p dpp-node

# 6. Create GitHub Release with binary and changelog
gh release create v0.1.0 \
  target/release/dpp-node \
  --title "v0.1.0" \
  --notes-file RELEASE_NOTES.md
```

## Docker Image

```sh
# Build context is the parent dir holding dpp-core/ + dpp-engine/.
docker build -t ghcr.io/odal-node/dpp-node:v0.1.0 -f dpp-engine/docker/node.Dockerfile .
docker push ghcr.io/odal-node/dpp-node:v0.1.0
docker build -t ghcr.io/odal-node/dpp-resolver:v0.1.0 -f dpp-engine/docker/resolver.Dockerfile .
docker push ghcr.io/odal-node/dpp-resolver:v0.1.0
```

## Post-Release

1. Verify the GitHub Release is published with the binary attached.
2. Verify the Docker image runs correctly against a fresh PostgreSQL instance.
3. Run the seed script against the released version to confirm compatibility.
4. Announce the release in project communication channels.

## Hotfix Process

For critical bugs in a released version:

1. Create a `fix/description` branch from the release tag.
2. Apply the fix with tests.
3. Merge to `main` via PR.
4. Tag a new patch version (e.g., `v0.1.1`).
5. Rebuild and publish Docker image and binary.

## Wasm Plugins

Sector plugins are distributed as `.wasm` files attached to GitHub Releases.
Their versions track independently from the platform version.

## References

- [Versioning Policy](VERSIONING.md)
- [Contributing Guide](../../CONTRIBUTING.md)
- [Changelog](../../CHANGELOG.md)
