# Release Process

This document describes how dpp-engine releases are prepared, validated,
and published.

## Distribution Model

dpp-engine is not published to crates.io. It is distributed as:

1. **Docker images** — `ghcr.io/odal-node/dpp-node` and `…/dpp-resolver`,
   built and pushed by `.github/workflows/release.yml` when a `v*` tag is
   pushed. A tag `vX.Y.Z` publishes the image tags **`X.Y.Z`**, **`X.Y`** and
   **`latest`** — no `v` prefix on the image tags.
2. **Source** — the repository itself (BSL-1.1 licensed).

**No release binary and no GitHub Release are produced.** Nothing builds a
standalone Linux binary outside the images, and one built on a developer
machine would be for that machine's target. Until a workflow produces one, the
images are the distribution.

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
6. **README accuracy** — verify the root README reflects the current API:
   the crate map against `crates/`, the dpp-core table against
   `[workspace.dependencies]`, and the resolver route table against
   `dpp-resolver/src/router.rs`. All four drifted before 0.13.0.
7. **CHANGELOG sections reconciled** — sweep `[Unreleased]` for breaking-change
   language outside `### Breaking`. A removed route or renamed field described
   under *Added*, *Changed* or *Fixed* is a break nobody will migrate for.
8. **Dependency review** — check for known vulnerabilities with `cargo audit`.
9. **dpp-core version pinned** — ensure the workspace uses a tagged release
   of dpp-core, not an unreleased commit.

## Release Command

The version lives in **four** places, and they move in one pull request:

1. `Cargo.toml` `[workspace.package] version`;
2. `api/openapi.yaml` `info.version` — `spec-version-check.sh` compares it with (1);
3. `api/openapi.bundled.yaml` and `.json` — regenerate with `just openapi-bundle`;
   `openapi-check` fails if they drift;
4. `Cargo.lock` — rebuild once after the bump and commit it. Nothing builds
   with `--locked` outside the images, so a stale lock goes unnoticed until the
   release images refuse it.

Rename `[Unreleased]` to `[X.Y.Z] - <date>` in the same pull request. Merge it,
wait for CI on the merge commit — including both **Container image** checks —
then tag that commit:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

🚨 **Pushing the tag publishes.** `release.yml` builds both images and pushes
them to GHCR with their attestations. There is no dry run on a tag — CI's
images job, which builds the same Dockerfiles without pushing, is the rehearsal.

## Docker Image

`release.yml` does this on a tag. By hand, for a local image:

```sh
# Build context is the parent dir holding dpp-engine/ (and dpp-core/ for local mode).
docker build -t ghcr.io/odal-node/dpp-node:0.1.0 -f dpp-engine/docker/node.Dockerfile .
docker build -t ghcr.io/odal-node/dpp-resolver:0.1.0 -f dpp-engine/docker/resolver.Dockerfile .
```

## Supply-Chain Attestations

Images pushed by `release.yml` carry two attestations alongside the image, not
inside it. Read them with:

```sh
docker buildx imagetools inspect ghcr.io/odal-node/dpp-node:0.1.0 \
  --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/odal-node/dpp-node:0.1.0 \
  --format '{{ json .Provenance }}'
```

- **SBOM** — what is in the image. The Debian runtime packages come from
  BuildKit's filesystem scan; the Rust crates come from the dependency graph
  `cargo auditable` embeds in the binary at build time. **Both halves are
  needed.** A plain `cargo build` produces a binary that records nothing about
  itself, so a scan of that image would list the base layer and none of the
  application's dependencies — accurate, and useless for the question anyone is
  actually asking.
- **Provenance** — SLSA `mode=max`: the source commit, the workflow that built
  it, the base images and the build arguments.

The same crate list is readable straight out of a pulled image, without the
registry:

```sh
docker create --name tmp ghcr.io/odal-node/dpp-node:0.1.0
docker cp tmp:/usr/local/bin/dpp-node ./dpp-node && docker rm tmp
cargo audit bin ./dpp-node
```

That command answers "is the thing I am running affected by this advisory"
against the artefact itself rather than against a lockfile someone says matches
it.

Run outside a checkout of this repository, it reports **RUSTSEC-2023-0071**
(`rsa`, reached through `dpp-seal`'s certificate verification) and exits
non-zero. Inside one, `.cargo/audit.toml` suppresses it and records why it does
not apply here: this workspace performs no RSA private-key operation, which is
the only thing that advisory is about.

**If a release is ever cut without `cargo auditable`**, the image still builds
and still pushes, the SBOM attestation is still produced, and it is silently
missing every crate. Nothing fails. The Dockerfiles are the only thing keeping
this true — treat a change to their build command as a supply-chain change.

## Post-Release

1. Verify the tag's `release.yml` run pushed both images under all three tags.
2. Verify the Docker image runs correctly against a fresh PostgreSQL instance.
3. **Verify the attestations are present** — run the `imagetools inspect`
   commands above and confirm the SBOM lists crates, not only Debian packages.
4. Run the seed script against the released version to confirm compatibility.
5. Announce the release in project communication channels.

## Hotfix Process

For critical bugs in a released version:

1. Create a `fix/description` branch from the release tag.
2. Apply the fix with tests.
3. Merge to `main` via PR.
4. Tag a new patch version (e.g., `v0.1.1`); its `release.yml` run publishes
   the images.

## Wasm Plugins

**Not distributed yet.** No release carries plugin artefacts, and the images
ship none, so a node with no plugin for a product group takes the passthrough
path. An operator who needs one builds it from dpp-core's `plugins/` and
installs it, signed, through `POST /vault/api/v1/plugins`. Plugin versions track
independently from the platform version.

## References

- [Versioning Policy](VERSIONING.md)
- [Contributing Guide](../../CONTRIBUTING.md)
- [Changelog](../../CHANGELOG.md)
