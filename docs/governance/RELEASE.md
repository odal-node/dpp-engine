# Release process

How a `dpp-engine` release is prepared, tagged and checked.

## What a release produces

| Artefact | Where |
|---|---|
| Container images `dpp-node` and `dpp-resolver` | `ghcr.io/odal-node/…`, tagged `X.Y.Z`, `X.Y` and `latest` (no `v` prefix) for a git tag `vX.Y.Z` |
| SBOM and SLSA provenance attestations | Attached to each image |
| Source | This repository, under BSL-1.1 |

`dpp-engine` is not published to crates.io. No standalone binary and no GitHub Release
are produced; the images are the distribution. Releases have no fixed schedule, and a
security fix is released as soon as it is verified.

> [!NOTE]
> The GHCR packages are not public yet, so pulling the images needs access to the
> organisation.

## Before tagging

1. **Gates green.** `just check` and `just test-integration` (Docker) pass locally, and
   CI is green on the commit to be tagged.
2. **Changelog.** Rename `[Unreleased]` to `[X.Y.Z] - <date>` (Keep a Changelog format).
   Move any breaking-change wording found under *Added*, *Changed* or *Fixed* to
   *Breaking*: a break listed elsewhere is one nobody migrates for.
3. **Migrations.** Every schema change is a new file in `ops/pg/`, and
   `just migrations-check` passes.
4. **Onboarding.** `odal bootstrap` provisions the first API key against a fresh node.
5. **README.** The crate table matches `crates/`, the `dpp-core` references match
   `[workspace.dependencies]`, and the resolver routes match
   `crates/dpp-resolver/src/router.rs`.
6. **Dependencies.** `just audit` passes, and every `dpp-core` crate is pinned to a
   published release, never a local path or an unreleased commit.
7. **Standards re-read.** Read each row of
   [`docs/architecture/STANDARDS.md`](../architecture/STANDARDS.md) at its source
   (`https://www.rfc-editor.org/info/rfcNNNN`), correct `Status as read`, and set `Read`
   to today. The gate proves every citation has a dated status; only this step proves
   the status is still current.

## Bumping the version

The version is in four places, changed in one pull request:

1. `Cargo.toml`, `[workspace.package] version`.
2. `api/openapi.yaml`, `info.version`. `just spec-version-check` compares it with (1).
3. `api/openapi.bundled.yaml` and `.json`: regenerate with `just openapi-bundle`.
   `just openapi-check` fails if they drift.
4. `Cargo.lock`: build once after the bump and commit it. Only the image builds use
   `--locked`, so a stale lock surfaces when the release images refuse it.

## Tagging

Merge the release pull request, wait for CI on the merge commit (including both
**Container image** checks), then tag that commit:

Replace `<version>` below with the release number from `Cargo.toml`, without the `v`.

```bash
git tag -a v<version> -m "v<version>"
git push origin v<version>
```

> [!WARNING]
> Pushing the tag publishes. `release.yml` builds both images and pushes them with their
> attestations. There is no dry run on a tag; CI's image job, which builds the same
> Dockerfiles without pushing, is the rehearsal.

To build an image locally (the build context is the directory containing
`dpp-engine/`, and `dpp-core/` for local-core builds):

```bash
docker build -t ghcr.io/odal-node/dpp-node:<version> -f dpp-engine/docker/node.Dockerfile .
docker build -t ghcr.io/odal-node/dpp-resolver:<version> -f dpp-engine/docker/resolver.Dockerfile .
```

## Supply-chain attestations

Each image pushed by `release.yml` carries two attestations beside it:

```bash
docker buildx imagetools inspect ghcr.io/odal-node/dpp-node:<version> --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/odal-node/dpp-node:<version> --format '{{ json .Provenance }}'
```

- **SBOM:** the Debian runtime packages from BuildKit's filesystem scan, and the Rust
  crates from the dependency list `cargo auditable` embeds in the binary at build time.
  A plain `cargo build` embeds nothing, and the SBOM would then list only the base
  layer.
- **Provenance:** SLSA `mode=max`: source commit, workflow, base images and build
  arguments.

The crate list can also be read from a pulled image directly:

```bash
docker create --name tmp ghcr.io/odal-node/dpp-node:<version>
docker cp tmp:/usr/local/bin/dpp-node ./dpp-node && docker rm tmp
cargo audit bin ./dpp-node
```

Run outside a checkout of this repository, that reports **RUSTSEC-2023-0071** (`rsa`,
reached through `dpp-seal`'s certificate verification) and exits non-zero. Inside a
checkout, `.cargo/audit.toml` suppresses it with the reason: the workspace performs no
RSA private-key operation, which is all that advisory concerns.

If an image were built without `cargo auditable`, it would still build, push and get an
SBOM, and the SBOM would be missing every crate with nothing failing. Treat a change to
the Dockerfiles' build command as a supply-chain change.

## After tagging

1. The tag's `release.yml` run pushed both images under all three tags.
2. The image starts against a fresh PostgreSQL and passes `odal status`.
3. The attestations are present, and the SBOM lists crates, not only Debian packages.
4. `odal bootstrap` works against the released images.
5. The release is announced.

## Hotfixes

1. Branch `fix/<description>` from the release tag.
2. Fix it, with a test.
3. Merge to `main` through a pull request.
4. Tag the next patch version; its `release.yml` run publishes the images.

## Wasm plugins

Plugins are not distributed yet: no release carries plugin artefacts, and the images
ship none, so a product group without a plugin takes the passthrough path. Build a
plugin from `dpp-core`'s `plugins/`, sign it, and install it with `odal plugin install`.
Plugin versions are independent of the engine version.

## References

- [Versioning](VERSIONING.md)
- [Git workflow](GIT-STRATEGY.md)
- [Changelog](../../CHANGELOG.md)
