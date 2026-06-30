# Versioning Policy

This document describes how dpp-engine versions its releases, what
stability guarantees each version range provides, and how breaking changes
are communicated.

## Scheme

dpp-engine follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):

    MAJOR.MINOR.PATCH

- **MAJOR** — incompatible API changes (endpoint removed, request/response shape changed).
- **MINOR** — backwards-compatible new functionality (new endpoint, new optional field).
- **PATCH** — backwards-compatible bug fixes.

## Pre-1.0 Conventions

While the platform is below 1.0.0:

- A **minor** bump (0.x.0 -> 0.y.0) may contain breaking changes. Each such
  change is listed in CHANGELOG.md under a **Breaking** heading with a
  migration note.
- A **patch** bump (0.x.y -> 0.x.z) is always backwards-compatible.

The goal is to reach 1.0.0 once the HTTP API has been stable for at least one
release cycle.

## Workspace Version

All crates in the workspace share a single version defined in the root
`Cargo.toml`. Every release bumps all crates together.

## API Versioning

HTTP endpoints are versioned in the URL path: `/api/v1/...`. When a breaking
change to the HTTP API is required:

1. The new endpoints are added under `/api/v2/...`.
2. The old `/api/v1/...` endpoints remain operational for at least one
   minor release cycle.
3. Deprecation is announced in CHANGELOG.md and via a `Deprecation` response
   header on v1 endpoints.

## Database Migration Versioning

Migration files are numbered sequentially (`001_`, `002_`, etc.) and are
idempotent. New migrations are added — existing migrations are never modified.
This means any database created by any previous version can be migrated
forward by running the current version.

## dpp-core Compatibility

The platform pins to a specific tagged version of dpp-core. When dpp-core
releases a new version:

1. Update the dependency in `Cargo.toml`.
2. Adapt any changed port trait implementations.
3. Bump the platform version accordingly.
4. Note the dpp-core version in CHANGELOG.md.

## Breaking Change Detection

Breaking changes are caught by:

1. **Integration tests** — the Tier 2 smoke test exercises the full HTTP API.
   A breaking change in request/response shape causes test failures.
2. **Code review** — PRs that change handler signatures or response types
   must be flagged as breaking.

## Deprecation Process

1. Add a `Deprecation` response header to the affected endpoint.
2. Log a warning when the deprecated endpoint is called.
3. Add a note to CHANGELOG.md under **Deprecated**.
4. Remove the endpoint no earlier than the next minor release.

## References

- [SemVer 2.0.0 specification](https://semver.org/spec/v2.0.0.html)
- [Release process](RELEASE.md)
- [Changelog](CHANGELOG.md)
