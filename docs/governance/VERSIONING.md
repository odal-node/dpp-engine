# Versioning

How `dpp-engine` numbers its releases, what each kind of release may change, and how
breaking changes are announced.

## Scheme

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html): `MAJOR.MINOR.PATCH`.

- **MAJOR:** incompatible changes to the HTTP API, the CLI or the database.
- **MINOR:** new functionality that is backwards compatible.
- **PATCH:** backwards-compatible fixes.

Every crate in the workspace shares the version in the root `Cargo.toml`
(`[workspace.package]`), and a release bumps them together. The OpenAPI description's
`info.version` matches it; `just spec-version-check` enforces that.

## Before 1.0

The engine is pre-production and below 1.0:

- **A minor release may break things:** routes, request and response shapes, CLI flags,
  configuration variables and the database schema. Each break is listed under
  **Breaking** in [CHANGELOG.md](../../CHANGELOG.md), with what to change. Breaking
  commits are marked with `!` in their conventional commit title.
- **A patch release never breaks.**
- **Removed things are removed.** There is no deprecation period while nobody depends
  on the old behaviour in production.

## From 1.0

Once the API has been stable for a release cycle, 1.0.0 starts these rules:

1. A breaking HTTP change adds the new form under a new path version (`/api/v2/…`);
   the old version keeps working for at least one minor release.
2. Deprecated endpoints return a `Deprecation` response header, log a warning when
   called, and are listed under **Deprecated** in the changelog.
3. Removal happens no earlier than the next minor release after the deprecation.

## Database migrations

Migrations in `ops/pg/` are numbered `NNNN_name.sql`, only ever added, and never edited
or renumbered once on `main`: sqlx records each file's checksum, and a node whose
recorded checksum disagrees refuses to start. A database created by any earlier
release can therefore be migrated forward by starting the current one. Migrations go
forward only; rolling back means restoring a backup.

## `dpp-core` compatibility

The engine pins exact `dpp-core` crate versions from crates.io in
`[workspace.dependencies]`. When `dpp-core` releases:

1. Bump the pins.
2. Adapt the port implementations to any changed traits.
3. Record the new `dpp-core` version in the changelog.

A `dpp-core` breaking change does not always break the engine's API; the engine's own
version bump follows the rules above for what its users see.

## How breaking changes are caught

- **The OpenAPI contract test** fails when a route, a schema's properties or an enum's
  values change without the description changing with them.
- **The integration suites** exercise the full HTTP API against PostgreSQL.
- **Review:** a change to a handler's request or response type is breaking unless shown
  otherwise.

## References

- [Release process](RELEASE.md)
- [Changelog](../../CHANGELOG.md)
