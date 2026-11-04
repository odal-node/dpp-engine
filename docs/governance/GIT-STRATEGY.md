# Git workflow

Trunk-based development on `main`. Commit conventions and pull request expectations are
in [CONTRIBUTING.md](../../CONTRIBUTING.md); this page covers branches, merging,
protection and tags.

## Branches

```text
main          always releasable; releases are tagged here
feat/*        features
fix/*         bug fixes
docs/*        documentation
test/*        tests only
refactor/*    behaviour-preserving changes
ci/*, chore/* CI, tooling, dependency bumps
```

Branches are short-lived and merge into `main` through a pull request. There is no
`develop` branch and no long-lived release branch.

## Merging

- **Squash merge only.** The pull request title becomes the commit subject on `main`,
  so it must be a Conventional Commit; the `PR title is a conventional commit` check
  enforces it. A title cannot be corrected after a release is cut from it.
- **Up to date before merge.** Required checks run against the current `main`, so a
  branch behind `main` must be updated first. Merges are therefore serial.
- **Rebase old branches before pushing.** A branch cut from an old `main` should be
  rebased locally and checked again with `just check` before it is pushed, to confirm
  it still does what it was for.

## Protection on `main`

Enforced by a repository ruleset:

| Rule | Setting |
|---|---|
| Changes | Through pull requests only, squash merge |
| Force pushes and deletion | Blocked |
| Required checks | Format, Clippy, unit tests, integration tests (testcontainers), PostgreSQL integration tests, security audit, the guard scripts (debug prints, `mod.rs` contents, event subject literals, contract fixtures), OpenAPI lint, conventional PR title |
| Up-to-date branch | Required |

Some CI jobs are not yet required checks. They report on every pull request but do not
block a merge.

## Reviews

Automated review (CodeRabbit) runs only on pull requests labelled `review-ready`, or when
someone comments `@coderabbitai review`. It reviews the pull request as it stood at that
moment and does not re-review on push, so after a rebase or a fix for a finding, ask
again. Label a branch only when it is finished: scope complete, `just check` green,
conventional title, not a draft.

## Tags and releases

Tags are `v{MAJOR}.{MINOR}.{PATCH}`, annotated, on a `main` commit that has already
passed CI:

```bash
git tag -a v0.15.0 -m "v0.15.0"
git push origin v0.15.0
```

Pushing a `v*` tag runs `release.yml`, which builds and publishes the container images.
[RELEASE.md](RELEASE.md) has the full checklist, and [VERSIONING.md](VERSIONING.md)
what each kind of release may change.

## Visibility

This repository is public. Anything committed, and every pull request, issue and commit
message, is published when pushed. Do not reference non-public repositories, internal
decision records, commercial terms or the text of paid standards (EN, ISO); cite a
standard's clause and describe it in your own words.
