## Summary

<!-- What this change does and why, in one paragraph. -->

## Related issue

<!-- "Closes #123", or "none" and the reason. -->

## Changes

<!-- The main changes, as bullets. -->

## Checklist

- [ ] Tests added or updated for the new behaviour
- [ ] `just check` passes locally (format, clippy over every target including the Docker-gated suites, guard scripts, unit tests, audit)
- [ ] `just test-integration` run if persistence, lifecycle or auth changed (needs Docker)
- [ ] No `println!`, `eprintln!` or `dbg!` in service-crate `src/`; use `tracing` (`just debug-check`)
- [ ] No secrets, credentials or `.env` files in the diff
- [ ] Docs updated if a public API, endpoint or CLI command changed; `just openapi-check` passes if `api/` changed
- [ ] Database change: a new migration under `ops/pg/` (an applied migration is never edited), and `just migrations-check` passes
