## Summary

<!-- What does this PR do? One paragraph. -->

## Related issue

<!-- e.g. Closes #123, or a gaps-register ID like B-02 -->

## Changes

<!-- Bullet list of the main changes. -->

## Checklist

- [ ] Tests added or updated for new behaviour
- [ ] `just lint` passes locally (`cargo clippy --workspace --all-targets -- -D warnings`)
- [ ] `just fmt` applied (`cargo fmt --all`)
- [ ] `just test` passes (unit); `just test-integration` run if persistence/lifecycle/auth changed (needs Docker)
- [ ] No `println!`/`eprintln!`/`dbg!` in service-crate `src/` (use `tracing::`) — `just debug-check`
- [ ] No secrets, credentials, or `.env` files in the diff
- [ ] Docs updated if a public API, endpoint, or CLI command changed
- [ ] If the DB schema changed: `ops/pg/0001_init.sql` updated and still idempotent
