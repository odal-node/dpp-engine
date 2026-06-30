# Git Strategy — dpp-engine

**Model:** Trunk-based development
**Remote:** `git@github.com:odal-node/dpp-engine.git`
**Primary branch:** `main`

---

## Branch Structure

```
main                    <- always deployable, tagged releases
  +-- feat/*            <- feature branches (short-lived, <1 week)
  +-- fix/*             <- bug fixes
  +-- chore/*           <- CI, docs, formatting, dependency bumps
  +-- release/v*        <- optional: release prep branch if needed
```

No `develop` branch. No long-lived branches. Everything merges to `main` via PR.

---

## Commit Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

Types: feat, fix, test, docs, chore, refactor, ci
Scopes: vault, dal, identity, integrator, node, types, common, resolver, ops
```

Examples:
```
feat(vault): add operator config PATCH endpoint
fix(dal): handle edge case in api_key lookup
test(node): add Tier 2 smoke test for publish flow
docs(ops): rewrite seed data for operator schema
chore(deps): upgrade axum to 0.8.2
```

---

## Release Tagging

```
v0.1.0    <- first release (current state)
v0.1.1    <- patch: bug fixes
v0.2.0    <- minor: new endpoints, schema changes
v1.0.0    <- major: Control-Plane managed hosting (one node per operator), production-ready API
```

Tag format: `v{MAJOR}.{MINOR}.{PATCH}`

Create tags on `main` only:
```bash
git tag -a v0.1.0 -m "Initial release — DPP platform"
git push origin v0.1.0
```

---

## PR Workflow

1. Create a feature branch: `git checkout -b feat/unsold-goods-endpoint`
2. Make changes, commit with conventional format
3. Push and open PR against `main`
4. CI runs: `fmt-check -> clippy -> test`
5. Squash-merge to `main` (keeps history clean)
6. Delete the feature branch

---

## Branch Protection (set up on GitHub)

For `main`:
- Require PR reviews (1 reviewer minimum)
- Require CI status checks to pass
- Require linear history (squash merges)
- No force pushes
- No direct commits (everything via PR)

---

## First Push Checklist

```bash
# 1. Make sure everything passes
cargo fmt --all --check
cargo clippy --workspace
cargo test --workspace

# 2. Create the GitHub repo
gh repo create odal-node/dpp-engine --private --description "Odal Node DPP Platform (BSL-1.1)"

# 3. Set remote and push
cd dpp-engine
git remote add origin git@github.com:odal-node/dpp-engine.git
git branch -M main
git push -u origin main

# 4. Tag the initial release
git tag -a v0.1.0 -m "Initial release — DPP platform"
git push origin v0.1.0

# 5. Set branch protection rules on GitHub
```

---

## Visibility Strategy

dpp-engine is **BSL-1.1 licensed**. It is private by default; source-available publication follows once the initial release is validated.

| Phase | Visibility | Reason |
|---|---|---|
| **Now** | Private | Active development, schema stabilisation |
| **After initial validation** | Source-available | BSL-1.1 allows reading; production use requires license |
| **After 4-year change date** | Apache-2.0 | BSL conversion clause |
