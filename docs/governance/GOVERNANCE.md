# Project Governance

This document describes the decision-making structure for dpp-engine and
how it is expected to evolve.

## Current Model: BDFL (Benevolent Dictator For Life)

dpp-engine is maintained by a single author and the project is in its early
pre-1.0 phase. All design decisions, release approvals, and merge authority
rest with:

- **Maintainer**: Aleksandar Temelkov (LKSNDRTMLKV)
- **Organisation**: Odal Node
- **Contact**: https://github.com/LKSNDRTMLKV

This model is appropriate for the current stage. It allows fast iteration
while the EU regulatory landscape (ESPR delegated acts, EU Registry API) is
still evolving.

## Relationship to dpp-core

dpp-engine consumes dpp-core (Apache-2.0) as a dependency. The platform
never modifies core types or traits — it only implements them. Decisions
affecting the core/platform boundary (new port traits, type changes) are
made in the dpp-core repo first.

**Core Purity Rule**: No platform concerns (auth, audit, API keys, operator
management) may be pushed into dpp-core. The platform adapts to core, not
the reverse.

## Decision Records

Significant technical decisions are recorded in the architecture docs under
`docs/architecture/`. Key decisions include:

- Composite auth provider pattern
- Fire-after-commit event semantics
- Operator model (not tenant model)
- Single-tenant persistence — no Row-Level Security; operator isolation is an infrastructure boundary, one node per operator

## Contribution Governance

All contributions follow the process described in [CONTRIBUTING.md](CONTRIBUTING.md):

1. Open an issue describing the proposed change.
2. Fork, implement, and submit a pull request.
3. CI must pass (fmt, clippy, test).
4. The maintainer reviews and merges.

No pull request is merged without maintainer approval. Force-pushes to `main`
are prohibited.

## Security Decisions

Security-sensitive changes (anything touching authentication, API key hashing,
or identity service integration) require:

1. A dedicated review focusing on the security implications.
2. Explicit sign-off in the PR description noting what changed and why.
3. An update to [SECURITY.md](../project/SECURITY.md) if the change affects
   the threat model.

## Licensing

dpp-engine is licensed under BSL-1.1 (Business Source License 1.1).

- **Change Date**: 4 years from each version's release date.
- **Change License**: Apache-2.0 (same as dpp-core).
- **Additional Use Grant**: Self-hosting for internal business use is permitted.
  Offering the software as a hosted service to third parties requires a
  commercial license.

The maintainer holds copyright. Contributors retain copyright over their
contributions and grant the license via PR submission.

## Evolution Path

| Contributors | Model | Change |
|---|---|---|
| 1 (current) | BDFL | All authority with maintainer |
| 2 - 5 | BDFL + Trusted Committers | Named individuals gain merge rights |
| 5+ | Maintainer Council | Formal RFC process for breaking changes |

## References

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](../project/SECURITY.md)
- [Architecture docs](../architecture/)
- [