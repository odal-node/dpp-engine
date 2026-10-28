# Governance

How decisions are made for `dpp-engine`, and how that is expected to change.

## Current model: single maintainer

The project is pre-1.0 and has one maintainer, who holds all design, release and merge
authority:

- **Maintainer:** Aleksandar Temelkov ([@LKSNDRTMLKV](https://github.com/LKSNDRTMLKV))
- **Organisation:** Odal Node

One decision-maker keeps iteration fast while the regulation (ESPR delegated acts, the EU
registry API) is still moving.

## Relationship to dpp-core

`dpp-engine` uses `dpp-core` (Apache-2.0) as a dependency. The engine implements core's
traits and never modifies its types or traits. Decisions that affect the boundary between
the two (new port traits, type changes) are made in the `dpp-core` repository first.

Engine concerns (auth, audit, API keys, operator management) are never pushed into
`dpp-core`. The engine adapts to core, not the reverse.

## Where decisions are recorded

Significant technical decisions are recorded in the documents under
[`docs/architecture/`](docs/architecture/), including:

- the composite auth provider pattern;
- fire-after-commit event semantics;
- the operator model (rather than a tenant model);
- single-tenant persistence with no row-level security: isolation between operators is an
  infrastructure boundary, one node per operator.

## Contributions

Every contribution follows [CONTRIBUTING.md](CONTRIBUTING.md):

1. Open an issue describing the change.
2. Fork, implement, and open a pull request.
3. CI passes (format, clippy, guard scripts, tests, integration tiers).
4. The maintainer reviews and merges.

Nothing merges without maintainer approval. Force-pushes to `main` are blocked.

## Security-sensitive changes

A change to authentication, API key hashing, signing or identity needs:

1. A review focused on its security implications.
2. A statement in the pull request description of what changed and why.
3. An update to [SECURITY.md](SECURITY.md) if it changes the threat model.

## Licensing

`dpp-engine` is licensed under the Business Source License 1.1. The [LICENSE](LICENSE) file
is authoritative; in summary:

- **Additional Use Grant:** production use to issue, sign, store and serve passports for
  your own organisation's products and compliance obligations is permitted at no charge.
- **Not covered:** offering the engine to third parties as a hosted or managed service, or
  embedding it in a competing product. Both need a commercial licence.
- **Change date:** four years from each release's date.
- **Change licence:** Apache-2.0, the same as `dpp-core`.

The maintainer holds copyright in the original work. Contributors keep copyright in their
contributions and license them under the repository's licence through the DCO sign-off.

## How the model will change

| Contributors | Model | What changes |
|---|---|---|
| 1 (today) | Single maintainer | All authority with the maintainer |
| 2 to 5 | Maintainer and trusted committers | Named people gain merge rights |
| More than 5 | Maintainer council | A written RFC process for breaking changes |

## References

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [Architecture documents](docs/architecture/)
