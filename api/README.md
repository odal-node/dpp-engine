# `api/` — the HTTP API description

**Author multi-file. Ship single-file.**

- `openapi.yaml` — the root. Holds `info`, `servers`, `securitySchemes`, `tags`,
  `x-tagGroups`, a `$ref` per path, and a `$ref` per schema. Nothing else
  belongs here. The order of those last two blocks is the order the rendered
  reference shows — see *Ordering* below.
- `paths/<service>/` — one file per URL path, named for the path with `/`
  written as `_`, in the directory of the service that serves it.
- `components/schemas/<group>/` — one file per named schema, in the directory of
  the model group it renders under. `components/responses/` is flat.
- `openapi.bundled.yaml` — **generated, committed, never hand-edited.** The
  single-file form every consumer reads.
- `openapi.bundled.json` — the same document in JSON, for the contract test
  below. Also generated and committed; also never hand-edited.

```
just openapi-bundle    # regenerate both bundles from the tree
just openapi-check     # diff the bundles, then lint the YAML one
just openapi-html      # regenerate the browsable spec (git-ignored)
```

## The spec is checked against the code, not just against itself

`crates/dpp-node/tests/openapi_contract.rs` runs in the ordinary `just check`
gate and fails when this description and the Rust types disagree:

- **every named schema** is compared against the keys `serde` emits for a
  maximally-populated instance of the type behind it — a field the server sends
  and the spec omits fails, and so does a property the spec promises and the
  server never sends;
- **every enum schema** is compared against the wire strings the Rust enum
  actually serialises to;
- **every route** registered by each of the three deployables this document
  describes — the node, the resolver, and the standalone identity service that
  `servers` names as host of the mTLS signing surface — is compared against the
  paths documented here, in both directions, with no exception list;
- **every schema in this directory** must be registered in that test or listed
  in its `UNCHECKED` table with a reason. A new schema nothing checks fails the
  build rather than passing quietly.

This exists because `openapi-check` reads only the spec. Redocly can prove this
description is *valid*; it cannot prove it is *true*. Before the contract test,
nothing in CI opened a `.rs` file on the spec's behalf, and the two had drifted
apart in fourteen schemas, one enum and two routes — including a required
property no endpoint ever returned, and two lifecycle states the server emits
that the spec did not list.

**Known limit: the contract test compares property *names*, not their types.**
A property documented as `type: string` whose field is an object still passes.
That gap is real — `co2ePerUnit` and `repairabilityScore` were both documented
as bare numbers long after they became objects. Check the type when you touch a
schema; the gate will not do it for you.

When it fails, fix the spec or fix the type. Do not edit the test's fixtures to
agree with a wrong spec — the fixtures are the statement of what the server
sends.

## Why the bundle is committed rather than built on demand

The documentation site vendors this spec and verifies its copy against the
version at a recorded commit — `git show <commit>:<path>`. That reads one blob
out of git history, which works for a committed file and cannot work for an
artefact that only exists after a build step. Committing the bundle is what
keeps that check deterministic and self-contained.

CI regenerates the bundle and fails if the committed one differs, so it cannot
drift from the tree it came from.

## Authoring rules

**This is OpenAPI 3.1.** `nullable: true` is not a keyword in 3.1 and is
rejected by the linter. A nullable value is a type union:

```yaml
# a nullable scalar
type: [string, "null"]

# a nullable $ref — a union with the null type, not allOf + nullable
anyOf:
  - $ref: "#/components/schemas/TreeReport"
  - type: "null"
```

This defect has reached `main` twice. `just openapi-check` runs in CI on every
push specifically to stop a third time.

**`.redocly.lint-ignore.yaml` baselines the problems the spec has today**, so the
lint passes now and fails on new ones. Shrink that file; never regenerate it, or
the gate stops meaning anything. It is keyed by *filename* — it names
`openapi.bundled.yaml`, which is what CI lints.

**Comments do not survive.** `redocly split` and `redocly bundle` both discard
YAML comments. Anything worth keeping goes in a `description` field, a tag
description, or this file — never in a `#` comment.

## Layout

**One rule: a file lives in the directory of the section it renders under.**

`paths/vault/`, `paths/integrator/`, `paths/identity/`, `paths/resolver/`,
`paths/health/` are the five `x-tagGroups` entries. `components/schemas/<group>/`
are the fourteen model groups, and a schema's directory is also the value of its
`x-tags`. So the tree, the sidebar, and the spec cannot disagree about where
something belongs without the disagreement being visible as a wrong path.

Filenames keep `redocly split`'s URL-derived convention (`/` written as `_`), but
the directories do not: `split` writes one flat `paths/` directory, so **this
tree is maintained by hand and cannot be regenerated by the tool.** That is the
price of the rule above, and it is worth stating plainly rather than discovering
by running `split` and losing the grouping. A hundred and seven schemas in one
flat directory had no navigable order and no relationship to how they are read.

The move that introduced this layout rewrote 373 `$ref`s across 180 files and
left `openapi.bundled.yaml` **byte-identical** — which is the check to repeat if
the tree is ever restructured again. A reorganisation that changes the bundle
changed the API.
