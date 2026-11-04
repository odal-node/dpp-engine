# `api/`: the HTTP API description

The OpenAPI 3.1 description of every route the node, the resolver and the
standalone identity service serve. It is written as many small files and shipped
as one.

| Path | What it is |
|---|---|
| `openapi.yaml` | The root: `info`, `servers`, `securitySchemes`, `tags`, one `$ref` per path and one `$ref` per schema. Nothing else |
| `paths/<service>/` | One file per URL path, named for the path with `/` written as `_`, in the directory of the service that serves it |
| `components/schemas/<group>/` | One file per named schema, in the directory of its model group. `components/responses/` is flat |
| `openapi.bundled.yaml` | Generated and committed. The single file every consumer reads, and the one [docs.odal-node.io/api](https://docs.odal-node.io/api/) renders. Never edit it by hand |
| `openapi.bundled.json` | The same document as JSON, read by the contract test below. Also generated and committed |

```bash
just openapi-bundle    # regenerate both bundles from the tree
just openapi-check     # regenerate, fail if the committed bundles differ, then lint
just openapi-html      # build a local browsable copy (git-ignored)
```

These recipes need Node.js (they run `@redocly/cli` through `npx`), so
`openapi-check` is not part of `just check`. CI runs it on every push.

## The contract test

`crates/dpp-node/tests/openapi_contract.rs` runs in `just check` and fails when the
description and the Rust types disagree:

- **Schemas.** Each named schema is compared with the keys `serde` emits for a
  fully populated instance of the type behind it. A field the server sends and the
  spec omits fails, and so does a property the spec lists that the server never
  sends.
- **Enums.** Each enum schema is compared with the strings the Rust enum
  serialises to.
- **Routes.** The routes registered by the node, the resolver and the standalone
  identity service are compared with the documented paths, in both directions,
  with no exception list.
- **Coverage.** Every schema file must be registered in the test or listed in its
  `UNCHECKED` table with a reason, so a new schema cannot go unchecked by default.

`openapi-check` proves the description is valid OpenAPI; this test checks it
against the code.

**Limit:** the test compares property names, not types. A property documented as
`type: string` whose field is an object still passes. Check the type yourself when
you change a schema.

When the test fails, fix the spec or fix the type. Do not edit the test's fixtures
to match a wrong spec: the fixtures describe what the server sends.

## Why the bundle is committed

The documentation site vendors this spec and checks its copy against the bundle at
a recorded commit with `git show <commit>:<path>`. That only works for a committed
file. `redocly bundle` is byte-deterministic, so `openapi-check` can prove with a
plain diff that the committed bundle matches the tree.

## Authoring rules

**OpenAPI 3.1 has no `nullable` keyword**, and the linter rejects it. Write a
nullable value as a type union:

```yaml
# a nullable scalar
type: [string, "null"]

# a nullable $ref
anyOf:
  - $ref: "#/components/schemas/TreeReport"
  - type: "null"
```

**`.redocly.lint-ignore.yaml` is a baseline** of the lint findings that existed
when the lint was introduced, so the lint fails only on new ones. Remove entries as
you fix them; never regenerate the file. It is keyed by file name and names
`openapi.bundled.yaml`, the file CI lints.

**YAML comments are lost.** `redocly bundle` and `redocly split` both drop them. Put
anything worth keeping in a `description` field, a tag description or this file.

## Layout

A file lives in the directory of the thing it belongs to: `paths/` has one directory
per service (`vault/`, `integrator/`, `identity/`, `resolver/`, `health/`), and
`components/schemas/` has one per model group.

File names follow `redocly split`'s convention (`/` written as `_`), but the
directories do not: `split` writes one flat `paths/` directory. **The tree is
maintained by hand**; running `redocly split` would flatten it.

When you restructure the tree, regenerate the bundle and check that it is
byte-identical. A reorganisation that changes the bundle has changed the API.

## Ordering

Three blocks in `openapi.yaml` decide how the rendered reference is ordered:

| Block | Controls |
|---|---|
| `tags:` | The order of the sections |
| `paths:` | The order of operations within a section |
| `components.schemas:` | The order of the models |

Every entry in `components.schemas` is a `$ref`, so the bundler could assemble the
document without it. The block exists to fix the model order; without it, models
appear in whatever order the bundler reaches them. A schema missing from the block
still bundles, through the paths that use it, but it is listed after all the
declared ones. Add a new schema to the block, in its group.

## Naming

**A schema name must be unambiguous on its own.** Rust qualifies a name with its
module path (`handlers::sign::SignRequest`); OpenAPI schemas share one flat
namespace. Put the qualifier in the name: `InternalSignRequest`,
`CreatePassportRequest`.

**The Rust type has the same name as its schema.** The contract test binds the two
by string, so a type named differently from its schema needs a translation entry,
and a mismatch is easy to miss.

Name request and response bodies by direction:

| Direction | Shape | Example |
|---|---|---|
| Request body | `Create<Thing>Request` | `CreateApiKeyRequest`, `CreateWebhookRequest` |
| Response carrying a one-time secret | `Created<Thing>Response` | `CreatedApiKeyResponse`, `CreatedWebhookResponse` |

Do not use a prefix such as `New*` that does not say which direction it is.
