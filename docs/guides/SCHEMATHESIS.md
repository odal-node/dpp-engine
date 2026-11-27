# Generated API response checks

Schemathesis generates requests from the OpenAPI contract and checks each
response against it. The nightly run uses the bundled OpenAPI 3.1 description,
the project-built node image, and all Schemathesis checks.

## Decision: keep

The first run found real `500` responses for malformed-but-schema-valid input.
Those defects were fixed and covered by node integration tests, so this check is
worth keeping as a nightly regression signal.

## Measured run

Run on 2026-11-27 against a local node started with `just up` and bootstrapped
with the `dev-write` API key (write scope). Schemathesis ran from its Docker
image, version `4.34.4`; no Python environment or dependency was added to the
repository.

| Setting | Result |
|---|---|
| Schema | `api/openapi.bundled.yaml` (OpenAPI `3.1.0`) |
| Checks | `--checks all`, with `--experimental=openapi-3.1` |
| Scope | 99 of 104 operations; credential read, webhook test delivery, and the three standalone identity mTLS operations excluded |
| Runtime | 120.07 seconds (`--max-time 120`) |
| Generated cases | 16,863 |
| Failed cases | 69, including 5 server-error responses |

### Distinct findings

1. `POST /vault/api/v1/dpp` accepted a well-formed `supersedesId` that did not
   identify a stored passport. PostgreSQL rejected the insert on its foreign
   key, and the API returned `500`. The handler now checks the reference first
   and returns the already-documented `422` validation response.
2. NUL bytes in free-text filters reached PostgreSQL in the passport list,
   identity lookup, and public GTIN lookup. PostgreSQL rejected those query
   values and the API returned `500`. The handlers now reject them with a
   documented RFC 9457 `400` before querying the database.

Both findings have real-Postgres integration coverage in
`crates/dpp-node/tests/smoke.rs`; the pre-fix tests reproduced `500`, and both
pass after the fixes.

### False positives and scope limits

- The bundled description covers the node, standalone identity service, and
  resolver. The initial broad pass targeted the node, so resolver-only paths
  were not meaningful node checks; the nightly job includes only paths mounted
  by the node. In particular, the shared root `/health` operation is
  `resolverHealth`, while the node's `/health` returns a different minimal
  body, so the nightly path filter leaves it out; node liveness is checked
  separately before the run.
- The nightly run also excludes `/vault/internal/scan-batch`, an mTLS-only
  resolver-to-node sink rather than a public node operation.
- The measured credential had `write` scope. Admin-only operations therefore
  exercised their documented access-denial paths rather than their successful
  responses; the run reported 29 authorization warnings. Nightly CI bootstraps
  a fresh admin key to cover those operations.
- The credential read (`readDppByCredential`) resolves a caller-supplied
  `did:web`, and `testWebhook` sends a request to the configured receiver. Both
  are excluded from the local and nightly runs rather than pointed at an
  uncontrolled external service.

The `69` failed cases are not a count of confirmed defects: the first command
did not retain a structured report, and its combined schema included routes
not served by the target node. The fixed server errors above are the distinct
actionable findings established by that run. The other 64 failed examples were
not individually retained or classified, so they are neither counted as
resolved nor dismissed as false positives. The nightly workflow narrows the
target to node routes and preserves the all-check setting; its Actions log is
the source for any further triage.