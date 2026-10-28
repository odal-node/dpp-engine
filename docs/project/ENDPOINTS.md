# How routes are mounted

The authoritative route list, with authentication, scopes and error codes, is the
OpenAPI description, [`api/openapi.bundled.yaml`](../../api/openapi.bundled.yaml),
browsable at [docs.odal-node.io/api](https://docs.odal-node.io/api/). A contract test
(`crates/dpp-node/tests/openapi_contract.rs`) fails when a router serves a path the
description does not list, or the reverse. This page explains how the routers are
composed, which the description does not show.

## The node (`dpp-node`, port 8001)

`crates/dpp-node/src/router.rs` nests three routers under one listener:

| Prefix | Router | Mounted with |
|---|---|---|
| `/health` | `dpp-node` | |
| `/vault/*` | `dpp_vault::router::build` | Auth middleware on `/vault/api/v1/*`; scope checks in the handlers |
| `/identity/*` | `dpp_identity_service::router::build_public` | Public routes only: the DID document and probes |
| `/integrator/*` | `dpp_integrator::router::build` | Each handler forwards the caller's `Bearer` token to the vault |

Within `/vault`, routes fall into four groups by who may call them:

| Group | Authentication |
|---|---|
| `/vault/api/v1/*` | API key (`Bearer odal_sk_…`) or the local admin (`Basic`) |
| `/vault/public/*` | None. The signed public view |
| `/vault/credential/*` | None, but reads more when the caller sends `X-DPP-Credential`. Kept out of `/public` because a public URL whose body varies by caller breaks caching, and out of `/api/v1` because a repairer or authority holds a credential, not an API key |
| `/vault/internal/*` | mTLS (`CN=odal-resolver`): the resolver's scan-count flush |

## Signing endpoints are not mounted

`dpp-identity`'s `/internal/sign`, `/internal/verify` and `/internal/keys/rotate` exist
only on the standalone identity binary (port 8002), behind mTLS with `CN=odal-vault`.
The node mounts `build_public()` instead and signs in-process through
`LocalIdentityService`, so it has no network-reachable signing endpoint. The test
`public_router_has_no_internal_endpoints` in `dpp-identity` keeps it that way.

## The resolver (`dpp-resolver`, port 8003)

A separate process with its own router (`crates/dpp-resolver/src/router.rs`): the GS1
Digital Link routes under `/01/…`, the content-negotiated `/dpp/{dppId}`, the QR code
route and the probes. See [its README](../../crates/dpp-resolver/README.md).

## Idempotency keys

Which routes accept `Idempotency-Key` is defined once, in
`dpp_common::idempotency::policy`, and the test
`every_keyed_route_is_a_route_the_node_serves` checks that table against the live
routers.
