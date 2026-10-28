# dpp-identity

The operator's `did:web` identity: it serves the DID document that holds the
Ed25519 public key every passport signature is verified against, and, as a
standalone service, signs and rotates keys. Part of
[dpp-engine](../../README.md), under the Business Source License 1.1.

## Two ways it runs

| Deployment | What is exposed |
|---|---|
| Inside `dpp-node` (every deployment today) | Only `build_public()`: `GET /identity/.well-known/did.json`, `/identity/health`, `/identity/ready`. The vault signs in-process through `dpp-vc`'s `LocalIdentityService`, so there is no network-reachable signing endpoint. The test `public_router_has_no_internal_endpoints` keeps it that way |
| Standalone `dpp-identity` binary (port 8002) | The public routes at the root, plus `POST /internal/sign`, `/internal/verify` and `/internal/keys/rotate`, reachable only over mTLS by a caller with `CN=odal-vault` |

The standalone binary is kept so identity can move onto its own host, with a
narrower blast radius than the full node. Nothing deploys it that way yet.

```bash
curl -s http://localhost:8001/identity/.well-known/did.json
```

## Key custody

The key store (`dpp-crypto`'s `KeyStore`) holds the Ed25519 key pair, encrypted at
rest with AES-256-GCM under a key derived from `KEY_STORE_PASSPHRASE` with Argon2id.
Losing the passphrase means losing the ability to sign; there is no recovery path.

## mTLS model (standalone only)

TLS is terminated by a proxy (Caddy, Nginx, Envoy or a cloud load balancer), which
verifies the client certificate and forwards its subject and issuer in
`X-Client-Cert-Subject` and `X-Client-Cert-Issuer`. The service checks the subject
`CN`, the issuer `CN` (`MTLS_REQUIRED_ISSUER_CN`, default `Odal Internal CA`) and a
shared secret the proxy adds (`MTLS_PROXY_SHARED_SECRET`), so a client cannot forge
the headers. It fails closed unless `MTLS_ALLOW_INSECURE=true`, which is for local
development and CI only. The shared implementation is `dpp_common::mtls`.

## Configuration

| Variable | Purpose |
|---|---|
| `KEY_STORE_PATH` | Encrypted key store file |
| `KEY_STORE_PASSPHRASE` | Key store passphrase. Generate it; never reuse a template value |
| `DID_WEB_BASE_URL` | The origin the `did:web` identifier is derived from |
| `PORT` | Listening port of the standalone binary |

## Modules

```text
src/
├── router.rs       build() (full) and build_public() (DID document and probes)
├── handlers/       DID document, sign, verify, rotate, health
├── middleware/     mTLS enforcement for /internal/*
├── config.rs
└── state.rs
```

## Licence

[Business Source License 1.1](../../LICENSE).
