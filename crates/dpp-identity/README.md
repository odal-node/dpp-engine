# dpp-identity

HTTP service for `did:web` identity management and Ed25519 JWS signing in
[Odal Node](https://odal-node.io).

Every passport published by the vault is signed by the operator's Ed25519 key.
`dpp-identity` owns that key, serves the `did:web` document, and provides the
signing endpoint. In the fused `dpp-node` binary, signing is done **in-process**
via `LocalIdentityService` — the network signing endpoint is never mounted on the
public router.

---

## Why a standalone binary still exists

Today, nobody runs `dpp-identity` as its own process — every deployment uses
the fused `dpp-node` binary, which signs in-process via `LocalIdentityService`
and only ever mounts `build_public()` (the `did:web` document). The standalone
binary, its mTLS-gated `/internal/*` endpoints, and this crate's `main.rs`
remain because splitting identity out onto its own host is a real future
option (a separate signing host with a narrower blast radius than the full
node) — not because anything currently deploys that way. If you're
"finishing" the separation nobody has asked for yet, stop and check that
assumption first.

## When to use this crate

- You need to extend or test the `did:web` document endpoint.
- You need to add or modify key rotation logic.
- You are writing a test that needs a real `KeyStore` instance.

---

## HTTP API

### Public endpoints (no auth required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |
| `GET` | `/.well-known/did.json` | `did:web` DID document with the operator's Ed25519 verification method |

### Internal endpoints (mTLS, `CN=odal-vault` only)

These endpoints are **not mounted** in `dpp-node`. They are only reachable when
`dpp-identity` runs as a standalone process, accessed by `dpp-vault` over a
mutual-TLS network channel.

| Method | Path | Description |
|---|---|---|
| `POST` | `/internal/sign` | Produce an Ed25519 JWS over a base64-encoded payload |
| `POST` | `/internal/keys/rotate` | Generate a new keypair and update the DID document |

---

## Security model

- The `KeyStore` holds one Ed25519 keypair, encrypted at rest with AES-256-GCM.
- mTLS enforcement: `MTLS_ENFORCE=true` (default) requires the caller to present
  a client certificate with `CN=odal-vault`. The header `X-Client-Cert-Subject` is
  set by the TLS terminator (nginx / Caddy) before routing to the service.
- In `dpp-node`, the vault calls `LocalIdentityService` directly — there is no
  network-reachable signing surface at all. (Regression test: `public_router_has_no_internal_endpoints`.)

---

## Module structure

```
src/
├── config.rs             Config (DID_WEB_BASE_URL, MTLS_ENFORCE, key store path)
├── handlers/
│   ├── did_document.rs   Serves the JWK-formatted DID document
│   ├── sign.rs           /internal/sign — Ed25519 JWS production
│   └── rotate_key.rs     /internal/keys/rotate — keypair rotation
├── middleware/mtls.rs    mTLS CN check middleware
├── router.rs             build() (full) + build_public() (did:web only)
└── state.rs              AppState (Arc<KeyStore>, did_web_base_url)
```

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-crypto` | `KeyStore` implementation, Ed25519 signing primitives |
| `dpp-domain` | `IdentityPort` trait that this service implements |
| `dpp-vault` | Calls this service to sign passports at publish time |
| `dpp-node` | Mounts only `build_public()` under `/identity`; signing is in-process |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
