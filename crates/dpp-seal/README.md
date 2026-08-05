# dpp-seal

eIDAS qualified electronic seal adapter for [Odal Node](https://odal-node.io).

Implements `SealPort` (from `dpp-domain::ports::seal`) against **eID Easy Cloud
Direct e-Sealing**, which aggregates qualified QTSPs and returns **CAdES**. When
eID Easy is not configured the adapter delegates to `GhostSeal`, and a production
node refuses to boot.

> **Not yet exercised against the live provider.** Every code path is built and
> tested against a local mock; the sandbox test is blocked on eID Easy enabling
> test e-seal credentials for our client.

## What ships

| Component | Status |
|---|---|
| `QtspSealAdapter` | eID Easy backend, or `GhostSeal` when unconfigured |
| `config::EideasyConfig` | `from_env()`, host allowlist, redacting `Debug` |
| `eideasy::client` | HMAC-signed POST to `/api/signatures/e-seal` |
| `eideasy::types` | Request/response wire types |
| `error::SealError` | Typed auth / transport / protocol / provider failures |

`verify()` is **not** implemented and says so, returning a typed error. Verifying
a detached CAdES needs an independent AdES validator — no Rust implementation
exists — and a seal is worth exactly as much as the independence of whoever
checked it, so this adapter never reports a verdict it did not compute.

## The one rule

The HMAC covers `METHOD + PATH + X-Timestamp + RAW_REQUEST_BODY`, and eID Easy
requires the body term to be the **exact bytes sent**. `client::SignedBody` makes
that structural: the body is serialized once, the signature is derived from that
same value, and nothing can take the bytes without the signature that goes with
them. `reqwest`'s `.json()` would re-serialize between signing and sending and
produce a 401 indistinguishable from a bad key.

The crate's mock server recomputes the HMAC from the bytes it received, so this
is verified over a socket rather than asserted in a comment.

## What is sealed

`SHA-256(passport.jwsSignature)` — the compact JWS string, hashed as stored. The
JWS is frozen at publish, reconstructible by anyone holding the passport, and
commits to the whole payload, which makes the qualified seal a countersignature:
a QTSP attesting that this operator signature existed at this time. Sealing the
canonicalized document instead would sweep in `lintResult`/`status`/`qrCodeUrl`,
all mutable after publish, so a re-lint would silently break the seal.

The composition lives in `dpp-vault`'s seal service; this crate only ever sees a
hex digest.

## Provider notes

**CAdES is not a downgrade.** eIDAS Art. 35(2) attaches the integrity and origin
presumption to a seal being *qualified* — a qualified certificate from a QTSP —
not to the AdES envelope. Detached CAdES over a hash also fits proof-bound better
than enveloped JAdES: only a digest and a detached signature ever leave the node.

**Not claimable:** no public source states the EU DPP registry accepts CAdES
*specifically*. It almost certainly validates the certificate chain rather than
the envelope flavour, but "registry-conformant CAdES" must not be stated as fact
anywhere customer-facing until that is confirmed.

**`mimeType` is `application/pdf`.** eID Easy built Direct e-Sealing for PDF and
both their docs and their support answer use that value. It is a label, not a
fact about the seal — they receive only the digest, never the payload, so they
cannot inspect the content, and for a detached CMS over an external hash the
declared type is not part of what the signature covers. `MIME_JSON` exists,
unused, for if they confirm the accurate value is accepted.

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-domain::ports::seal` | `SealPort`, `GhostSeal`, and the value objects (`SealRequest`, `SealedEnvelope`, `SealFormat::Cades`) |
| `dpp-types::seal` | `SealOutbox` — the durable queue, engine-side |
| `dpp-vault` | Composes the digest and enqueues at publish; serves `GET /api/v1/dpp/{id}/seal` |
| `dpp-node` | Resolves the adapter at boot, maps it to a trust tier, runs the drain |

## Configuration

```
SEAL_PROVIDER=eideasy                              # or `none` (default) for GhostSeal
SEAL_EIDEASY_BASE_URL=https://test.eideasy.com     # sandbox; prod = https://id.eideasy.com
SEAL_EIDEASY_CLIENT_ID=...                         # from test.eideasy.com "My Webpages"
SEAL_EIDEASY_HMAC_KEY=...                          # generated once in Eseal Settings
SEAL_EIDEASY_SIGNATURE_PROFILE=CAdES_BASELINE_T    # optional; must be enabled for client
```

`SEAL_PROVIDER` takes `eideasy` or `none`, and an unrecognised value fails the
boot. It exists with one provider because env var names are a published
interface: adding a QTSP later must not force every self-hoster through a config
migration.

Three failure modes are all refused rather than ghosted, for the same reason —
each would downgrade a node that was configured for qualified sealing into one
that has none: **credentials without a selected provider**, a **partial**
`SEAL_EIDEASY_*` set, and an **unrecognised host** in `SEAL_EIDEASY_BASE_URL`
(which cannot be classified into a trust tier).

`SEAL_EIDEASY_HMAC_KEY` is an operator-supplied node-wide credential and lives
in the node `.env` (mode 600) beside
`EU_REGISTRY_CLIENT_SECRET` and `MTLS_PROXY_SHARED_SECRET` — not in the key
store, which holds Ed25519 pairs for DID publication, and not in Postgres, which
would put a live signing credential in every backup.

When eID Easy config is absent, `QtspSealAdapter` falls back to `GhostSeal` and
logs a warning; `NODE_PROFILE=production` refuses to boot.

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
