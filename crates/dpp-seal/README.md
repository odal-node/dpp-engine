# dpp-seal

eIDAS qualified electronic seal adapter for [Odal Node](https://odal-node.io).

Implements `SealPort` (from `dpp-domain::ports::seal`) over one of three
backends, selected by `SEAL_PROVIDER`: **eID Easy Cloud Direct e-Sealing**, which
aggregates qualified QTSPs and returns **CAdES**; a **local** development sealer;
or `GhostSeal` when nothing is configured. Only the first carries legal weight,
and a production node refuses to boot on either of the others.

> **Not yet exercised against the live provider.** Every code path is built and
> tested against a local mock; the sandbox test is blocked on eID Easy enabling
> test e-seal credentials for our client.

## What ships

| Component | Status |
|---|---|
| `backend::SealBackend` | The seam each backend implements |
| `QtspSealAdapter` | `SealPort` over one `dyn SealBackend`; names none of them |
| `config::SealProvider` | Which backend this node runs, resolved from the environment |
| `eideasy::` | The hosted QTSP backend: config (host allowlist, redacting `Debug`), HMAC-signed POST to `/api/signatures/e-seal`, wire types, and its own typed errors |
| `local::` | A real detached CMS `SignedData` under a self-signed P-256 key |
| `ghost::` | `GhostSeal` as a backend — synthetic envelopes, no legal validity |
| `error::SealError` | Config / transport / backend / unsupported — nothing provider-shaped |

Each backend owns its module entirely: its variables, its validation, its failure
messages, its wire types, and its own construction. Nothing outside a backend's
module names it, so one can be added or dropped without touching the others.

`verify()` is **not** implemented for the hosted backend and says so, returning a
typed error. It is the `SealBackend` default, so a new backend refuses by
construction and has to override it to claim otherwise.

The reason is independence, not tooling. A qualified seal is worth exactly as
much as the independence of whoever checked it, so a verdict this node issues on
a seal this node bought attests nothing a relying party should accept — validate
those elsewhere. Rust AdES libraries exist and are improving; none of that
changes the answer.

**The local backend does verify**, and overrides the default to say so, because
neither objection applies to it: its seals make no trust claim beyond "this key
signed this digest", so a cryptographic check is the whole truth about them and
there is no authority whose independence could be borrowed. It carries the sealed
digest in CMS `signedAttrs` — as CAdES requires — which is what makes the
envelope self-checking; a verifier holding only the bytes can confirm the
signature over those attributes against the certificate travelling inside. That
establishes internal consistency and nothing about trust: the certificate is
self-signed and on no EU Trusted List, which the node states structurally by
resolving this backend to the `Ghost` trust tier.

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
SEAL_PROVIDER=eideasy                              # `local`, or `none` (default) for GhostSeal
SEAL_EIDEASY_BASE_URL=https://test.eideasy.com     # sandbox; prod = https://id.eideasy.com
SEAL_EIDEASY_CLIENT_ID=...                         # from test.eideasy.com "My Webpages"
SEAL_EIDEASY_HMAC_KEY=...                          # generated once in Eseal Settings
SEAL_EIDEASY_SIGNATURE_PROFILE=CAdES_BASELINE_T    # optional; must be enabled for client

SEAL_LOCAL_KEY_PATH=./.seal-local                  # optional; only for SEAL_PROVIDER=local
```

`SEAL_PROVIDER` takes `eideasy`, `local` or `none`, and an unrecognised value
fails the boot. The selection is deliberately explicit rather than inferred from
whichever credentials happen to be present: a node that cannot name its trust
provider must not quietly become one that has none.

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

With no provider selected the node wires the ghost backend, which logs a warning
on every seal; `NODE_PROFILE=production` refuses to boot on it — and on the local
backend too, whose certificate is on no EU Trusted List.

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
