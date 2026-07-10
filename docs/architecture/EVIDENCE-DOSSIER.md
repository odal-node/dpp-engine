# Evidence Dossier — format v1

The evidence dossier is a self-contained, signed snapshot of a passport's full
proof chain. It is generated and persisted by `POST /dpp/{id}/evidence`, listed
and fetched via `GET /dpp/{id}/evidence` / `GET /evidence/{id}`, and verified —
either a stored dossier (`POST /evidence/{id}/verify`) or an uploaded document
(`POST /evidence/verify`) — by the checks in `dpp-vault`'s `domain::verify`
module. The `odal verify <dossier-id | file>` CLI command drives the same two
verify endpoints.

`format_version` is currently `"1"`. This document describes that version.

## Members

| Field | Type | Meaning |
|---|---|---|
| `manifest` | `DossierManifest` | Signed metadata binding every other member into one atomic unit. |
| `manifestJws` | string | Compact EdDSA JWS over the JCS-canonical bytes of `manifest`. |
| `fullView` | `SignedLayer` | The full (non-redacted) passport payload as it was actually signed, plus that signature. |
| `publicView` | `SignedLayer` | The public (redacted) passport payload as it was actually signed, plus that signature. |
| `didDocuments` | map\<DID, DID document\> | Snapshot of every DID document needed to verify every signature in the dossier — the issuer's own, plus any transfer-chain counterparties'. |
| `auditEntries` | `AuditEntry[]` | The full hash-chained audit trail, oldest first. |
| `transferChain` | `TransferChain?` | Present iff the passport has ever changed responsible operator. |
| `eolEvent` | object? | Present iff the passport was declared end-of-life. |
| `checkpoint` | object? | **Always `null` in v1** — the signed-checkpoint layer is not yet built. |
| `calcReceipts` | array | **Always `[]` in v1** — `dpp-calc` invocation is not yet wired end to end (pending a licensed emission-factor data source). |

### `DossierManifest`

| Field | Meaning |
|---|---|
| `formatVersion` | `"1"`. |
| `passportId` | The passport this dossier is for. |
| `issuerDid` | The `did:web` DID that signed `manifest`, `fullView`, and `publicView` — the node operator's own identity. Transfer-chain signatures carry their own signer DIDs on each record instead. |
| `createdAt` | When this dossier was assembled. |
| `nodeVersion` | The engine version that produced it. |
| `rulesetVersion` | The `dpp-calc` ruleset version, when a determination ran. Omitted for passthrough-only passports. |
| `contentHashes` | map\<member name, hex SHA-256\> — see below. |

### `SignedLayer`

`{ payload, jws }` — the exact JSON value that was signed, alongside the JWS over it. The dossier embeds this pair directly rather than have a verifier reconstruct "what should have been signed": engine-side transforms (e.g. the full-view payload forces `status` to `"active"`; the public-view payload is redacted) are engine-internal, and reconstructing them independently is both extra surface for the two sides to disagree on and, in practice, was found to be a source of a real bug (see "Why `SignedLayer` embeds the payload" below).

## Why the manifest hashes every member (`contentHashes`)

Each member is independently verifiable on its own — its own JWS, or its own hash chain. That is not sufficient by itself: without a binding mechanism, an attacker could mix genuinely-signed-but-stale members from two different generations of the *same* passport — for example, pairing a current, validly-signed `fullView` with an older `auditEntries` array that omits a later suspension event. Each individual signature would still verify.

`manifest.contentHashes` is a map from member name to the hex SHA-256 of that member's JCS-canonical bytes. Because the manifest itself is signed (`manifestJws`), tampering with any member's content — even by swapping in another genuinely-signed artifact — is caught: the recomputed hash won't match what the signed manifest commits to.

## Why `SignedLayer` embeds the payload

An earlier version of this format had the verifier reconstruct the full/public view payloads from the passport record itself. This was found to be unreliable: `jws_signature`/`public_jws_signature` are frozen at publish time, but a passport's `status` (and other fields) mutate afterward on suspend/archive/end-of-life — those transitions never re-sign. A verifier reconstructing "the current record" would produce a payload that no longer matches what was actually signed, and falsely report tamper on a perfectly legitimate, unmodified signature. Embedding the exact signed payload sidesteps this: verification only has to confirm the signature covers *this* payload, never derive what the payload should be.

## Trust model

Verification is an integrity check of a dossier — stored or uploaded — against its own signatures and hash chains. A green report proves: no member was altered since the dossier was generated; every signature covers exactly the payload it's paired with; the audit trail's hash chain is unbroken; every present transfer-chain signature is valid; the whole bundle is atomically bound (no mix-and-match).

Trust is anchored to the DID documents embedded in the dossier at generation time — the report's `trustAnchorNote` states this and the snapshot date explicitly. This is honest, not exhaustive: it does not independently confirm those DID documents are still the operator's *real*, current keys, and running the check through this node's own API does not make the node a disinterested third party.

What it does not prove, in any case: that the *issuing* operator didn't rewrite their own audit history before generating the dossier. An operator who regenerates their entire hash chain from genesis with altered content produces a dossier that is internally, perfectly self-consistent. Closing this requires an independent observation of the chain head at an earlier point in time — the signed-checkpoint layer (`checkpoint`, currently always `null`) exists for exactly this and is not yet built. Anyone relying on a dossier for a high-stakes claim should know the honest line: *tamper-evident against everyone except the issuer, until checkpoints ship.*

## Strictness

Every dossier-owned type (`DossierV1`, `DossierManifest`, `SignedLayer`, `AuditEntry`) rejects unknown fields at deserialization. An unrecognised field anywhere in one of these types is treated as malformed input (`odal verify` exit code 2 / HTTP 422 from the verify endpoints), not silently ignored — it may mean the dossier was produced by a newer format version this verifier doesn't understand, and a verifier must never silently pass over content it didn't check.

This alone is not sufficient: `didDocuments`, `checkpoint`, and `calcReceipts` are untyped JSON by design (forward-compatible placeholders), and `transferChain` embeds `dpp-domain` types (`TransferChain`, `TransferRecord`, `ResponsibleOperator`) that are *not* strict, because they are core domain types shared with contexts where tolerance is correct. An unknown field nested inside one of those would parse successfully and be silently dropped by serde — and because content hashes are computed from the *parsed* structure, the dropped content would not be reflected in a hash mismatch either.

`verify_dossier_json` closes this gap with a 9th check, **`input_fidelity`**: it compares the canonical (JCS) bytes of the raw input against the canonical bytes of the parsed dossier, re-serialized. Any content lost anywhere in the tree — not just in the strict types — fails this check.

**Corollary rule: optional fields are omitted, never emitted as explicit `null`.** Every optional field in this format uses `skip_serializing_if`, so a value that's genuinely absent doesn't appear in the JSON at all. This is what makes the fidelity round-trip exact — an explicit `"field": null` versus an omitted field would otherwise be indistinguishable content that still produces different canonical bytes.

## Versioning

A breaking change to this format bumps `format_version`. A verifier that doesn't recognise a `format_version` (or, per the strictness rule above, encounters any field it doesn't understand) must refuse the dossier as malformed rather than attempt a best-effort partial verification. An honest refusal ("this dossier may require a newer verifier") is always the correct failure mode — never a false green.

## See also

- [`evidence-dossier-v1.schema.json`](evidence-dossier-v1.schema.json) — machine-readable JSON Schema for this format.
- `crates/dpp-vault/src/domain/verify/engine.rs` — the reference implementation of every check described above.
- `crates/dpp-types/src/evidence.rs` — the wire format and persistence types.
