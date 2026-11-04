# Evidence dossier, format v1

An evidence dossier is a single signed JSON document holding everything needed to
check a passport's proof chain offline: the signed payloads, the DID documents that
verify them, the hash-chained audit trail, the transfer chain and the seal.

```bash
odal passport evidence <passport-id> -o dossier.json   # generate and store
odal verify <dossier-id>                                # verify a stored dossier
odal verify dossier.json                                # verify a file
```

| Operation | Route |
|---|---|
| Generate and store | `POST /vault/api/v1/dpp/{id}/evidence` (write scope) |
| List for a passport | `GET /vault/api/v1/dpp/{id}/evidence` |
| Fetch one | `GET /vault/api/v1/evidence/{id}` |
| Verify a stored dossier | `POST /vault/api/v1/evidence/{id}/verify` |
| Verify an uploaded dossier | `POST /vault/api/v1/evidence/verify` |

`formatVersion` is `"1"`. The machine-readable schema is
[`evidence-dossier-v1.schema.json`](evidence-dossier-v1.schema.json); the reference
verifier is `crates/dpp-vault/src/domain/verify/engine.rs`; the wire types are in
`crates/dpp-types/src/evidence.rs`.

## Members

| Field | Type | Contents |
|---|---|---|
| `manifest` | `DossierManifest` | Signed metadata that binds every other member (below) |
| `manifestJws` | string | Compact EdDSA JWS over the JCS-canonical bytes of `manifest` |
| `fullView` | `SignedLayer` | The full passport payload exactly as signed, and its JWS |
| `publicView` | `SignedLayer` | The public (redacted) payload exactly as signed, and its JWS |
| `didDocuments` | map of DID to DID document | Every DID document needed to verify the signatures: the issuer's, and any transfer counterparties' |
| `auditEntries` | `PassportAuditEntry[]` | The full hash-chained audit trail, oldest first |
| `transferChain` | `TransferChain`, optional | Present when responsibility for the passport has ever been transferred |
| `eolEvent` | object, optional | Present when end of life was declared |
| `checkpoint` | object | Always `null` in v1: signed checkpoints are not built yet |
| `calcReceipts` | array | Always `[]` in v1: calculations are not yet recorded in the dossier |
| `componentGraph` | object, optional | The component-tree (bill of materials) verification report. Present when the passport has `componentRefs` |
| `qualifiedSeal` | object, optional | The eIDAS seal over the full-view signature, with `signedOverJws` and `payloadHash` so it can be checked from this document alone. Present only when the passport carries a seal. The seal is stripped from every audience view, so the dossier is the place it travels with its preimage |

### `DossierManifest`

| Field | Contents |
|---|---|
| `formatVersion` | `"1"` |
| `passportId` | The passport |
| `issuerDid` | The operator's `did:web` DID, which signed `manifest`, `fullView` and `publicView`. Transfer records carry their own signer DIDs |
| `createdAt` | When the dossier was assembled |
| `nodeVersion` | The engine version that produced it |
| `rulesetVersion` | The ruleset version, when a compliance determination ran |
| `contentHashes` | Member name to hex SHA-256 of that member's JCS-canonical bytes |

### `SignedLayer`

`{ payload, jws }`: the exact JSON value that was signed, and the JWS over it.

The verifier does not reconstruct the signed payload from the passport record. A
passport's `status` changes after publish (suspend, retire, end of life) without
re-signing, so a payload rebuilt from the current record would no longer match the
signature, and a legitimate passport would be reported as tampered. Embedding the
signed payload means the verifier only checks that the signature covers this payload.

## The checks

`odal verify` and the verify routes run these checks and print one line per check.

| Check | Passes when |
|---|---|
| `manifest_signature` | `manifestJws` verifies against the issuer's DID document |
| `content_integrity` | Every member's SHA-256 matches `manifest.contentHashes` |
| `full_view_signature` | `fullView.jws` covers `fullView.payload` |
| `public_view_signature` | `publicView.jws` covers `publicView.payload` |
| `audit_chain` | The audit hash chain is unbroken |
| `transfer_chain` | Every transfer record's signatures verify. Not applicable without a chain |
| `checkpoint` | Not applicable in v1 |
| `calc_receipts` | Not applicable in v1 |
| `component_graph` | The embedded tree report shows no integrity violation. A component that was unreachable when the dossier was built is reported as incomplete, not failed |
| `qualified_seal` | The seal covers the JWS it is served with, recomputed from `signedOverJws` rather than read from the dossier's own `payloadHash`. Not applicable without a seal |
| `input_fidelity` | The canonical bytes of the input equal the canonical bytes of the parsed dossier (below) |

Exit codes: `0` every check passed or was not applicable, `1` a check failed, `2` the
input could not be read or parsed. The verify routes answer `422` for input that
cannot be parsed.

### Why the manifest hashes every member

Each member can be verified on its own, but that alone would allow mixing genuinely
signed members from two generations of the same passport: for example, a current
`fullView` with an older `auditEntries` that omits a later suspension. Each signature
would still verify. `contentHashes` is inside the signed manifest, so replacing any
member, even with another genuinely signed one, changes its hash and fails
`content_integrity`.

### Why `input_fidelity` exists

The dossier's own types (`DossierV1`, `DossierManifest`, `SignedLayer`,
`PassportAuditEntry`) reject unknown fields. Some members are not strict:
`didDocuments`, `checkpoint` and `calcReceipts` are untyped JSON, and
`transferChain` uses `dpp-core` domain types that tolerate unknown fields elsewhere.
An unknown field nested there would be dropped silently while parsing, and because
content hashes are computed from the parsed structure, no hash would change.
`input_fidelity` compares the canonical bytes of the raw input with the re-serialised
parse, so content lost anywhere in the tree fails the check.

This is why every optional field is omitted when absent rather than written as
`null`: the round trip must reproduce the input byte for byte.

## Trust model

A passing report shows that:

- no member changed since the dossier was generated;
- every signature covers exactly the payload it is paired with;
- the audit trail's hash chain is unbroken, and every transfer signature is valid;
- the members belong together.

Trust is anchored in the DID documents embedded at generation time; the report's
`trustAnchorNote` says so and gives the snapshot date. The check does not confirm
those keys are still the operator's current keys, and running it through the
issuing node's API does not make the node an independent party.

**Limit:** a dossier cannot show that the issuing operator did not rewrite its own
audit history before generating it. An operator that rebuilds its hash chain from
the first entry produces a dossier that is internally consistent. Detecting that
needs an independent record of the chain head at an earlier time, which is what the
`checkpoint` member is reserved for. Until checkpoints exist, a dossier is
tamper-evident against everyone except its issuer.

## Versioning

A breaking change increments `formatVersion`. A verifier that meets an unknown
`formatVersion`, or any field it does not understand, refuses the dossier as
malformed (exit code 2) instead of attempting a partial check.
