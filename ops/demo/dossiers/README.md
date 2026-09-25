# Demo Evidence Dossiers

Test dossiers for the evidence verifier: four that verify, four tampered in
different ways, two that are not dossiers at all. Built from the engine's own
types with real Ed25519 signing (not hand-crafted JSON) by
`crates/dpp-vault/examples/generate_demo_dossiers.rs`. Every operator, DID and
host in them is fictional.

`expected.json` holds `verify_dossier_json`'s verdict on each file, check by
check. `crates/dpp-vault/tests/demo_dossiers_verify.rs` fails when a file stops
getting that verdict, or when the **Expected** or **Fails** column below stops
matching it — so a format change that breaks this corpus breaks the build, not
the demo.

Try each with `odal verify <file>`, or the console's **Dossiers** menu item, in
`dpp-engine`. Both upload the file to the node `odal` is connected to
(`POST /api/v1/evidence/verify`), so a node has to be running; the verdict is
the node's. `odal verify` exits 0 when every check passes, 1 when one fails, and
2 when the node refuses the file as not a dossier.

## Dataset Index

| # | File | Expected | Fails | Purpose |
|---|------|----------|-------|---------|
| 01 | `01-valid-simple.json` | exit 0, VERIFIED | — | Minimal passport: created + published, no transfer, no EOL. `transfer_chain` correctly reports absent (not a failure). |
| 02 | `02-valid-with-transfer.json` | exit 0, VERIFIED | — | Adds a completed transfer of responsibility: the outgoing operator's `fromSignature` over the transfer terms, and the node's `nodeAcceptanceAttestation` over the acceptance it ran. |
| 03 | `03-valid-with-eol.json` | exit 0, VERIFIED | — | Adds an end-of-life audit entry and `eolEvent` (no transfer). |
| 04 | `04-valid-full-lifecycle.json` | exit 0, VERIFIED | — | Transfer + EOL both present. Base fixture the tampered variants below are derived from. |
| 05 | `05-tampered-signature.json` | exit 1, TAMPER | `public_view_signature` | One character flipped in `publicView.jws`. Every other check, including `content_integrity`, stays green: the manifest hashes the public view's payload, not its JWS. |
| 06 | `06-tampered-audit-entry.json` | exit 1, TAMPER | `content_integrity`, `audit_chain` | `auditEntries[0].action` changed post-signing. Both `audit_chain` (hash-chain break) and `content_integrity` (manifest hash mismatch) fire together — a realistic cascade, not surgically isolated. |
| 07 | `07-tampered-transfer-signature.json` | exit 1, TAMPER | `content_integrity`, `transfer_chain` | One character flipped in the transfer's `nodeAcceptanceAttestation`. It no longer verifies against the node's key, so `transfer_chain` fails, and `content_integrity` with it — same cascade pattern as 06. |
| 08 | `08-hidden-field-injection.json` | exit 1, TAMPER | `input_fidelity` | The subtle one: an unrecognized field (`certificationStatus`) injected inside `transferChain.transfers[0]` — a *tolerant* nested type (not `deny_unknown_fields`). It parses fine and is silently dropped, so every signature/hash check stays green. **Only `input_fidelity` catches it.** |
| 09 | `09-unknown-top-level-field.json` | exit 2, hard parse error | — | An unrecognized field (`verifiedBy`) at the dossier's own top level. `DossierV1` itself *is* `deny_unknown_fields`, so this never even produces a report — rejected before verification starts. Contrast with 08: same idea, different location, different severity. |
| 10 | `10-not-json.txt` | exit 2, hard parse error | — | Not JSON at all. |

## Demo Flow

### Scenario A: Happy path
```
odal verify ops/demo/dossiers/01-valid-simple.json
odal verify ops/demo/dossiers/04-valid-full-lifecycle.json
```
Both VERIFIED, exit 0. Second one exercises every present-and-checkable layer (manifest, both
signed views, audit chain, transfer chain, input fidelity).

### Scenario B: Obvious tamper (show it fails loudly)
```
odal verify ops/demo/dossiers/05-tampered-signature.json
```
`public_view_signature` FAILs, exit 1, everything else stays green — a single flipped byte is
caught and precisely localized.

### Scenario C: Cascading tamper (show related checks agree)
```
odal verify ops/demo/dossiers/06-tampered-audit-entry.json
odal verify ops/demo/dossiers/07-tampered-transfer-signature.json
```
Two checks fail together in each — the content-hash binding and the specific integrity check
both catch the same tamper from different angles. In 07 the broken signature is the node's
acceptance attestation, and the report says so: it names the acceptance, not the outgoing
operator's signature, which still verifies.

### Scenario D: The subtle one (why `input_fidelity` exists)
```
odal verify ops/demo/dossiers/08-hidden-field-injection.json
```
Every signature and hash check passes. Only `input_fidelity` — comparing canonical input bytes
against canonical re-serialized bytes — catches the silently-dropped injected field. This is
the check that exists specifically because top-level strictness alone can't see into nested
tolerant types.

### Scenario E: Malformed input (show the hard-failure path)
```
odal verify ops/demo/dossiers/09-unknown-top-level-field.json
odal verify ops/demo/dossiers/10-not-json.txt
```
Both exit 2 — rejected before a verification report is even produced.

## Regenerating

From the repository root:

```
cargo run -p dpp-vault --example generate_demo_dossiers -- ops/demo/dossiers
```

Rewrites every file here, `expected.json` included. The output is deterministic — fixed
keys, ids and timestamps — so an unchanged build reproduces it byte for byte. The manifests
record the node and `dpp-core` versions they were generated with, as a real dossier does, so
a version bump changes them; it does not make them fail to verify.

Never hand-edit a file: a tampered fixture edited by hand is how you get one that no longer
demonstrates what its row claims. If a regeneration changes a verdict, update the table in
the same commit.
