# Demo Evidence Dossiers

Test dossiers for the evidence verifier. Built from `dpp-evidence`'s real types with
real Ed25519 signing (not hand-crafted JSON) — see `crates/dpp-evidence/examples/generate_dataset.rs`.

Try each with `odal verify <file>` (stateless CLI) or the console's **Verify** menu item, in `dpp-engine`.

## Dataset Index

| # | File | Expected | Purpose |
|---|------|----------|---------|
| 01 | `01-valid-simple.json` | exit 0, VERIFIED | Minimal passport: created + published, no transfer, no EOL. `transfer_chain` correctly reports N/A (absent, not a failure). |
| 02 | `02-valid-with-transfer.json` | exit 0, VERIFIED | Adds a signed transfer-of-responsibility record. |
| 03 | `03-valid-with-eol.json` | exit 0, VERIFIED | Adds an end-of-life audit entry (no transfer). |
| 04 | `04-valid-full-lifecycle.json` | exit 0, VERIFIED | Transfer + EOL both present. Base fixture the tampered variants below are derived from. |
| 05 | `05-tampered-signature.json` | exit 1, TAMPER | One character flipped in `publicView.jws`. Only `public_view_signature` fails — every other check, including `content_integrity`, stays green (the JWS isn't part of the content-hash binding). |
| 06 | `06-tampered-audit-entry.json` | exit 1, TAMPER | `auditEntries[0].action` changed post-signing. Both `audit_chain` (hash-chain break) and `content_integrity` (manifest hash mismatch) fire together — a realistic cascade, not surgically isolated. |
| 07 | `07-tampered-transfer-signature.json` | exit 1, TAMPER | One character flipped in the transfer's `toSignature`. `transfer_chain` and `content_integrity` both fail, same cascade pattern as 06. |
| 08 | `08-hidden-field-injection.json` | exit 1, TAMPER | The subtle one: an unrecognized field (`certificationStatus`) injected inside `transferChain.transfers[0]` — a *tolerant* nested type (not `deny_unknown_fields`). It parses fine and is silently dropped, so every signature/hash check stays green. **Only `input_fidelity` catches it.** |
| 09 | `09-unknown-top-level-field.json` | exit 2, hard parse error | An unrecognized field at the dossier's own top level. `DossierV1` itself *is* `deny_unknown_fields`, so this never even produces a report — rejected before verification starts. Contrast with 08: same idea, different location, different severity. |
| 10 | `10-not-json.txt` | exit 2, hard parse error | Not JSON at all. |

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
both catch the same tamper from different angles.

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

```
cd dpp-core
cargo run -p dpp-evidence --example generate_dataset -- ops/demo/dossiers
```
