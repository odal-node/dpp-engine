# dpp-render

Shared HTML rendering of the public passport view for [Odal Node](https://odal-node.io).

`dpp-render` is a pure `passport JSON -> String` renderer: no HTTP, no caching, no
signature verification, and no field-level redaction. It exists so the live
resolver read and the continuity tier's pre-rendered snapshot go through **one**
renderer — a second implementation is exactly how the static tier would drift
from what the resolver serves.

---

## When to use this crate

- You are changing what the public passport HTML page looks like (layout, QR
  code, a sector's table).
- You are adding rendering support for a new EU DPP sector.
- You are wiring up a new place that needs to turn a passport's public view
  into HTML (today: `dpp-resolver`'s live handler and `dpp-node`'s snapshot drain).

## What this crate does *not* do

`render_page` renders whatever `serde_json::Value` it is given — it performs
no filtering of its own. The caller is responsible for passing the
already-redacted **Public**-tier view; see `dpp-vault::public_view`, which is
the single source of truth for which fields are public per sector (via
`dpp-domain`'s `SectorCatalog` / `AccessTier`). In practice this crate stays
leak-safe by construction: each section builder (`src/sections/*.rs`) reads
named fields off `sectorData` individually rather than serializing it
wholesale, so a field a section never names is never rendered regardless of
what the input JSON contains — see the `..._is_never_rendered` tests in
`src/sections/textile.rs` and `src/page.rs` for that guarantee in force.

**This means test/example fixtures in this crate must be shaped like a real
Public-tier view, not a full passport.** It's easy to hand-write a fixture
that "looks public" but includes a field the redaction step would actually
strip — that field will render here with no error, because this crate trusts
its input. Two fields most likely to be gotten wrong, per
`SectorAccessPolicy::passport_default` (`dpp-core/crates/dpp-crypto/src/access/policy.rs`):

| Field | Tier | Why |
|---|---|---|
| `batchId` | Professional | Mutable after publish; a `Public` field is part of the signed payload, so anything re-writable post-publish can't sit there without breaking signature verification. |
| `lintResult` | Professional | Advisory QA output, restamped on every re-run; same signed-payload-must-be-stable reasoning, plus it's operator/auditor-facing, not consumer-facing. |
| `jwsSignature`, `retentionLocked` | Confidential | Internal/signature bookkeeping. |

Sector-specific fields are gated per-sector in
`dpp-core/crates/dpp-domain/sectors/*.json`'s `accessTiers`. Audited against
every field each `src/sections/*.rs` builder actually reads (2026-07-19) —
none of them currently name a gated field:

| Sector | Professional/Confidential fields (catalog) |
|---|---|
| aluminium | *(none — all Public)* |
| battery | `dueDiligenceUrl`, `criticalRawMaterials`, `disassemblyInstructionsUrl`, `cathodeMaterial`, `anodeMaterial`, `electrolyteMaterial`, `sohMethodology` |
| construction | `epdUrl` |
| detergent | *(none — all Public)* |
| electronics | `svhcSubstances`, `disassemblyInstructionsUrl`, `repairManualUrl`, `criticalRawMaterials` |
| furniture | `svhcSubstances`, `disassemblyInstructionsUrl` |
| steel | *(none — all Public)* |
| textile | `svhcSubstances`, `disassemblyInstructions`, `sparePartsAvailable` |
| toy | `svhcSubstances` |
| tyre | *(none — all Public)* |
| unsold-goods † | `operatorName`, `destructionJustification` |

† `sections/mod.rs` dispatches this sector by the literal tag `"unsoldGoods"`,
which does not match the catalog's key (`"unsold-goods"`) — a pre-existing
naming mismatch, not introduced here, worth resolving separately.

This table is a point-in-time audit, not a runtime guarantee — it will drift
the moment a section builder or a sector manifest changes without the other
being re-checked. Re-verify it whenever you add a field to a section builder
or bump a sector's `accessTiers`.

---

## Module structure

```
src/
├── lib.rs        Crate docs; re-exports render_page, build_qr_svg, carrier_uri
├── page.rs        render_page — the full HTML document; SnapshotNotice banner
├── carrier.rs      GS1 Digital Link URI construction for the QR code
├── esc.rs          HTML escaping — every interpolated field goes through this
└── sections/       One file per EU DPP sector's HTML table (aluminium, battery,
                     construction, detergent, electronics, furniture, steel,
                     textile, toy, tyre) + mod.rs's sector dispatch
```

## Seeing the output

There's no bin, dev server, or Docker setup for this crate — it's a pure
function library. To eyeball a rendered page in a browser:

```
cargo run -p dpp-render --example preview
```

This writes `dpp-render-preview-live.html` and `dpp-render-preview-snapshot.html`
(the live and continuity-snapshot-banner variants) using synthetic fixture
data. Keep that fixture synthetic — this is the crate that produces the
public-facing page, so no real partner, facility, or product data belongs in
it, in examples or in tests.

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-digital-link` | `short_serial` + `build_qr_url` — builds the GS1 Digital Link this crate's QR encodes |
| `dpp-vault` | Produces the redacted Public-tier view this crate renders (`public_view.rs`) |
| `dpp-resolver` | Calls `render_page` live for `GET /dpp/{id}` with `Accept: text/html` |
| `dpp-node` | Calls `render_page` from the snapshot drain to pre-render the continuity tier |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
