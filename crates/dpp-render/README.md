# dpp-render

Renders a passport's public view as the HTML page a phone shows after scanning the
product's QR code. A pure function from JSON to `String`: no HTTP, no caching, no
signature checks and no redaction. Part of [dpp-engine](../../README.md), under the
Business Source License 1.1.

Two callers use it, so the live page and the pre-rendered continuity snapshot cannot
drift apart:

| Caller | When |
|---|---|
| `dpp-resolver` | `GET /dpp/{id}` with `Accept: text/html` |
| `dpp-node`'s snapshot drain | Pre-renders each published passport for the static continuity tier |

## See the output

```bash
cargo run -p dpp-render --example preview
```

This writes `dpp-render-preview-live.html` and `dpp-render-preview-snapshot.html`
(with the snapshot banner) from synthetic data. Keep the fixtures synthetic: no real
company, facility or product data in examples or tests.

## Page layout

1. **A curated section per product group** (`src/sections/`): named fields with units
   and a reading order, such as a battery's voltage and capacity, or a textile's fibre
   composition bar.
2. **A remainder table** (`src/remainder.rs`) of every public `productGroupData`
   field the curated section did not show. It is computed from the data, so a field
   added to a product group schema in `dpp-core` appears on the page with no change
   here.
3. **The QR code** for the passport's GS1 Digital Link (`src/carrier.rs`).

Every interpolated value goes through `esc.rs`.

## Input must already be redacted

`render_page` renders whatever JSON it is given; with the remainder table, that
means every key in `productGroupData`. The caller must pass the public view produced
by `dpp-vault`'s `public_view`, which applies `dpp-core`'s disclosure policy once,
at publish. Do not add filtering here: a second disclosure policy is the defect
`public_view` exists to prevent.

The same rule applies to test fixtures. A hand-written fixture containing a
restricted field (for example `batchId`, which is not public) will render here
without error, because this crate trusts its input. Build fixtures from the public
view, not from a full passport.

## Modules

```text
src/
├── lib.rs         render_page, build_qr_svg, carrier_uri
├── page.rs        the HTML document and the snapshot banner
├── sections/      one curated section per product group, and the dispatch
├── remainder.rs   the table of public fields no section shows
├── fields.rs      field extraction and formatting helpers
├── carrier.rs     GS1 Digital Link URI for the QR code
└── esc.rs         HTML escaping
```

## Licence

[Business Source License 1.1](../../LICENSE).
