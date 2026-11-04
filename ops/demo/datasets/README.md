# Demo datasets

Bulk-import fixtures, valid and deliberately broken. Run each with
`odal passport import <file>`, then `odal passport validate`, then
`odal passport publish`.

## Product group column

The importer picks the row validator from a **`productGroup`** column
(`productCategory` / `product_category` are also accepted, matched
case-insensitively). It is read once, from the first data row, for the whole
file; there is no per-row product group. The value must be a product group the
importer supports: `battery`, `textile`, `steel`, `aluminium`, `tyre`, `mattress`,
`furniture`, `toy`, `construction`, `electronics` or `detergent`.

A file whose column is still headed `sector` (the old name) is not detected.

## Index

| # | File | Rows | Purpose | Expected result |
|---|------|------|---------|-----------------|
| 01 | `01-textile-small-valid.csv` | 5 | Happy path, small batch | All import OK, validate OK, publish OK |
| 02 | `02-textile-large-valid.csv` | 30 | Larger catalogue, varied products | All import OK, validate OK, publish OK |
| 03 | `03-textile-missing-fields.csv` | 9 | Missing required fields | Import lenient; validate flags every gap |
| 04 | `04-textile-malformed-json.csv` | 9 | Broken `fibreComposition` JSON | Per-row import errors OR fibre defaults empty |
| 05 | `05-textile-invalid-gtin.csv` | 7 | Bad GTIN formats + 1 valid control | Import rejects bad GS1 checksums per row |
| 06 | `06-textile-wrong-sector.csv` | 5 | Wrong / missing / typo `productGroup` values | Whole-file detection uses row 1 (`textile`); the odd values on later rows are not honoured per-row |
| 07 | `07-textile-encoding-edge-cases.csv` | 8 | Unicode, emoji, long strings, embedded commas | UTF-8 + CSV escaping |
| 08 | `08-textile-duplicate-gtins.csv` | 5 | Same GTIN on multiple products | Delta-import identity matching |
| 09 | `09-battery-valid.csv` | 10 | Battery, basic columns | Import OK. `portable` rows publish; `ev`, `industrial` and `lmt` rows stay drafts (see below) |
| 10 | `10-battery-faulty.csv` | 10 | Battery, broken data | Per-row import / validation failures |
| 11 | `11-mixed-sectors.csv` | 5 | Textile and battery in one file | Detection is whole-file, so the battery rows are validated as textile |
| 12 | `12-textile-tab-separated.tsv` | 3 | TSV (tab delimiter) | Delimiter auto-detect |
| 13 | `13-textile-semicolon-separated.csv` | 3 | European CSV (semicolon delimiter) | Delimiter auto-detect |
| 14 | `14-textile-snake-case-headers.csv` | 3 | `snake_case` column names (`product_category`) | Header aliasing |
| 15 | `15-textile-100-products.csv` | 100 | Larger import | All OK; above the 100-row threshold an import runs as a background job |
| 16 | `16-empty-file.csv` | 0 | Truly empty | "file is empty or has no header row" |
| 17 | `17-header-only.csv` | 0 | Header, no data rows | "No data rows found" |
| 18 | `18-battery-extended.csv` | 10 | Industrial batteries with the extended column set: weight, up to three materials, recycled content, operating temperatures, due-diligence URL | Import OK; rows stay drafts (industrial needs the full Annex XIII set) |

## Batteries: what a CSV can and cannot carry

`validate_battery_row` maps about 38 columns, envelope columns included (`batteryChemistry`, voltages, capacity,
`recycledContent*Pct`, `batteryWeightKg`, `operatingTemp*`, `carbonFootprintClass`,
`dueDiligenceUrl`, `batteryType`, `material_N_*`, `placedOnMarketDate`,
`commodityCode` and others). Every Annex XIII point 1 to 4 field is left `null`.

The publish gate (`Passport::check_mandatory_content`) requires the full
per-category Annex XIII set for `ev`, `lmt` and `industrial` batteries: 30 to 40
fields a CSV cannot express. Those rows import and can be inspected as drafts,
but `publish` will reject them until the content is supplied.

**Fully-populated, publishable battery passports live in
[`../passports/`](../passports/)** (JSON, one file per category) with a
`load.sh` that creates and publishes them.

## Demo flow

```sh
# A: happy path
odal passport import ops/demo/datasets/01-textile-small-valid.csv
odal passport validate
odal passport publish

# B: validation catches errors
odal passport import ops/demo/datasets/03-textile-missing-fields.csv
odal passport validate            # names every missing field, per row

# C: a background import job
odal passport import ops/demo/datasets/15-textile-100-products.csv

# D: batteries with full Annex XIII content (JSON, not CSV)
ODAL_API_KEY=odal_sk_... ops/demo/passports/load.sh

# E: broken input
odal passport import ops/demo/datasets/04-textile-malformed-json.csv
odal passport import ops/demo/datasets/05-textile-invalid-gtin.csv
```
