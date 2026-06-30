# Demo Datasets

Test datasets for the Odal Node DPP demo. Run each with `dpp import <file>` then `dpp validate`.

## Dataset Index

| # | File | Rows | Purpose | Expected Result |
|---|------|------|---------|-----------------|
| 01 | `01-textile-small-valid.csv` | 5 | Happy path — small batch | All import OK, all validate OK |
| 02 | `02-textile-large-valid.csv` | 30 | Larger catalog — varied products | All import OK, all validate OK |
| 03 | `03-textile-missing-fields.csv` | 9 | Missing required fields | Import may succeed (lenient), validate catches all |
| 04 | `04-textile-malformed-json.csv` | 9 | Broken fibreComposition JSON | Import fails on rows OR fibre defaults to empty |
| 05 | `05-textile-invalid-gtin.csv` | 7 | Bad GTIN formats + 1 valid control | Import may succeed, validate catches GTIN errors |
| 06 | `06-textile-wrong-sector.csv` | 5 | Wrong/missing/typo sector values | Sector mismatch errors or unknown sector |
| 07 | `07-textile-encoding-edge-cases.csv` | 8 | Unicode, emojis, long strings, commas | Tests UTF-8 handling and CSV escaping |
| 08 | `08-textile-duplicate-gtins.csv` | 5 | Same GTIN on multiple products | Tests uniqueness enforcement |
| 09 | `09-battery-valid.csv` | 10 | Battery sector — valid data | All OK (different sector demo) |
| 10 | `10-battery-faulty.csv` | 10 | Battery sector — broken data | Various validation failures |
| 11 | `11-mixed-sectors.csv` | 5 | Textile + battery in one file | Tests multi-sector import |
| 12 | `12-textile-tab-separated.tsv` | 3 | TSV format (tab delimiter) | Tests delimiter handling |
| 13 | `13-textile-semicolon-separated.csv` | 3 | European CSV (semicolon delimiter) | Tests delimiter handling |
| 14 | `14-textile-snake-case-headers.csv` | 3 | snake_case column names | Tests header aliasing |
| 15 | `15-textile-100-products.csv` | 100 | Stress test — full catalog | All OK, tests performance |
| 16 | `16-empty-file.csv` | 0 | Header only, trailing newline | "No data rows found" message |
| 17 | `17-header-only.csv` | 0 | Header only, no newline | "No data rows found" message |

## Demo Flow

### Scenario A: Happy Path (Customer brings clean data)
```
dpp import 01-textile-small-valid.csv
dpp validate
odal publish
```

### Scenario B: Customer data has errors (show validation catches them)
```
dpp import 03-textile-missing-fields.csv
dpp validate                              # Shows exactly which fields are missing
# Fix the CSV → re-import
```

### Scenario C: Large catalog (show speed)
```
dpp import 15-textile-100-products.csv    # Should complete in 2-3 seconds
dpp validate
odal publish
```

### Scenario D: Multi-sector (show we handle more than textile)
```
dpp import 09-battery-valid.csv
dpp validate
odal publish
```

### Scenario E: Bad data formats (show resilience)
```
dpp import 04-textile-malformed-json.csv  # Shows per-row error reporting
dpp import 05-textile-invalid-gtin.csv    # Shows GTIN validation
```
