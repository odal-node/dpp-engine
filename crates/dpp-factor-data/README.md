# dpp-factor-data

> **Not yet wired.** This crate exists as a stub. `dpp-node` does not load it yet;
> it will be injected into the calculation pipeline once a dataset licence is signed
> and the S3-backed factor store is stood up.

Licensed LCI emission factor data store for [Odal Node](https://odal-node.io).

Implements `dpp_calc::FactorProvider` for licensed datasets (ecoinvent, EF 3.1,
Sphera). The `dpp-calc` crate defines the open methodology and trait; this crate
holds the proprietary data layer so no licensed bytes ever appear in the
Apache-2.0 `dpp-calc` crate.

## What ships now

Only `GhostFactorProvider` (returns `FactorNotFound` for every lookup) plus the
supporting types `FactorDatasetManifest` and the `FactorStore` trait.
No ecoinvent or EF data is bundled.

## What comes later

Before enabling the real `LicensedFactorProvider`, the following must be resolved

1. Which dataset(s) to license first — ecoinvent, EF 3.1, or Sphera?
2. Does the licence permit a managed multi-operator service?
3. KMS availability: cloud SSE-KMS vs client-side `aes-gcm` envelope?
4. Confirm with counsel that returning *computed* CO₂e + `table_hash` (not raw factors) is outside the "automated redistribution" prohibition.

## Storage model (future)

```
s3://odal-factordata-<operator>/
  ecoinvent-3.10/table.bin.enc     (AES-GCM encrypted factor table)
  ecoinvent-3.10/manifest.json     (FactorDatasetManifest)
  licenses/ecoinvent-3.10.pdf.enc  (signed licence document, encrypted)
```

Encrypted with KMS envelope encryption (SSE-KMS on cloud; client-side `aes-gcm` for self-hosted).
The `FactorStore` trait decrypts into memory, never writes plaintext to disk.

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-calc` (core, Apache-2.0) | Defines `FactorProvider` trait + open calculators; never touches licensed data |
| `dpp-node` | Boots with `GhostFactorProvider`; swaps in real provider when store is configured |

## Licence warning

**DO NOT** bundle or expose raw factor tables in any crate or over any API.
The `table_hash` in `CalculationReceipt` is the only licensed-data artefact
that may be shared externally.

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
