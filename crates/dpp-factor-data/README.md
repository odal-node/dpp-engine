# dpp-factor-data

The storage layer for licensed life-cycle inventory (LCI) emission factors, such as
ecoinvent, EF or Sphera datasets, behind `dpp-calc`'s `FactorProvider` trait. Part
of [dpp-engine](../../README.md), under the Business Source License 1.1.

> [!NOTE]
> **Status: planned.** No dataset is licensed, and no crate in the workspace depends
> on this one. It ships a stub provider and the storage types only.

## What is here

| Item | Purpose |
|---|---|
| `GhostFactorProvider` | A stub that answers `FactorNotFound` for every lookup |
| `FactorStore` | The trait a real provider loads factor tables through |
| `FactorDatasetManifest` | Describes a dataset (name, version, table hash) without containing it |

## Why it is a separate crate

`dpp-calc` (Apache-2.0) holds the calculation methods and the `FactorProvider`
trait. Licensed factor tables come with redistribution terms that bind regardless of
this repository's licence, so they are kept out of both repositories:

- Loader code, manifest types and stub providers may live here.
- Raw factor tables, or any data derived from a licensed dataset, may not be
  committed anywhere, encrypted or not. They are loaded at runtime from operator
  storage.
- No API returns raw factors. A calculation result may carry the dataset's
  `table_hash` so it can be reproduced against the same table.

A real provider becomes useful once a calculation that needs LCI data runs on the
publish path. In `dpp-calc` that is the carbon footprint calculation, which waits on
the delegated act under ESPR Art. 7(1).

## Licence

[Business Source License 1.1](../../LICENSE).
