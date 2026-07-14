# dpp-engine fuzz targets

libFuzzer targets for the engine's hostile-input byte frontiers. Requires
**nightly + Linux** (libFuzzer is not available on the Windows dev box), so these
run in the nightly CI job — not in the stable `just check` gate.

## Targets

| Target | Fuzzes |
|---|---|
| `parse_csv` | `dpp_integrator::domain::csv_parser::parse_csv` — bulk-import CSV bytes |
| `verify_dossier_json` | `dpp_vault::domain::verify::verify_dossier_json` — evidence-dossier JSON |

## Run locally (Linux)

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run parse_csv -- -max_total_time=60
cargo +nightly fuzz run verify_dossier_json -- -max_total_time=60
```

> Local runs need the core dependency resolvable: either the published `dpp-core`
> crates, or the sibling `../dpp-core` checkout via `just core-local` (the
> `.cargo/config.toml` patch applies to this crate too, since config is discovered
> from the `dpp-engine` dir upward).

## Corpus & regressions

Seed corpora from existing fixtures (e.g. `ops/demo/*` CSVs, generated dossiers):

```sh
mkdir -p corpus/parse_csv corpus/verify_dossier_json
cp ops/demo/datasets/*.csv corpus/parse_csv/            2>/dev/null || true
```

A crash writes a reproducer to `artifacts/`. Minimize it (`cargo +nightly fuzz
tmin`) and commit the input as a named regression **unit test** in the crate it
broke — the corpus feeds the ordinary test suite.
