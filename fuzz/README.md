# dpp-engine fuzz targets

libFuzzer targets for the places where bytes from outside reach the engine. They need
**nightly Rust on Linux** (libFuzzer does not support Windows), so they run in the nightly
CI job rather than in `just check`.

## Targets

Every target holds the same property: any input returns, never a panic. Some hold a
second property as well, given in the table.

| Target | Fuzzes | Where the bytes come from |
|---|---|---|
| `parse_csv` | `csv_parser::parse_csv` | An uploaded CSV |
| `parse_xlsx` | `xlsx_parser::parse_xlsx` on the raw bytes, and on the input written as the worksheet of a valid workbook, past the ZIP checksums. Its zip-bomb, dimension-bomb and attribute-bomb guards hold, or the run reports running out of memory or time | An uploaded XLSX |
| `import_rows` | Each importable product group's row validator over the rows `parse_csv` reads, then the repeated-serial check, which keeps or refuses every valid row and never both | The cells of an uploaded spreadsheet |
| `create_request_validate` | `CreatePassportRequest` from JSON, then `validate_create_request` | A create or dry-run body, and every row an import forwards |
| `credential_header` | `read_and_verify` on the `X-DPP-Credential` header, raw and as three base64url-encoded parts. Every issuer is trusted and publishes a key nobody can sign for, so a credential that verifies is a failure too | An anonymous caller of `/credential/dpp/{dppId}` |
| `verify_dossier_json` | `verify::verify_dossier_json`, with the seal inspector the node boots with | An uploaded evidence dossier |
| `cades_seal_inspect` | Every public reader in `dpp_seal::cades`, and every `SealInspector` answer, on raw DER | A seal from a QTSP, a stored one, or the one in a dossier |
| `trusted_list_parse` | `parse_lotl`, `parse_trusted_list`, `verify_lotl`, and `verify_trusted_list` against each pointer the document names | The EU list of trusted lists and the national lists, fetched over the network |
| `public_page_render` | `render_page` on any JSON view. Every string reaches the page escaped, checked by rendering the view again with its markup characters masked and comparing the raw `<`, `>`, `"` and `'` counts | A passport's public view, written by the operator and their suppliers |
| `url_guard` | `validate_webhook_url` and `validate_public_https_url`. Each accepts the normalised URL it returns, unchanged | A webhook target, a lineage reference, a transfer counterparty's DID |

Every `[[bin]]` in `Cargo.toml` is also listed in the matrix in
`.github/workflows/fuzz.yml`, the only place the targets run, and in the table above.
`scripts/fuzz-targets-check.sh` (in `just check`) fails when they differ. Pull requests
also run `just fuzz-check`, which format-checks and lints the targets on stable, so a
change that stops one compiling fails before it merges.

## Run locally (Linux)

```bash
cargo install cargo-fuzz
cp Cargo.lock fuzz/Cargo.lock                                 # the graph that ships
cargo +nightly fuzz run parse_xlsx                            # until a crash or Ctrl-C
cargo +nightly fuzz run parse_xlsx -- -max_total_time=60     # 60-second smoke run
```

`fuzz/Cargo.lock` is git-ignored. Copying the workspace lock first, as CI does, keeps
every package the two share at the version the engine ships with; without it cargo
resolves the fuzz crate afresh.

> Local runs need the core dependency resolvable: either the published `dpp-core`
> crates, or the sibling `../dpp-core` checkout via `just core-local` (the
> `.cargo/config.toml` patch applies to this crate too, since config is discovered
> from the `dpp-engine` dir upward).

## Corpus and regressions

The nightly job keeps each target's corpus in the Actions cache and restores the
newest one on the next run, so coverage builds up rather than starting over. It also
seeds two pairs of targets from files the repository already keeps: `parse_csv` and
`import_rows` from the committed spreadsheets, and `create_request_validate` and
`public_page_render` from the stored passport documents in
`crates/dpp-dal/tests/fixtures/passport_docs`, minified, leaving out any longer than the
input limit. To seed a corpus locally:

```bash
mkdir -p fuzz/corpus/parse_csv
cp crates/dpp-integrator/templates/*.csv ops/demo/datasets/*.csv fuzz/corpus/parse_csv/
```

When cargo-fuzz finds a crash, it writes a reproducer to `artifacts/`. Minimise it
(`cargo +nightly fuzz tmin`) and commit the input as a named regression **unit test** in
the crate it broke, so the ordinary test suite keeps checking it.
