# Demo samples — fully-populated DPPs

Two reference Digital Product Passports with a wide field set populated, for
visualising the full data shape and for seeding a fresh node. Current passport
format (envelope `productGroup` + `productGroupData`; no `schemaVersion` — the
node stamps the product group's current schema on create).

| File | Product group | Notes |
|------|---------------|-------|
| `battery-full.json` | battery | `industrial` battery carrying the **complete** EU Battery Regulation Annex XIII data set — publishes past the mandatory-content gate. Valid GTIN `09506000134352`. |
| `textile-full.json` | textile | `TextileData` with fibre composition (sums to 100%), SVHC, care, microplastic and durability data. |

For a battery example **per category** (`ev`, `lmt`, `portable`, lead-acid …),
see [`../passports/`](../passports/).

## Publish them (the `odal` CLI)

`odal passport import` accepts **JSON** (a single DPP object or an array) as well
as CSV, so these post verbatim with every field intact.

```sh
# 1. Point the CLI at your node (config at ~/.config/odal/config.toml):
#      vault_url    = "http://localhost:8001/vault"
#      resolver_url = "http://localhost:8003"
#      api_key      = "odal_sk_..."
odal init                                              # interactive, or edit the toml

# 2. Create the drafts
odal passport import ops/demo/samples/battery-full.json
odal passport import ops/demo/samples/textile-full.json

# 3. Publish (Ed25519 sign + GS1 Digital Link)
odal passport publish

# 4. Inspect
odal passport export --format json
#   or open the public page: http://localhost:8003/dpp/<id>
```

Without a built CLI, `curl` the create endpoint directly — see
`../passports/load.sh` for the pattern.

Prereq: node running, schema migrated, operator identity set (`odal operator set`).
