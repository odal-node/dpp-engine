# Demo samples — fully-populated DPPs

Reference Digital Product Passports with **every field populated** (including all
optional sector fields), for visualising the full data shape and for seeding a
fresh node. These are the canonical "this is what a complete DPP looks like"
examples.

| File | Sector | Notes |
|------|--------|-------|
| `battery-full.json` | battery | EU Battery Regulation shape; all `BatteryData` fields set; valid GTIN `09506000134352`. |
| `textile-full.json` | textile | All `TextileData` fields set; fibre composition sums to 100%; SVHC + care + microplastic data. |

## Publish them (the clean, cross-platform way — the `odal` CLI, no shell scripts)

The `odal` CLI (`dpp-engine/cli`) is the supported way to create and publish
DPPs. `dpp import` accepts **JSON** (a single DPP object or an array) as well as
CSV, so these samples post verbatim with every field intact.

The CLI binary is `dpp` (built from the `dpp-cli` crate). The examples below use
`cargo run -p dpp-cli --` so they work regardless of where the binary lives.

```sh
# 1. Point it at your node and authenticate with an API key.
#    Config lives at ~/.config/odal/config.toml:
#      vault_url = "http://localhost:8001/vault"
#      resolver_url = "http://localhost:8003"
#      api_key  = "odal_sk_..."        # from ops/bootstrap.sh, or key management
cargo run -p dpp-cli -- init        # interactive, or edit the toml directly

# 2. Create the passports (drafts)
cargo run -p dpp-cli -- import ops/demo/samples/battery-full.json
cargo run -p dpp-cli -- import ops/demo/samples/textile-full.json

# 3. Publish (signs with Ed25519, mints the GS1 Digital Link)
cargo run -p dpp-cli -- publish

# 4. Visualise the stored data
cargo run -p dpp-cli -- export --format json    # full records to stdout
#   or open the public page: http://localhost:8003/dpp/<id>
```

Prereq: the node must be running with the schema migrated and seeded — see the
top-level run docs (`cargo run -p dpp-node`, then `ops/bootstrap.sh`).
