# Demo Passports — full Annex XIII battery content

JSON passport bodies that carry the **complete** EU Battery Regulation (2023/1542)
Annex XIII data set for their category, so they pass the publish-time
mandatory-content gate (`Passport::check_mandatory_content`).

## Why these are JSON, not CSV

The CSV importer (`dpp-integrator`, `validate_battery_row`) only maps ~18 battery
columns and hard-codes every Annex XIII point 1–4 field to `null`. A battery
whose `batteryType` is `ev`, `lmt`, or `industrial` therefore **cannot be
published from a CSV** — `odal publish` rejects it with
`'<field>' is mandatory for a '<type>' battery and is absent` for ~30–40 fields.
The `ops/demo/datasets/*.csv` battery files still import and are fine for the
bulk-import / delta-import demo; they just stop at draft for those categories.

These files go straight to `POST /vault/api/v1/dpp` with a fully-populated
`productGroupData` object, which can express everything — nested arrays
(`hazardousSubstances`, `criticalRawMaterials`, `cathodeMaterial` …), the
`notInUseTemperatureRange` object, the `stateOfHealth` one-of, and so on.

## The cases

| File | `batteryType` | Chemistry | Notes |
|------|---------------|-----------|-------|
| `01-battery-industrial-nmc.json` | industrial | NMC | Reference industrial pack. Full point 1–3 set + the point 4 individual-battery blocks (`dynamicPerformance`, `stateOfHealth`, `usageHistory`). |
| `02-battery-industrial-lfp.json` | industrial | LFP | Stationary-storage style, cobalt-free, 6000-cycle. |
| `03-battery-industrial-lead-acid.json` | industrial | lead-acid | VRLA standby. Carries `hazardSymbol: "lead"` and a non-zero `recycledContentLeadPct`. |
| `04-battery-ev-nmc.json` | ev | NMC | EV traction battery. Adds the EV-only `capacityThresholdForExhaustionPct` and the `electricVehicle` `stateOfHealth` parameter set (SOCE). |
| `05-battery-lmt-lfp.json` | lmt | LFP | e-bike pack. `stationaryOrLmt` state-of-health set; **no** capacity-threshold field (barred for LMT). |
| `06-battery-portable-nimh.json` | portable | NiMH | Outside the Commission's per-category guidance, so the content gate imposes nothing — the minimal end of the spectrum. |

The per-category field obligations come from
`dpp-rules::batteries::passport_content` (the Commission *Digital Batteries
Passport — data points by category* guidance, v1.0, 28 Jul 2026).

## Load them

`load.sh` creates and publishes every file against a local node. It needs an
admin or write-scoped API key.

```sh
# mint a key (admin Basic auth; creds from dpp-engine/.env)
KEY=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" -H 'content-type: application/json' \
  -d '{"name":"demo-passports","scope":"write"}' \
  http://localhost:8001/vault/api/v1/api-keys | sed 's/.*"secret":"//;s/".*//')

ODAL_API_KEY=$KEY ./ops/demo/passports/load.sh          # create + publish
ODAL_API_KEY=$KEY ./ops/demo/passports/load.sh --draft  # create only
```

Override the node with `ODAL_VAULT_URL` (default `http://localhost:8001/vault`).

Equivalent with a rebuilt CLI (JSON import posts each record to the create
endpoint):

```sh
odal passport import ops/demo/passports/01-battery-industrial-nmc.json
odal passport publish <id>
```

## GTINs

`09590000000014`, `…021`, `…038`, `…045`, `…052`, `…069` — a reserved block that
does not collide with the `ops/demo/datasets` CSVs (`3801…` textile, `4901…` /
`0950…` battery).
