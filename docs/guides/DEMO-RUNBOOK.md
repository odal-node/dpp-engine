# Demo Runbook

How to stand up a node that issues the shipped demo passports and serves them at
a URL — the end-to-end path, with the defaults that will break it if left alone.

This is the **demonstration** path. For a real deployment read
[OPERATOR-SETUP.md](OPERATOR-SETUP.md); the difference is called out where it
matters.

---

## What this demonstrates

Two things that are hard to convey any other way:

1. **One passport, two answers.** The same record served publicly and to a
   credentialed reader, showing that disclosure is enforced per field rather
   than per document.
2. **A product identified without GS1.** EN 18219 clause 5 offers three
   identifier schemes as alternatives. Only the first needs GS1 membership, and
   the carrier URL visibly differs — see [§7](#7-the-carrier-url-tells-you-which-scheme-issued-the-passport).

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Docker ≥ 24** with Compose | `docker compose version` |
| **`odal` binary** | `cargo build -p dpp-cli --release` |
| A domain | **Only for rungs 2–3.** A laptop demo needs none — see [§6](#6-yes-this-works-on-a-laptop) |

---

## 🚨 The three settings that decide whether this works

Two of the three fail **silently**. Read this section before running anything.

### 1. `RESOLVER_BASE_URL` — the default does not resolve

```bash
RESOLVER_BASE_URL=http://localhost:8003      # or your demo host
```

The built-in default is `https://id.odal-node.io`, which **does not exist**.
`build_carrier_url` writes this value into every passport's `qr_code_url` at
publish, and the passport is then signed — so a wrong value is **inside the
signature** and cannot be corrected without reissuing. Every QR code would scan
to nothing.

**Set it before the first publish.** Not after.

### 2. `CREDENTIAL_ISSUERS_SELF` — without it the demo shows nothing

```bash
CREDENTIAL_ISSUERS_SELF=true
```

This makes the node trust its own DID as a legitimate-interest issuer. Without
it the credential directory is never wired, and
`GET /credential/dpp/{dppId}` returns **200 with the public body**.

That is the failure to fear: nothing errors, both views render, and the
demonstration quietly shows no contrast at all.

### 3. `CREDENTIAL_ISSUERS_AUTHORITY` — only if you want the third tier

Self-trust grants **legitimate interest only** (repairer, recycler, second-life)
— deliberately, because an authority's standing is conferred by a member state,
not by us. Showing the authority view means issuing a second identity and naming
its DID here.

Public vs legitimate-interest is usually enough to make the point.

---

## 1. Configure

Copy `.env.example` to `.env`, then set the standard values —
`DATABASE_URL`, `DATABASE_MIGRATE_URL`, `KEY_STORE_PATH`,
`KEY_STORE_PASSPHRASE`, `DID_WEB_BASE_URL` — plus the two above:

```bash
RESOLVER_BASE_URL=http://localhost:8003
CREDENTIAL_ISSUERS_SELF=true
```

## 2. Bring the node up

```bash
odal init --node-url http://localhost:8001
odal up
```

`odal up` starts the node, resolver, PostgreSQL and the plugin host from the
compose file in `docker/`. `odal status` reports each port's trust tier;
`odal down` stops everything.

## 3. Bootstrap the operator

```bash
odal bootstrap
```

Seeds operator config and mints the first API key. Keep the key — it is shown
once.

## 4. Publish the demo passports

The corpus lives in `ops/demo/`:

| Directory | Contents |
|---|---|
| `passports/` | 8 fully-populated Annex XIII batteries |
| `datasets/` | 19 CSV import fixtures, valid and deliberately broken |
| `dossiers/` | 11 evidence dossiers, including transfer and end-of-life |

These files are the **only** demonstration that a fully-populated Annex XIII
battery publishes at all — the CSV importer cannot carry those fields.
`crates/dpp-vault/tests/demo_passports_publish.rs` guards them against drift.

`odal import` accepts JSON as well as CSV/TSV and creates drafts; `odal publish`
signs them. Dry-run first if you want to see the verdict without creating
anything:

```bash
# Optional: dry-run one file, creates nothing
odal validate ops/demo/passports/01-battery-industrial-nmc.json

# Create as a draft, then sign and publish
odal import ops/demo/passports/01-battery-industrial-nmc.json
odal publish                 # publishes every draft; pass an id for just one
```

`odal list` shows the passports and their ids.

## 5. Issue a credential

```bash
odal credential issue \
  --holder-did did:web:repairs.example \
  --name "Example Repairs Ltd" \
  --role recycler \
  --country DE \
  --valid-for-days 30
```

`--role` defaults to `authorised_repairer`; `recycler`, `remanufacturer`,
`preparer_for_reuse` and `distributor` are the other named ones.
`--product-groups` narrows the credential; omit it to cover all.

Prints a JWS. The holder sends it as the `X-DPP-Credential` header.

> **Authority roles are refused here.** Market surveillance, customs and
> notified-body standing is conferred by a member state, not asserted by an
> operator — so the node will not sign that claim about itself.

> Nothing can withdraw a credential once issued — this node publishes no
> revocation status list — so the lifetime is the only control, and it is capped
> at **90 days**.

## 6. Show the contrast

```bash
# Public — no credential
curl http://localhost:8001/vault/public/dpp/<dppId>

# Credentialed — same record, more fields
curl -H "X-DPP-Credential: <jws>" \
     http://localhost:8001/vault/credential/dpp/<dppId>
```

The second response carries Annex XIII point 2 and point 4 content the first
omits — dismantling and safety data, state of health, use history.

### ✅ Yes, this works on a laptop

Worth stating, because the code suggests otherwise at first reading.

Credential verification resolves the issuer's `did:web`, and every such fetch
passes `url_guard::assert_public_target`, which **requires https and refuses
loopback and private addresses**. A purely local demo looks impossible.

It is not. `HttpCredentialDirectory::with_local_issuer` resolves *a credential
the node issued to itself* **in-process, never touching the guard**. The node
wires it whenever credentials are live. So a self-issued credential works on
`localhost` with no domain, no TLS and no tunnel.

A credential from *another* issuer does need that issuer's DID to be publicly
resolvable — which is the guard doing its job.

## 7. The carrier URL tells you which scheme issued the passport

`build_carrier_url` branches on whether the product group data carries a GTIN:

| Identifier scheme | Carrier URL | Needs GS1 membership? |
|---|---|---|
| 1 — GS1 | `{base}/01/{gtin}/21/{serial}` — a GS1 Digital Link | **Yes** |
| 2 — Identification Link | `{base}/dpp/{id}` | No |
| 3 — DID | `{base}/dpp/{id}` | No |

This is worth putting on screen. Requiring a GTIN would mean requiring GS1
membership, and schemes 2 and 3 exist precisely so a manufacturer without a
Company Identification Number can still issue a conformant passport. Two
passports side by side, with two different carrier forms, make that concrete in
a way a sentence does not.

---

## Where this runs

| Rung | State | Notes |
|---|---|---|
| **Local, by CLI** | Ready | Everything above. No domain required |
| **Staging** | Configuration exists; **never applied** | `evidence/applies/` is empty. Schedule a first apply early rather than during a demo week |
| **Public site** | A link, not a host | The marketing domain is static. It links to a demo node; it never serves passports |

That last row is deliberate, not a limitation. Every real node is per-operator
on its own domain — a shared endpoint serving operators' passports would invert
the sovereignty the product rests on.

---

## Teardown

```bash
odal down
```

Removes the containers. The keystore at `KEY_STORE_PATH` and the Postgres volume
survive; delete them explicitly if the demo identity should not persist.
