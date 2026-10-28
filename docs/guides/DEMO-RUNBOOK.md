# Demo runbook

Stand up a node that issues the shipped demo passports and serves them at a URL,
and set the three values that otherwise break the demonstration.

This is the demonstration path. For a real deployment, follow
[OPERATOR-SETUP.md](OPERATOR-SETUP.md); differences are noted where they matter.

## What it shows

1. **One passport, two answers.** The same record read publicly and by a
   credentialed reader: disclosure is decided per field, not per document.
2. **The carrier URL is derived from the product identifier.** Publish mints a GS1
   Digital Link from the passport's GTIN ([section 7](#7-the-carrier-url-is-derived-from-the-product-identifier)
   also covers why the shipped corpus cannot show the non-GS1 form yet).

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker 24+ with Compose v2 | `docker compose version` |
| The `odal` binary | `cargo build -p dpp-cli --release` |
| A domain | Only for a hosted demo. A laptop demo needs none ([section 6](#6-show-the-contrast)) |

## The three settings that decide whether it works

> [!WARNING]
> Read this before running anything. Two of these fail silently.

### 1. `RESOLVER_BASE_URL`: required, and it must be the final host

```bash
RESOLVER_BASE_URL=http://localhost:8003      # or the demo host
```

There is no default; the node, the resolver and `odal up` all refuse to start
without it. `.env.example` ships the laptop value above.

Publish writes this value into every passport's `qrCodeUrl`, inside the signature,
so a wrong value cannot be corrected without reissuing the passport. The resolver
builds its Digital Link redirects on the same value. Set it to the host the demo will
be scanned from before the first publish.

### 2. `CREDENTIAL_ISSUERS_SELF`: without it the contrast disappears

```bash
CREDENTIAL_ISSUERS_SELF=true
```

This makes the node trust its own DID as a legitimate-interest issuer. Without it the
credential directory is not wired, and `GET /vault/credential/dpp/{dppId}` answers
`200` with the public body. Nothing errors, both views render, and they are
identical.

### 3. `CREDENTIAL_ISSUERS_AUTHORITY`: only for the authority tier

Self-trust grants legitimate-interest roles only (repairer, recycler, second-life
operators), because an authority's standing is conferred by a member state, not by
the operator. Showing the authority view needs a second identity, named here by its
DID. Public versus legitimate interest is usually enough.

## 1. Configure

```bash
cp .env.example .env
```

Set `KEY_STORE_PASSPHRASE` and the admin credentials as in the
[README quick start](../../README.md#2-configure), plus:

```bash
RESOLVER_BASE_URL=http://localhost:8003
CREDENTIAL_ISSUERS_SELF=true
```

## 2. Start the stack

```bash
odal up
odal status
```

`odal up` starts the node, the resolver, PostgreSQL, Redis and NATS from
`docker/docker-compose.yml`. `odal status` reports each trust port's mode.

## 3. Onboard the operator

```bash
set -a; . ./.env; set +a
odal bootstrap --legal-name "Demo GmbH" --country DE \
  --address "Musterstrasse 1, 10115 Berlin" --contact-email demo@example.com
odal facility add --name "Demo plant" --scheme gln --value 4012345000009 \
  --country DE --default
odal operator-id add --scheme vat --value DE123456789 --primary
```

`bootstrap` prints the first API key once; keep it. The demo passports are batteries,
whose passport obligation is in force, so publish refuses with `422`
*"missing required registry identity"* until the facility and operator identifier
exist. A draft created before them still publishes once they do.

## 4. Publish the demo passports

The corpus is in `ops/demo/`:

| Directory | Contents |
|---|---|
| `passports/` | 6 fully populated Annex XIII batteries, each with a GTIN |
| `datasets/` | 18 CSV and TSV import fixtures, valid and deliberately broken |
| `dossiers/` | 11 evidence dossiers, including transfer, end of life and tampered ones |
| `samples/` | Full example bodies for a battery and a textile passport |

The JSON passports are the only demonstration that a fully populated Annex XIII
battery publishes: the CSV importer cannot carry all of those fields.
`crates/dpp-vault/tests/demo_passports_publish.rs` keeps them publishable.

```bash
odal passport validate ops/demo/passports/01-battery-industrial-nmc.json   # dry run
odal passport import ops/demo/passports/01-battery-industrial-nmc.json     # creates a draft
odal passport publish                                                       # every draft, or pass an id
odal passport list
```

## 5. Issue a credential

```bash
odal credential issue did:web:repairs.example \
  --name "Example Repairs Ltd" --role recycler --country DE --valid-for-days 30
```

`--role` defaults to `authorised_repairer`; `recycler`, `remanufacturer`,
`preparer_for_reuse` and `distributor` are the other named roles. `--product-groups`
narrows the credential. The command prints a JWS, which the holder sends as the
`X-DPP-Credential` header.

Authority roles (market surveillance, customs, notified bodies) are refused. The
node publishes no revocation list, so a credential lives at most 90 days.

## 6. Show the contrast

```bash
curl http://localhost:8001/vault/public/dpp/<dppId>
curl -H "X-DPP-Credential: <jws>" http://localhost:8001/vault/credential/dpp/<dppId>
```

The second response adds the Annex XIII point 2 and point 4 content the first omits:
dismantling and safety information, state of health and use history.

### It works on a laptop

Credential verification resolves the issuer's `did:web`, and outbound fetches go
through `url_guard::assert_public_target`, which requires `https` and refuses loopback
and private addresses. That would rule out a local demo, except that
`HttpCredentialDirectory::with_local_issuer` resolves a credential the node issued to
itself in-process, without a network fetch. A self-issued credential therefore works
on `localhost` with no domain, TLS or tunnel. A credential from another issuer needs
that issuer's DID document to be publicly reachable.

## 7. The carrier URL is derived from the product identifier

Publish (`build_carrier_url` in `dpp-vault`) branches on the scheme of
`productGroupData.productIdentifier` and, for GS1, on the passport's `granularity`:

| Product identifier | Level | Carrier URL | Needs GS1 membership |
|---|---|---|---|
| GS1 (`scheme: gs1`) | model | `{base}/01/{gtin}` | Yes |
| GS1 | batch | `{base}/01/{gtin}/10/{batch}` | Yes |
| GS1 | item, or not stated | `{base}/01/{gtin}/21/{serial}` | Yes |
| Identification link or DID | any | `{base}/dpp/{id}` | No |

No demo passport states a level, so each prints the `/21/{serial}` form with a serial
derived from the passport id. A scan resolves to exactly that passport.

### The non-GS1 form is not in the corpus

All six demo passports carry a GS1 identifier, and
`demo_passports_publish.rs::every_demo_passport_carries_a_gtin` asserts they always
will. The node accepts `scheme: did` and `scheme: identificationLink` identifiers,
which publish with the `{base}/dpp/{id}` carrier and need no GS1 membership (EN 18219
clause 5 allows such schemes), but there is no demo passport showing it. Do not
promise that comparison until a non-GS1 demo passport exists and the guard test is
revisited.

## Where it can run

| Setting | State | Notes |
|---|---|---|
| Local, through the CLI | Ready | Everything above, no domain needed |
| A hosted environment | Depends on your deployment | Deploy well before the demo, so a first failure is not on the day |
| A public website | Link only | A marketing site links to a node; it does not serve passports from a shared endpoint |

Each node serves one operator on its own domain. A shared endpoint serving several
operators' passports would break that isolation.

## Teardown

```bash
odal down
```

This removes the containers. The `node-data` volume (which holds the signing key) and
the PostgreSQL volume remain; remove them with `docker volume rm` if the demo
identity should not persist.
