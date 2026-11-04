# Licensing

`dpp-core` is an open-source Rust library under Apache-2.0: stateless, with no
database and no network I/O. `dpp-engine` is the self-hostable node built on it, under
the Business Source License 1.1. Running it in production for your own organisation's
products and compliance obligations is free. Offering it to third parties as a hosted
service, or embedding it in a competing product, needs a commercial licence.

This page summarises the terms. The [`LICENSE`](../../LICENSE) file is authoritative.

## dpp-engine: Business Source License 1.1

| Use | Allowed | Basis |
|---|---|---|
| Read, audit, copy and modify the source | Yes | BSL-1.1 base grant |
| Non-production use: development, testing, evaluation | Yes | BSL-1.1 base grant |
| Production use to issue, sign, store and serve passports for your own organisation's products and compliance obligations | Yes, at no charge | Additional Use Grant |
| Offering the engine to third parties as a hosted or managed service | No, needs a commercial licence | Outside the grant |
| Redistributing or embedding it in a competing product, where it provides a material part of the value | No, needs a commercial licence | Outside the grant |
| Any use of a release after its Change Date | Yes, under Apache-2.0 | Change Licence |

| Term | Value |
|---|---|
| Licensor | Aleksandar Temelkov, trading as "Odal Node" |
| Licensed Work | Odal Node |
| Change Date | Four years after each release |
| Change Licence | Apache License, Version 2.0 |

Each release converts to Apache-2.0 on its own Change Date.

For a commercial licence, contact **legal@odal-node.io**.

## dpp-core: Apache-2.0

The library holds the data model, JSON Schemas, regulatory rules, signing and
verification, identifiers and calculators. It is Apache-2.0 with no additional
conditions, so anyone can build their own implementation on it.

| Repository | Licence | Contains |
|---|---|---|
| `dpp-core` | Apache-2.0 | Domain types and port traits, schema validation, regulatory rules, Ed25519 and JWS, `did:web`, product identifiers and GS1 Digital Link, AAS, calculators, the Wasm plugin ABI |
| `dpp-engine` | BSL-1.1 | HTTP services, PostgreSQL persistence, authentication, event bus, plugin host, operator administration, the `odal` CLI |

## Why the engine is BSL-1.1

- **The source is open to read and audit**, including by the operators and authorities
  who rely on its output.
- **Self-hosting for your own compliance is free**, so there is no lock-in to a hosted
  service.
- **Hosted-service rights are reserved**, which funds maintenance.
- **The restriction expires**: every release becomes Apache-2.0 after four years.
- **The regulatory logic is not restricted at all**: it lives in Apache-2.0 `dpp-core`,
  and the engine's port implementations can be rebuilt by anyone.

## Dependencies

Third-party crates must carry one of the licences allowed in [`deny.toml`](../../deny.toml)
(MIT, Apache-2.0, BSD, ISC, MPL-2.0 and similar permissive licences).
`cargo deny check licenses`, run by `just audit`, enforces it. No GPL-licensed crate is
allowed.

## References

- [Business Source License 1.1](https://mariadb.com/bsl11/)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [`dpp-core` licence](https://github.com/odal-node/dpp-core/blob/main/LICENSE)
