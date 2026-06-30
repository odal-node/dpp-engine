# Licensing

## dpp-engine — BSL-1.1

dpp-engine is licensed under the **Business Source License 1.1** (BSL-1.1).

### What This Means

| Use Case | Permitted | Notes |
|---|---|---|
| Reading and studying the source code | Yes | Source-available |
| Self-hosting for your own business operations | Yes | Additional Use Grant |
| Modifying for internal use | Yes | |
| Offering as a hosted service to third parties | **No** | Requires a commercial license |
| Redistributing as a competing product | **No** | Requires a commercial license |
| Using after the Change Date | Yes (Apache-2.0) | BSL conversion clause |

### Key Terms

- **Change Date**: 4 years from each version's release date.
- **Change License**: Apache-2.0 (the same license as dpp-core).
- **Additional Use Grant**: Production self-hosting to issue, sign, store, and
  serve DPPs for your own organisation's products and compliance — at no
  charge. The grant does **not** permit offering the Licensed Work to third
  parties as a hosted/managed service or as part of a competing product (those
  require a commercial license). **The LICENSE file is authoritative;** this
  table is a summary.
- **Licensor**: Aleksandar Temelkov, trading as "Odal Node".

After the Change Date, the specific version converts automatically to
Apache-2.0 and may be used without restriction.

### Commercial Licensing

For organisations that need to offer dpp-engine as a hosted service
or embed it in a competing product, commercial licenses are available.
Contact: dev@odal-node.io

## dpp-core — Apache-2.0

The core library (`dpp-core`) is licensed under Apache-2.0 with no
restrictions. All regulatory logic, domain types, cryptographic primitives,
and schema validation are open-source and free to use.

The core/platform licensing boundary aligns with the architectural boundary:

| Layer | License | Contains |
|---|---|---|
| dpp-core | Apache-2.0 | Domain types, port traits, schema validation, Ed25519, JWS, did:web, GS1 |
| dpp-engine | BSL-1.1 | HTTP services, PostgreSQL persistence, auth, event bus, operator management |

## Why BSL-1.1

BSL-1.1 balances openness with sustainability:

1. **Source transparency**: Anyone can read, audit, and verify the platform code.
2. **Self-hosting permitted**: Operators can run the platform on their own infrastructure.
3. **Commercial sustainability**: the BSL reserves hosted/managed-service rights, keeping the project maintainable while the source stays open.
4. **Time-limited restriction**: Every version converts to Apache-2.0 after 4 years.
5. **No vendor lock-in**: The core library is fully open. The platform's port trait implementations can be replicated by anyone.

## Dependency Licensing

All dependencies used by dpp-engine are compatible with BSL-1.1:

| Dependency | License | Notes |
|---|---|---|
| dpp-core | Apache-2.0 | Core library |
| axum | MIT | HTTP framework |
| serde | MIT/Apache-2.0 | Serialisation |
| tokio | MIT | Async runtime |
| reqwest | MIT/Apache-2.0 | HTTP client |
| chrono | MIT/Apache-2.0 | Date/time |
| uuid | MIT/Apache-2.0 | UUID generation |
| tracing | MIT | Logging |
| wasmtime | Apache-2.0 | Wasm runtime |
| ed25519-dalek | BSD-3-Clause | Ed25519 |

No GPL-licensed dependencies are used.

## References

- [BSL-1.1 Full Text](https://mariadb.com/bsl11/)
- [Apache-2.0 Full Text](https://www.apache.org/licenses/LICENSE-2.0)
- [dpp-core License](https://github.com/odal-node/dpp-core/blob/main/LICENSE)
