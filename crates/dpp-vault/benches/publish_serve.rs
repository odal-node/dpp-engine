//! The vault's create, publish and read path over HTTP, against a real Postgres.
//!
//! These are the calls a passport's life is made of, timed the way a client sees
//! them: the router, the auth middleware, the service and its repositories, and a
//! database round trip each. Nothing in `dpp-core`'s benches can see the sum.
//!
//! One thing is not real: the signer. The harness wires `MockIdentity`, which
//! hands back a fixed envelope, so publish here leaves out Ed25519. That cost is
//! `dpp-core`'s `crypto` bench, and a figure that included it would move with the
//! key store rather than with this crate.
//!
//! `floor_info` is a route that touches no database, so what a request costs on
//! loopback with auth and routing can be subtracted from the rest.
//!
//! The harness is the one `tests/` uses, included rather than copied: a second
//! copy of the vault's wiring would drift from the first.
//!
//! Needs Docker. With `ODAL_TEST_PG_ADMIN_URL` set the shared harness clones a
//! database on that server; unset, it starts a `postgres:17` container of its own.
//! Run with:
//! ```sh
//! just bench-infra
//! cargo bench -p dpp-vault --features integration-tests --bench publish_serve
//! ```

#[path = "../tests/helpers/mod.rs"]
mod helpers;

use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

/// Passports in the table the list is read from.
const LIST_SIZES: [u64; 2] = [100, 1_000];

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A battery that differs from every other in its batch, so none collides with
/// another on identity.
fn battery() -> Value {
    json!({
        "productName": "Bench Cycle Pack",
        "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
        "materials": [{ "name": "Lithium", "weightKg": 1.2 }],
        "batchId": format!("LOT-{:08}", NEXT.fetch_add(1, Ordering::Relaxed)),
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryChemistry": "LFP",
            "batteryType": "portable",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2,
            "ratedCapacityKwh": 4.8
        }
    })
}

async fn create(client: &TestClient) -> String {
    let resp = client.post_json("/api/v1/dpp", battery()).await;
    assert_eq!(resp.status(), 201, "create");
    let created: Value = resp.json().await.expect("a JSON body");
    created["id"].as_str().expect("an id").to_owned()
}

async fn publish(client: &TestClient, id: &str) {
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish");
}

async fn get_ok(client: &TestClient, path: &str) {
    let resp = client.get(path).await;
    assert_eq!(resp.status(), 200, "GET {path}");
}

fn publish_serve(c: &mut Criterion) {
    let rt = Runtime::new().expect("a tokio runtime");
    let pg = rt.block_on(start_postgres());
    let url = rt.block_on(start_vault(pg.dal.clone()));
    rt.block_on(seed_complete_operator(&pg.dal));
    let client = TestClient::new(&url, make_jwt("00000000-0000-0000-0000-000000000002"));

    // A benchmark that times a refusal still prints a figure, so each path is
    // walked once, and its answer checked, before anything is timed.
    let published_id = rt.block_on(async {
        let id = create(&client).await;
        publish(&client, &id).await;
        let resp = client.get(&format!("/public/dpp/{id}")).await;
        assert_eq!(resp.status(), 200, "public read");
        let served: Value = resp.json().await.expect("a JSON body");
        assert!(
            served["publicJwsSignature"].is_string(),
            "a published passport is served with its proof"
        );
        get_ok(&client, &format!("/api/v1/dpp/{id}")).await;
        get_ok(&client, "/api/v1/dpps").await;
        get_ok(&client, "/api/v1/info").await;
        id
    });

    // The list is the route whose cost grows with the table, so it is measured
    // first, at sizes the table is topped up to: the writes below add thousands of
    // rows while they are timed, which would move every size after them. The table
    // is read from the route itself, so the sweep is of what the route sees.
    let mut list = c.benchmark_group("vault_http_list");
    for size in LIST_SIZES {
        let have = rt.block_on(async {
            let resp = client.get("/api/v1/dpps?limit=1").await;
            let page: Value = resp.json().await.expect("a JSON body");
            page["total"].as_u64().expect("a total")
        });
        for _ in have..size {
            rt.block_on(create(&client));
        }
        list.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| rt.block_on(get_ok(&client, "/api/v1/dpps")));
        });
    }
    list.finish();

    let mut group = c.benchmark_group("vault_http");
    group.bench_function("floor_info", |b| {
        b.iter(|| rt.block_on(get_ok(&client, "/api/v1/info")));
    });
    group.bench_function("create", |b| {
        b.iter(|| rt.block_on(create(&client)));
    });
    group.bench_function("publish", |b| {
        b.iter_batched(
            || rt.block_on(create(&client)),
            |id| rt.block_on(publish(&client, &id)),
            BatchSize::SmallInput,
        );
    });
    let public = format!("/public/dpp/{published_id}");
    group.bench_function("public_read", |b| {
        b.iter(|| rt.block_on(get_ok(&client, &public)));
    });
    let private = format!("/api/v1/dpp/{published_id}");
    group.bench_function("authenticated_read", |b| {
        b.iter(|| rt.block_on(get_ok(&client, &private)));
    });
    group.finish();

    // Dropped inside the runtime: stopping a container needs a reactor.
    rt.block_on(async move { drop(pg) });
}

criterion_group!(benches, publish_serve);
criterion_main!(benches);
