//! NATS JetStream publish throughput benchmark.
//!
//! Requires Docker for testcontainers. Run with:
//! ```sh
//! cargo bench -p dpp-node --features integration-tests -- nats
//! ```

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use dpp_common::event::{DppEvent, EventBus, subjects};
use dpp_node::infra::nats_event_bus::NatsEventBus;
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};
use tokio::runtime::Runtime;

fn nats_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Start NATS container once for all benchmarks.
    let (url, _container) = rt.block_on(async {
        let image = GenericImage::new("nats", "2")
            .with_exposed_port(ContainerPort::Tcp(4222))
            .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
            .with_cmd(["--jetstream"]);
        let container = image.start().await.expect("NATS start failed");
        let port = container.get_host_port_ipv4(4222).await.expect("get port");
        tokio::time::sleep(Duration::from_millis(500)).await;
        (format!("nats://127.0.0.1:{port}"), container)
    });

    let bus = rt
        .block_on(NatsEventBus::connect(&url, Duration::from_secs(300)))
        .expect("connect failed");

    let event = DppEvent::v1(
        subjects::PASSPORT_PUBLISHED,
        "bench-operator",
        serde_json::json!({
            "passportId": "bench-001",
            "status": "active",
            "productName": "Benchmark Battery Module X-500"
        }),
    );

    c.bench_function("nats_publish_single", |b| {
        b.iter(|| {
            rt.block_on(async {
                bus.publish(&event).await.unwrap();
            });
        });
    });

    // Burst: publish 100 events sequentially and measure total time.
    c.bench_function("nats_publish_burst_100", |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..100 {
                    bus.publish(&event).await.unwrap();
                }
            });
        });
    });

    // Explicitly stop the container inside the runtime so the async drop has a
    // reactor — avoids the "no reactor running" panic during cleanup.
    rt.block_on(async move {
        drop(_container);
    });
}

criterion_group!(benches, nats_benchmarks);
criterion_main!(benches);
