//! Integration tests for `NatsEventBus` — verifies publish/consume round-trip
//! through a real NATS JetStream instance running in Docker.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-node --features integration-tests -- nats --nocapture
//! ```

#![cfg(feature = "integration-tests")]

use std::time::Duration;

use async_nats::jetstream::{self, consumer};
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use dpp_common::event::{DppEvent, EventBus, subjects};
use dpp_node::infra::nats_event_bus::NatsEventBus;

/// Spin up a NATS container with JetStream enabled.
async fn start_nats() -> (String, testcontainers::ContainerAsync<GenericImage>) {
    let image = GenericImage::new("nats", "2")
        .with_exposed_port(ContainerPort::Tcp(4222))
        .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
        .with_cmd(["--jetstream"]);

    let container = image.start().await.expect("NATS container start failed");
    let port = container.get_host_port_ipv4(4222).await.expect("get port");

    // Small delay for JetStream to initialise.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let url = format!("nats://127.0.0.1:{port}");
    (url, container)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn connect_creates_dpp_events_stream() {
    let (url, _container) = start_nats().await;

    let bus = NatsEventBus::connect(&url, Duration::from_secs(60))
        .await
        .expect("connect failed");

    // Verify the stream exists by connecting a second client and querying it.
    let client = async_nats::connect(&url).await.unwrap();
    let js = jetstream::new(client);
    let stream = js.get_stream("DPP_EVENTS").await;
    assert!(stream.is_ok(), "DPP_EVENTS stream must exist after connect");

    // Verify the stream captures the correct subject filter.
    let mut stream = stream.unwrap();
    let info = stream.info().await.unwrap();
    assert!(
        info.config.subjects.contains(&"dpp.>".to_string()),
        "stream must capture dpp.> subjects"
    );

    drop(bus);
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_event_is_persisted_in_jetstream() {
    let (url, _container) = start_nats().await;

    let bus = NatsEventBus::connect(&url, Duration::from_secs(60))
        .await
        .expect("connect failed");

    // Publish a passport-created event.
    let event = DppEvent::v1(
        subjects::PASSPORT_CREATED,
        "operator-test-1",
        serde_json::json!({
            "passportId": "dpp-001",
            "productName": "Test Widget"
        }),
    );
    bus.publish(&event).await.expect("publish failed");

    // Create a consumer and pull the message back.
    let client = async_nats::connect(&url).await.unwrap();
    let js = jetstream::new(client);
    let stream = js.get_stream("DPP_EVENTS").await.unwrap();

    let consumer = stream
        .create_consumer(consumer::pull::Config {
            durable_name: Some("test-verify".to_string()),
            filter_subject: "dpp.passport.created".to_string(),
            ..Default::default()
        })
        .await
        .expect("create consumer");

    let mut messages = consumer.fetch().max_messages(1).messages().await.unwrap();
    use futures::StreamExt;
    let msg = messages
        .next()
        .await
        .expect("expected at least one message")
        .expect("message error");

    // Deserialise and verify round-trip.
    let received: DppEvent = serde_json::from_slice(&msg.payload).expect("deserialise event");
    assert_eq!(received.event_type, "dpp.passport.created");
    assert_eq!(received.operator_id, "operator-test-1");
    assert_eq!(received.data["passportId"], "dpp-001");
    assert_eq!(received.version, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn multiple_event_types_route_to_correct_subjects() {
    let (url, _container) = start_nats().await;

    let bus = NatsEventBus::connect(&url, Duration::from_secs(60))
        .await
        .expect("connect failed");

    // Publish three different event types.
    let created = DppEvent::v1(subjects::PASSPORT_CREATED, "op-1", serde_json::json!({}));
    let published = DppEvent::v1(subjects::PASSPORT_PUBLISHED, "op-1", serde_json::json!({}));
    let suspended = DppEvent::v1(subjects::PASSPORT_SUSPENDED, "op-1", serde_json::json!({}));

    bus.publish(&created).await.unwrap();
    bus.publish(&published).await.unwrap();
    bus.publish(&suspended).await.unwrap();

    // Check stream has 3 messages.
    let client = async_nats::connect(&url).await.unwrap();
    let js = jetstream::new(client);
    let mut stream = js.get_stream("DPP_EVENTS").await.unwrap();
    let info = stream.info().await.unwrap();
    assert_eq!(info.state.messages, 3, "stream must contain 3 messages");

    // Filter by subject — only published events.
    let consumer = stream
        .create_consumer(consumer::pull::Config {
            durable_name: Some("test-published-only".to_string()),
            filter_subject: "dpp.passport.published".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut messages = consumer.fetch().max_messages(10).messages().await.unwrap();
    use futures::StreamExt;
    let msg = messages.next().await.unwrap().unwrap();
    let evt: DppEvent = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(evt.event_type, "dpp.passport.published");
    // No more messages on this subject.
    assert!(messages.next().await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn event_envelope_uses_camel_case_on_wire() {
    let (url, _container) = start_nats().await;

    let bus = NatsEventBus::connect(&url, Duration::from_secs(60))
        .await
        .expect("connect failed");

    let event = DppEvent::v1(
        subjects::PASSPORT_ARCHIVED,
        "op-wire",
        serde_json::json!({}),
    );
    bus.publish(&event).await.unwrap();

    let client = async_nats::connect(&url).await.unwrap();
    let js = jetstream::new(client);
    let stream = js.get_stream("DPP_EVENTS").await.unwrap();
    let consumer = stream
        .create_consumer(consumer::pull::Config {
            durable_name: Some("test-wire-format".to_string()),
            filter_subject: "dpp.passport.archived".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut messages = consumer.fetch().max_messages(1).messages().await.unwrap();
    use futures::StreamExt;
    let msg = messages.next().await.unwrap().unwrap();

    // Parse as raw JSON to verify field names are camelCase.
    let raw: serde_json::Value = serde_json::from_slice(&msg.payload).unwrap();
    assert!(raw.get("eventId").is_some(), "must use camelCase: eventId");
    assert!(
        raw.get("eventType").is_some(),
        "must use camelCase: eventType"
    );
    assert!(
        raw.get("operatorId").is_some(),
        "must use camelCase: operatorId"
    );
    assert!(raw.get("event_id").is_none(), "snake_case must NOT appear");
}
