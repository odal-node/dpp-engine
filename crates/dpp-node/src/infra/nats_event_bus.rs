//! NATS JetStream implementation of `EventBus`.
//!
//! Publishes versioned `DppEvent` envelopes to a JetStream stream.
//! The event's `event_type` field is used as the NATS subject (e.g.
//! `dpp.passport.published`), enabling subject-based routing and filtering.
//!
//! # Stream configuration
//!
//! On first connect, `NatsEventBus::connect()` creates (or re-uses) a stream
//! named `DPP_EVENTS` that captures all subjects matching `dpp.>`.
//! Retention is 7 days by default — tunable via `max_age`.
//!
//! # Reconnection
//!
//! The `async-nats` client handles TCP reconnection automatically with
//! exponential backoff. This adapter monitors connection state changes
//! and logs reconnection events. The JetStream context remains valid
//! across reconnects — no re-establishment is needed.

use std::time::Duration;

use async_nats::jetstream::{self, stream};
use dpp_common::event::{DppEvent, EventBus, EventBusError};

/// Maximum number of publish retry attempts during transient NATS disruptions.
const MAX_PUBLISH_RETRIES: u32 = 3;
/// Base delay between publish retries.
const RETRY_BASE_DELAY: Duration = Duration::from_millis(250);

/// NATS JetStream event bus with automatic reconnection monitoring.
pub struct NatsEventBus {
    jetstream: jetstream::Context,
    client: async_nats::Client,
}

impl NatsEventBus {
    /// Connect to NATS and ensure the `DPP_EVENTS` stream exists.
    ///
    /// The `async-nats` client handles TCP reconnection automatically.
    /// This method also spawns a background task that logs connection
    /// state changes (disconnect, reconnect, slow consumer warnings).
    ///
    /// # Arguments
    /// * `nats_url` — e.g. `"nats://localhost:4222"`
    /// * `max_age`  — retention period for events (default: 7 days)
    pub async fn connect(nats_url: &str, max_age: Duration) -> Result<Self, EventBusError> {
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .event_callback(|event| async move {
                match event {
                    async_nats::Event::Connected => {
                        tracing::info!("NATS connection established");
                    }
                    async_nats::Event::Disconnected => {
                        tracing::warn!("NATS disconnected — auto-reconnect in progress");
                    }
                    async_nats::Event::LameDuckMode => {
                        tracing::warn!("NATS server entering lame duck mode");
                    }
                    async_nats::Event::SlowConsumer(_) => {
                        tracing::warn!("NATS slow consumer detected");
                    }
                    _ => {
                        tracing::debug!(?event, "NATS connection event");
                    }
                }
            })
            .connect(nats_url)
            .await
            .map_err(|e| EventBusError::ConnectionLost(format!("NATS connect failed: {e}")))?;

        let jetstream = jetstream::new(client.clone());

        // Create or update the stream. `get_or_create_stream` is idempotent —
        // if the stream already exists with compatible config it's a no-op.
        jetstream
            .get_or_create_stream(stream::Config {
                name: "DPP_EVENTS".to_string(),
                subjects: vec!["dpp.>".to_string()],
                max_age,
                storage: stream::StorageType::File,
                retention: stream::RetentionPolicy::Limits,
                ..Default::default()
            })
            .await
            .map_err(|e| {
                EventBusError::ConnectionLost(format!("JetStream stream setup failed: {e}"))
            })?;

        tracing::info!(
            stream = "DPP_EVENTS",
            subjects = "dpp.>",
            max_age_secs = max_age.as_secs(),
            "JetStream event bus connected"
        );

        Ok(Self { jetstream, client })
    }

    /// Check if the NATS connection is currently active.
    pub fn is_connected(&self) -> bool {
        self.client.connection_state() == async_nats::connection::State::Connected
    }
}

#[async_trait::async_trait]
impl EventBus for NatsEventBus {
    async fn publish(&self, event: &DppEvent) -> Result<(), EventBusError> {
        let payload =
            serde_json::to_vec(event).map_err(|e| EventBusError::Serialisation(e.to_string()))?;

        // Retry publish with backoff during brief reconnection windows.
        let mut last_err = None;
        for attempt in 0..MAX_PUBLISH_RETRIES {
            match self
                .jetstream
                .publish(event.event_type.clone(), payload.clone().into())
                .await
            {
                Ok(ack_future) => {
                    // Await server acknowledgement to confirm persistence.
                    match ack_future.await {
                        Ok(_) => {
                            if attempt > 0 {
                                tracing::info!(
                                    event_type = %event.event_type,
                                    attempt = attempt + 1,
                                    "event published after retry"
                                );
                            } else {
                                tracing::debug!(
                                    event_type = %event.event_type,
                                    event_id = %event.event_id,
                                    "event published to JetStream"
                                );
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            last_err = Some(format!("ack failed: {e}"));
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(format!("publish failed: {e}"));
                }
            }

            if attempt + 1 < MAX_PUBLISH_RETRIES {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
                tracing::warn!(
                    event_type = %event.event_type,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis() as u64,
                    error = last_err.as_deref().unwrap_or("unknown"),
                    "retrying NATS publish"
                );
                tokio::time::sleep(delay).await;
            }
        }

        Err(EventBusError::PublishFailed(
            last_err.unwrap_or_else(|| "unknown publish error".into()),
        ))
    }
}
