//! `WebhookService` — subscription lifecycle + test delivery for signed webhooks.
//!
//! Creation SSRF-validates the receiver URL (`https`, non-private host) and
//! generates the signing secret server-side, returning it exactly once. Removal
//! is a soft deactivate. `test` enqueues a synthetic delivery so an operator can
//! prove a receiver end-to-end without waiting for a real passport event.

use std::sync::Arc;

use base64::Engine as _;
use rand::RngCore;
use uuid::Uuid;

use dpp_common::event::DppEvent;
use dpp_common::url_guard::validate_webhook_url;
use dpp_domain::domain::error::DppError;
use dpp_types::{
    NewWebhookSubscription, STANDALONE_OPERATOR_ID, WebhookOutbox, WebhookSubscription,
    WebhookSubscriptionStore,
};

const SECRET_PREFIX: &str = "whsec_";
const SECRET_ENTROPY_BYTES: usize = 32;

/// Event type used for the synthetic `test` delivery.
pub const WEBHOOK_TEST_EVENT: &str = "dpp.webhook.test";

/// A newly created subscription plus its signing secret. The secret is returned
/// only here — it is never recoverable from a later list/get.
pub struct CreatedWebhook {
    /// The persisted (redacted) subscription.
    pub subscription: WebhookSubscription,
    /// The plaintext signing secret, shown once.
    pub secret: String,
}

/// Application service for webhook subscription lifecycle and test delivery.
pub struct WebhookService {
    subscriptions: Arc<dyn WebhookSubscriptionStore>,
    outbox: Arc<dyn WebhookOutbox>,
    allow_private_targets: bool,
}

impl WebhookService {
    /// Construct with the subscription store, the delivery outbox (for `test`),
    /// and the SSRF opt-out flag from node config.
    pub fn new(
        subscriptions: Arc<dyn WebhookSubscriptionStore>,
        outbox: Arc<dyn WebhookOutbox>,
        allow_private_targets: bool,
    ) -> Self {
        Self {
            subscriptions,
            outbox,
            allow_private_targets,
        }
    }

    /// List all subscriptions (active and retired), secrets redacted.
    pub async fn list(&self) -> Result<Vec<WebhookSubscription>, DppError> {
        self.subscriptions.list().await
    }

    /// Validate + persist a new subscription, returning its one-time secret.
    ///
    /// # Errors
    ///
    /// `DppError::Validation` if the URL fails the SSRF/https check or the event
    /// filter is empty.
    pub async fn create(
        &self,
        mut input: NewWebhookSubscription,
    ) -> Result<CreatedWebhook, DppError> {
        let normalised = validate_webhook_url(&input.url, self.allow_private_targets)
            .map_err(|m| DppError::Validation(m.into()))?;
        input.url = normalised;

        if input.events.is_empty() || input.events.iter().all(|e| e.trim().is_empty()) {
            return Err(DppError::Validation(
                "at least one event filter is required (use \"*\" for all events)".into(),
            ));
        }

        let secret = generate_secret();
        let subscription = self.subscriptions.create(&input, &secret).await?;
        Ok(CreatedWebhook {
            subscription,
            secret,
        })
    }

    /// Soft-remove a subscription.
    ///
    /// # Errors
    ///
    /// `DppError::NotFound` if `id` does not match a subscription.
    pub async fn deactivate(&self, id: Uuid) -> Result<(), DppError> {
        if self.subscriptions.get(id).await?.is_none() {
            return Err(DppError::NotFound(id.to_string()));
        }
        self.subscriptions.deactivate(id).await?;
        Ok(())
    }

    /// Enqueue a synthetic test delivery to one subscription (regardless of its
    /// event filter). The node's drain then signs and POSTs it like any event.
    ///
    /// # Errors
    ///
    /// `DppError::NotFound` if `id` does not match a subscription.
    pub async fn test(&self, id: Uuid) -> Result<(), DppError> {
        let sub = self
            .subscriptions
            .get(id)
            .await?
            .ok_or_else(|| DppError::NotFound(id.to_string()))?;
        let event = DppEvent::v1(
            WEBHOOK_TEST_EVENT,
            STANDALONE_OPERATOR_ID,
            serde_json::json!({
                "subscriptionId": sub.id,
                "message": "Test delivery from your Odal node.",
            }),
        );
        let body =
            serde_json::to_string(&event).map_err(|e| DppError::Serialisation(e.to_string()))?;
        self.outbox
            .enqueue_for(sub.id, &event.event_type, &body)
            .await?;
        Ok(())
    }
}

fn generate_secret() -> String {
    let mut buf = [0u8; SECRET_ENTROPY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let random = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    format!("{SECRET_PREFIX}{random}")
}
