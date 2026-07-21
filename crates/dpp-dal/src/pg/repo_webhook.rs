//! `WebhookSubscriptionStore` + `WebhookOutbox` on PostgreSQL (`ops/pg/0022`).
//!
//! Two tables, one repo: `webhook_subscription` (receiver config) and
//! `webhook_delivery` (the durable outbox). Enqueue fans out one delivery per
//! matching active subscription; the node's drain loop POSTs each with an HMAC
//! signature and records the terminal (`delivered`/`exhausted`) or transient
//! (backoff) outcome — the same shape as `repo_registry_sync`, minus the
//! transactional publish coupling (webhook enqueue is after-commit).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_types::{
    NewWebhookSubscription, WebhookCounts, WebhookDeliveryRow, WebhookOutbox, WebhookSubscription,
    WebhookSubscriptionStore,
};

use super::{PgDal, db_err, require_updated};

/// PostgreSQL implementation of the webhook subscription store and delivery outbox.
pub struct PgWebhookRepo {
    dal: PgDal,
}

impl PgWebhookRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn row_to_subscription(row: &sqlx::postgres::PgRow) -> WebhookSubscription {
        WebhookSubscription {
            id: row.get::<Uuid, _>("id"),
            url: row.get::<String, _>("url"),
            events: row.get::<Vec<String>, _>("events"),
            active: row.get::<bool, _>("active"),
            description: row.get::<Option<String>, _>("description"),
            created_at: row.get::<DateTime<Utc>, _>("created_at"),
            updated_at: row.get::<DateTime<Utc>, _>("updated_at"),
        }
    }
}

#[async_trait]
impl WebhookSubscriptionStore for PgWebhookRepo {
    async fn create(
        &self,
        input: &NewWebhookSubscription,
        secret: &str,
    ) -> Result<WebhookSubscription, DppError> {
        let row = sqlx::query(
            r#"INSERT INTO odal.webhook_subscription (url, secret, events, description)
               VALUES ($1, $2, $3, $4)
               RETURNING id, url, events, active, description, created_at, updated_at"#,
        )
        .bind(&input.url)
        .bind(secret)
        .bind(&input.events)
        .bind(&input.description)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(Self::row_to_subscription(&row))
    }

    async fn list(&self) -> Result<Vec<WebhookSubscription>, DppError> {
        let rows = sqlx::query(
            r#"SELECT id, url, events, active, description, created_at, updated_at
               FROM odal.webhook_subscription
               ORDER BY created_at DESC"#,
        )
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::row_to_subscription).collect())
    }

    async fn get(&self, id: Uuid) -> Result<Option<WebhookSubscription>, DppError> {
        let row = sqlx::query(
            r#"SELECT id, url, events, active, description, created_at, updated_at
               FROM odal.webhook_subscription
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(Self::row_to_subscription))
    }

    async fn deactivate(&self, id: Uuid) -> Result<bool, DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.webhook_subscription SET active = false, updated_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }
}

#[async_trait]
impl WebhookOutbox for PgWebhookRepo {
    async fn enqueue(&self, event_type: &str, body: &str) -> Result<u64, DppError> {
        // Fan out to every active subscription whose filter matches this event
        // (exact subject or the `*` wildcard). Insert..select keeps it to one
        // round-trip regardless of subscriber count.
        let res = sqlx::query(
            r#"INSERT INTO odal.webhook_delivery (subscription_id, event_type, body)
               SELECT id, $1, $2 FROM odal.webhook_subscription
               WHERE active AND ($1 = ANY(events) OR '*' = ANY(events))"#,
        )
        .bind(event_type)
        .bind(body)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected())
    }

    async fn enqueue_for(
        &self,
        subscription_id: Uuid,
        event_type: &str,
        body: &str,
    ) -> Result<u64, DppError> {
        // Deliberately ignores the subscription's filter — the `test` endpoint
        // proves a specific receiver end-to-end. Still keyed on the row existing.
        let res = sqlx::query(
            r#"INSERT INTO odal.webhook_delivery (subscription_id, event_type, body)
               SELECT id, $2, $3 FROM odal.webhook_subscription WHERE id = $1"#,
        )
        .bind(subscription_id)
        .bind(event_type)
        .bind(body)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected())
    }

    async fn due(&self, limit: i64) -> Result<Vec<WebhookDeliveryRow>, DppError> {
        let rows = sqlx::query(
            r#"SELECT d.id AS delivery_id, d.subscription_id, s.url, s.secret,
                      d.event_type, d.body, d.attempts
               FROM odal.webhook_delivery d
               JOIN odal.webhook_subscription s ON s.id = d.subscription_id
               WHERE d.status = 'pending' AND d.next_attempt_at <= now()
               ORDER BY d.next_attempt_at ASC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows
            .iter()
            .map(|row| WebhookDeliveryRow {
                delivery_id: row.get::<Uuid, _>("delivery_id"),
                subscription_id: row.get::<Uuid, _>("subscription_id"),
                url: row.get::<String, _>("url"),
                secret: row.get::<String, _>("secret"),
                event_type: row.get::<String, _>("event_type"),
                body: row.get::<String, _>("body"),
                attempts: row.get::<i32, _>("attempts"),
            })
            .collect())
    }

    async fn mark_delivered(&self, delivery_id: Uuid) -> Result<(), DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.webhook_delivery SET
                 status = 'delivered',
                 delivered_at = now(),
                 last_attempt_at = now(),
                 attempts = attempts + 1,
                 message = NULL,
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(delivery_id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "webhook_delivery row", delivery_id)
    }

    async fn mark_attempt_failed(
        &self,
        delivery_id: Uuid,
        message: String,
    ) -> Result<(), DppError> {
        // Exponential backoff on the *new* attempt count, capped at 1h, with
        // 0.75–1.25× jitter to avoid thundering-herd retries — identical to the
        // registry-sync outbox. `attempts` is the pre-increment value.
        let res = sqlx::query(
            r#"UPDATE odal.webhook_delivery SET
                 attempts = attempts + 1,
                 message = $2,
                 last_attempt_at = now(),
                 next_attempt_at = now()
                   + (LEAST(power(2, attempts + 1), 3600) * (0.75 + random() * 0.5))
                     * interval '1 second',
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(delivery_id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "webhook_delivery row", delivery_id)
    }

    async fn mark_exhausted(&self, delivery_id: Uuid, message: String) -> Result<(), DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.webhook_delivery SET
                 status = 'exhausted',
                 message = $2,
                 last_attempt_at = now(),
                 attempts = attempts + 1,
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(delivery_id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "webhook_delivery row", delivery_id)
    }

    async fn status_counts(&self) -> Result<WebhookCounts, DppError> {
        let row = sqlx::query(
            r#"SELECT
                 count(*) FILTER (WHERE status = 'pending')   AS pending,
                 count(*) FILTER (WHERE status = 'delivered') AS delivered,
                 count(*) FILTER (WHERE status = 'exhausted') AS exhausted
               FROM odal.webhook_delivery"#,
        )
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(WebhookCounts {
            pending: row.get::<i64, _>("pending"),
            delivered: row.get::<i64, _>("delivered"),
            exhausted: row.get::<i64, _>("exhausted"),
        })
    }
}
