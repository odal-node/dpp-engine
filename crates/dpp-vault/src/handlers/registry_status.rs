//! `GET /api/v1/dpp/{dppId}/registry` and `GET /api/v1/registry` — what the EU
//! registry knows about this operator's passports.
//!
//! Registration is the legal obligation the rest of the system exists to
//! discharge, and until these routes existed an operator had no way to see
//! whether it had been discharged: the state lived in outbox tables, Prometheus
//! gauges and log lines, none of which an operator can reach.
//!
//! # Absent is not the same as zero
//!
//! A deployment without the Postgres outboxes has no registry state at all.
//! Reporting that as a row of zeros would read as "everything is registered",
//! which is the opposite of the truth. Both routes say `configured: false`
//! instead, and omit the counts.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, parse_passport_id};

/// Attempts after which a row is reported as stalled rather than merely
/// retrying. Matches the node's drain-task threshold; a row that has failed this
/// many times is not going to succeed without someone looking at it.
const STALL_THRESHOLD: i32 = 5;

/// One passport's registration, as the registry queue holds it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationView {
    /// Queue state: `pending`, `submitted`, `registered`, `rejected`,
    /// `deactivated`.
    pub status: &'static str,
    /// The registry's own record id, once it has issued one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_id: Option<String>,
    /// The last thing the registry (or the drain) said about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Attempts so far, and whether that count has reached the stall threshold.
    pub attempts: i32,
    pub stalled: bool,
    /// A status change owed to the registry, independent of the queue state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_intent: Option<&'static str>,
}

/// One transfer-of-responsibility notification.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferView {
    pub transfer_id: uuid::Uuid,
    /// Queue state: `pending`, `notified`, `rejected`.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub attempts: i32,
    pub stalled: bool,
}

/// `GET /api/v1/dpp/{dppId}/registry` response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportRegistryView {
    pub passport_id: String,
    /// Whether this deployment has registry queues at all.
    pub configured: bool,
    /// `None` when the passport has never been published — it owes no
    /// registration, which is different from owing one that has not happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationView>,
    /// Every handover notification recorded for this passport, newest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<TransferView>,
    /// Who is responsible for this passport **now**, from its transfer chain.
    ///
    /// Reported separately because the passport's own `operatorIdentifier` is
    /// the operator that *published* it, frozen at publish and covered by the
    /// signature — it is not rewritten by a transfer and cannot be. For a
    /// passport that has changed hands the two differ, and that difference is a
    /// fact about the product, not a defect. `None` when the passport has never
    /// been transferred, in which case the passport's own field is current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_operator: Option<CurrentOperatorView>,
}

/// The operator responsible for a passport today, per its transfer chain.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentOperatorView {
    pub did: String,
    pub name: String,
    pub country: String,
    /// How many completed handovers this passport has been through.
    pub transfer_count: usize,
}

/// `GET /api/v1/registry` response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRollupView {
    pub configured: bool,
    /// Whether this operator may currently register anything at all.
    pub verification: VerificationView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrations: Option<RegistrationCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfers: Option<TransferCounts>,
}

/// The operator's verified-registry standing.
///
/// Verified status ends when the electronic identification means used expire,
/// and at the latest three years after verification. An operator that lets it
/// lapse cannot register or amend anything until it verifies again, so this is
/// reported whether or not the queues are configured.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationView {
    /// `false` both when never verified and when lapsed — the registry refuses
    /// either way, though they are different situations to act on.
    pub current: bool,
    /// `None` when never verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The three-year cap. The eID means may expire sooner, which this cannot
    /// see, so it is an upper bound rather than a promise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Days remaining, negative once lapsed. Absent when never verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCounts {
    pub pending: i64,
    pub submitted: i64,
    pub registered: i64,
    pub rejected: i64,
    pub deactivated: i64,
    /// Status changes owed to the registry. Nothing drains these — the registry
    /// publishes no status-push API — so they are held durably and counted here
    /// rather than accumulating out of sight.
    pub status_intents: i64,
    /// Rows that have retried past the point of self-recovery.
    pub stalled: i64,
    /// Published passports with **no** outbox row at all.
    ///
    /// These owe a registration nobody is tracking: passports published before
    /// the outbox existed, or lost to an older write path. They are reported,
    /// not repaired — the queued payload is what a drain replays, and there is
    /// none to rebuild, so fabricating a row would create an entry that can
    /// never drain.
    pub unregistered_published: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCounts {
    pub pending: i64,
    pub notified: i64,
    pub rejected: i64,
    pub stalled: i64,
}

fn registration_status(s: dpp_types::RegistrySyncStatus) -> &'static str {
    s.as_db()
}

fn transfer_status(s: dpp_types::RegistryTransferStatus) -> &'static str {
    s.as_db()
}

/// One passport's registry position.
pub async fn passport_registry_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let Some(outbox) = state.service.registry_outbox.as_ref() else {
        return (
            StatusCode::OK,
            Json(PassportRegistryView {
                passport_id: dpp_id,
                configured: false,
                registration: None,
                transfers: Vec::new(),
                current_operator: None,
            }),
        )
            .into_response();
    };

    let registration = match outbox.pending_for(passport_id).await {
        Ok(row) => row.map(|r| RegistrationView {
            status: registration_status(r.status),
            registry_id: r.registry_id,
            message: r.message,
            attempts: r.attempts,
            stalled: r.status.is_drainable() && r.attempts >= STALL_THRESHOLD,
            status_intent: r.status_intent.map(|i| i.as_db()),
        }),
        Err(e) => return internal_error(format!("reading registry state: {e}")),
    };

    let transfers = match state.service.transfer_outbox.as_ref() {
        Some(transfers) => match transfers.rows_for(passport_id).await {
            Ok(rows) => rows
                .into_iter()
                .map(|r| TransferView {
                    transfer_id: r.transfer_id,
                    status: transfer_status(r.status),
                    registry_id: r.registry_id,
                    message: r.message,
                    attempts: r.attempts,
                    stalled: r.status == dpp_types::RegistryTransferStatus::Pending
                        && r.attempts >= STALL_THRESHOLD,
                })
                .collect(),
            Err(e) => return internal_error(format!("reading transfer notifications: {e}")),
        },
        None => Vec::new(),
    };

    // Only report a current operator when the chain says responsibility has
    // actually moved. An untransferred passport's own field is still current,
    // and echoing it here would imply a handover that never happened.
    let current_operator = match state.service.transfer_store.as_ref() {
        Some(store) => match store.get_chain(passport_id).await {
            Ok(Some(chain)) if chain.transfer_count() > 0 => {
                let op = chain.current_operator();
                Some(CurrentOperatorView {
                    did: op.did.clone(),
                    name: op.name.clone(),
                    country: op.country.clone(),
                    transfer_count: chain.transfer_count(),
                })
            }
            Ok(_) => None,
            Err(e) => return internal_error(format!("reading transfer chain: {e}")),
        },
        None => None,
    };

    (
        StatusCode::OK,
        Json(PassportRegistryView {
            passport_id: dpp_id,
            configured: true,
            registration,
            transfers,
            current_operator,
        }),
    )
        .into_response()
}

/// The operator-wide rollup: what is outstanding, and what needs a human.
pub async fn registry_rollup_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let verification = verification_view(&state).await;

    let Some(outbox) = state.service.registry_outbox.as_ref() else {
        return (
            StatusCode::OK,
            Json(RegistryRollupView {
                configured: false,
                verification,
                registrations: None,
                transfers: None,
            }),
        )
            .into_response();
    };

    let unregistered_published = match outbox.unregistered_published_count().await {
        Ok(n) => n,
        Err(e) => return internal_error(format!("counting unregistered published passports: {e}")),
    };

    let registrations = match outbox.status_counts(STALL_THRESHOLD).await {
        Ok(c) => RegistrationCounts {
            pending: c.pending,
            submitted: c.submitted,
            registered: c.registered,
            rejected: c.rejected,
            deactivated: c.deactivated,
            status_intents: c.status_intents,
            stalled: c.stalled,
            unregistered_published,
        },
        Err(e) => return internal_error(format!("reading registry counts: {e}")),
    };

    let transfers = match state.service.transfer_outbox.as_ref() {
        Some(t) => match t.status_counts(STALL_THRESHOLD).await {
            Ok(c) => Some(TransferCounts {
                pending: c.pending,
                notified: c.notified,
                rejected: c.rejected,
                stalled: c.stalled,
            }),
            Err(e) => return internal_error(format!("reading transfer counts: {e}")),
        },
        None => None,
    };

    (
        StatusCode::OK,
        Json(RegistryRollupView {
            configured: true,
            verification,
            registrations: Some(registrations),
            transfers,
        }),
    )
        .into_response()
}

/// The operator's verified-registry standing, read live from operator config.
///
/// A read failure reports "not current" rather than erroring the whole rollup:
/// an operator asking "can I register?" is better served by a conservative no
/// than by a 500.
async fn verification_view(state: &AppState) -> VerificationView {
    let config = match state.service.registry_reader.as_ref() {
        Some(reader) => reader
            .get(dpp_types::STANDALONE_OPERATOR_ID)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let Some(config) = config else {
        return VerificationView {
            current: false,
            verified_at: None,
            expires_at: None,
            days_remaining: None,
        };
    };
    let now = chrono::Utc::now();
    let expires_at = config.registry_verification_expires_at();
    VerificationView {
        current: config.registry_verification_is_current(now),
        verified_at: config.registry_verified_at,
        expires_at,
        days_remaining: expires_at.map(|e| (e - now).num_days()),
    }
}
