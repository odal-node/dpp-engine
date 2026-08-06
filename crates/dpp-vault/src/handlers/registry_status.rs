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
struct RegistrationView {
    /// Queue state: `pending`, `submitted`, `registered`, `rejected`,
    /// `deactivated`.
    status: &'static str,
    /// The registry's own record id, once it has issued one.
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_id: Option<String>,
    /// The last thing the registry (or the drain) said about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Attempts so far, and whether that count has reached the stall threshold.
    attempts: i32,
    stalled: bool,
    /// A status change owed to the registry, independent of the queue state.
    #[serde(skip_serializing_if = "Option::is_none")]
    status_intent: Option<&'static str>,
}

/// One transfer-of-responsibility notification.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferView {
    transfer_id: uuid::Uuid,
    /// Queue state: `pending`, `notified`, `rejected`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    attempts: i32,
    stalled: bool,
}

/// `GET /api/v1/dpp/{dppId}/registry` response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportRegistryView {
    passport_id: String,
    /// Whether this deployment has registry queues at all.
    configured: bool,
    /// `None` when the passport has never been published — it owes no
    /// registration, which is different from owing one that has not happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    registration: Option<RegistrationView>,
    /// Every handover notification recorded for this passport, newest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transfers: Vec<TransferView>,
}

/// `GET /api/v1/registry` response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryRollupView {
    configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    registrations: Option<RegistrationCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transfers: Option<TransferCounts>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationCounts {
    pending: i64,
    submitted: i64,
    registered: i64,
    rejected: i64,
    deactivated: i64,
    status_intents: i64,
    /// Rows that have retried past the point of self-recovery.
    stalled: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferCounts {
    pending: i64,
    notified: i64,
    rejected: i64,
    stalled: i64,
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

    (
        StatusCode::OK,
        Json(PassportRegistryView {
            passport_id: dpp_id,
            configured: true,
            registration,
            transfers,
        }),
    )
        .into_response()
}

/// The operator-wide rollup: what is outstanding, and what needs a human.
pub async fn registry_rollup_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let Some(outbox) = state.service.registry_outbox.as_ref() else {
        return (
            StatusCode::OK,
            Json(RegistryRollupView {
                configured: false,
                registrations: None,
                transfers: None,
            }),
        )
            .into_response();
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
            registrations: Some(registrations),
            transfers,
        }),
    )
        .into_response()
}
