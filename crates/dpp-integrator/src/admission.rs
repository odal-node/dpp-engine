//! Admission for `POST /api/v1/import/{productGroup}`: who may upload, and
//! whether the node has room for another import.
//!
//! # Why this is a layer and not the first lines of the handler
//!
//! A request with an `Idempotency-Key` is buffered whole by the idempotency
//! layer, which wraps the handler, before the handler runs. Admission done in
//! the handler therefore came after the body had been read, for those requests:
//! a junk token or a full node still cost a full upload, and the cap bounded the
//! imports that ran rather than the memory the uploads took.
//!
//! This layer is mounted outside the idempotency layer (see
//! [`crate::router::build`]), so for keyed and unkeyed requests alike it decides
//! before either of them reads a byte.
//!
//! # What it does, in order
//!
//! 1. Refuses headers that are no usable `multipart/form-data`: `400`. What the
//!    `Multipart` extractor always did before the handler ran, so a request that
//!    can never parse costs no vault call, no slot and no body read.
//! 2. Refuses a request with no `Bearer` token: `401`.
//! 3. Has the vault check the token: `401`. A merely non-empty token is not
//!    enough, or any junk string would drive the parser.
//! 4. Takes an import slot, or refuses with `429` and a `Retry-After`. After the
//!    token check, so an unauthenticated caller cannot fill the slots.
//! 5. Reads the upload, within [`UPLOAD_DEADLINE`] and [`IMPORT_BODY_LIMIT`].
//! 6. Hands the handler an [`Admitted`].
//!
//! Step 5 is here because the slot is held while it runs. If the idempotency
//! layer did the reading, as it does for any keyed request that gets past this
//! one, an upload that sent its headers and then stopped would hold a slot until
//! its connection closed, and with the default two slots that locks every other
//! import out. The limit covers the whole upload, not each read, so a sender
//! that drips a byte at a time cannot keep it open either. 120 s lets a 5 MiB
//! file through at about 44 KiB/s.
//!
//! The idempotency layer then fingerprints bytes already in memory. An import
//! turned away here has no claim to release, so it is never recorded under its
//! key; the layer's release of a `429` is a backstop, not the path this uses.

use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, to_bytes},
    extract::{FromRequest, Multipart, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem::{self, Problem};
use tokio::sync::OwnedSemaphorePermit;

use crate::{handlers::import::extract_bearer_token, state::AppState};

/// Hard cap on the size of an import upload body (5 MiB). Bounds the work an
/// authenticated caller can force the spreadsheet/CSV parser to do. Admission
/// reads the body under it, and the route sets it as the limit the `Multipart`
/// extractor reads through.
pub(crate) const IMPORT_BODY_LIMIT: usize = 5 * 1024 * 1024;

/// `Retry-After` on the `429` an import gets when no slot is free. A fixed
/// guess: how long a running import takes depends on its size, which this
/// request cannot know.
pub(crate) const IMPORT_BUSY_RETRY_AFTER_SECS: &str = "30";

/// How long an upload may take to arrive once its import holds a slot.
#[cfg(not(test))]
const UPLOAD_DEADLINE: Duration = Duration::from_secs(120);
/// Short enough for a test to wait out.
#[cfg(test)]
pub(crate) const UPLOAD_DEADLINE: Duration = Duration::from_secs(2);

/// What the handler receives from a request this layer let through.
///
/// A request reaches the handler only with one of these, so the handler holds a
/// token the vault accepted and a slot, and cannot be handed one without the
/// other. If the layer is ever left off the route the handler's extractor
/// refuses the request with a `500` instead of running an import nobody
/// admitted.
#[derive(Clone)]
pub struct Admitted {
    /// The caller's token, as the vault accepted it. Forwarded on every call
    /// the import makes.
    pub token: String,
    /// Held, never read: the slot goes back when the last clone of this is
    /// dropped. A synchronous import drops it on return; an import over the
    /// synchronous threshold moves it into its background task, so the `202`
    /// does not free it.
    _slot: Arc<OwnedSemaphorePermit>,
}

/// The refusal the `Multipart` extractor gives these headers, if it gives one.
///
/// The extractor is what decides whether a `Content-Type` is a usable
/// `multipart/form-data` with a boundary, so this asks it, on a request that
/// carries only that header, rather than restating its rule here.
async fn unusable_multipart_headers(headers: &HeaderMap) -> Option<Response> {
    let mut probe = Request::new(Body::empty());
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        probe
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type.clone());
    }
    Multipart::from_request(probe, &())
        .await
        .err()
        .map(IntoResponse::into_response)
}

/// Admit an import, or answer for it. See the module docs.
pub async fn admit_import(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Some(refusal) = unusable_multipart_headers(request.headers()).await {
        return refusal;
    }

    let token = match extract_bearer_token(request.headers()) {
        Some(t) if !t.is_empty() => t,
        _ => {
            metrics::counter!("import_rejections_total", "reason" => "auth").increment(1);
            return Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail("Missing or empty Authorization: Bearer token.")
                .into_response();
        }
    };

    if !state.vault_client.verify_token(&token).await {
        metrics::counter!("import_rejections_total", "reason" => "auth").increment(1);
        return Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
            .with_detail("Invalid or unauthorized Authorization: Bearer token.")
            .into_response();
    }

    let Ok(slot) = state.import_slots.clone().try_acquire_owned() else {
        metrics::counter!("import_rejections_total", "reason" => "busy").increment(1);
        let mut resp = Problem::new(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests")
            .with_detail(
                "This node is already running as many imports as it allows. \
                 Retry once one has finished.",
            )
            .into_response();
        resp.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(IMPORT_BUSY_RETRY_AFTER_SECS),
        );
        return resp;
    };

    // Returning from here drops the slot.
    let (mut parts, body) = request.into_parts();
    let bytes = match tokio::time::timeout(UPLOAD_DEADLINE, to_bytes(body, IMPORT_BODY_LIMIT)).await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            return http_problem::bad_request(format!("Failed to read uploaded file: {e}"))
                .into_response();
        }
        Err(_) => {
            metrics::counter!("import_rejections_total", "reason" => "upload_timeout").increment(1);
            return http_problem::bad_request(format!(
                "Failed to read uploaded file: it did not arrive within {} seconds.",
                UPLOAD_DEADLINE.as_secs()
            ))
            .into_response();
        }
    };

    parts.extensions.insert(Admitted {
        token,
        _slot: Arc::new(slot),
    });
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}
