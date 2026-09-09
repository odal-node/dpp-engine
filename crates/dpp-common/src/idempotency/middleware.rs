//! The axum middleware that claims, replays and refuses.

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::{
    policy::{RoutePolicy, policy_for},
    store::{
        Claim, DEFAULT_LEASE, DEFAULT_RETENTION, IdempotencyStore, RequestKey, StoredResponse,
        fingerprint,
    },
};
use crate::http_problem::Problem;

/// The header a client sends to make a write retry-safe.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Largest request or response body the middleware will buffer.
///
/// It has to hold the whole body to digest it and to store it, so this is a
/// real cap and not a formality. Above the node's 8 MiB request limit, so it
/// never becomes the thing that rejects a request the server would otherwise
/// have accepted.
const MAX_BUFFER: usize = 9 * 1024 * 1024;

/// Longest `Idempotency-Key` accepted. A key is a client-minted correlation
/// token — a UUID is 36 characters — and the column is the primary key, so an
/// unbounded one is an index-bloat vector.
const MAX_KEY_LEN: usize = 255;

/// Resolves the calling principal from a request.
///
/// A closure rather than a trait because the two services that mount keyed
/// routes answer it in genuinely different ways — the vault reads the
/// `AuthContext` its middleware inserted, the integrator (which authenticates
/// inside its handlers) derives a digest of the bearer token — and neither
/// crate can see the other's auth model.
///
/// `None` means the request is unauthenticated, which cannot be keyed: there
/// would be nothing to scope the key to, and an unscoped key is a probe
/// surface.
pub type PrincipalResolver = Arc<dyn Fn(&Request) -> Option<String> + Send + Sync>;

/// Everything the middleware needs, so it can be a plain `from_fn_with_state`
/// on any router that mounts keyed routes.
#[derive(Clone)]
pub struct IdempotencyLayerState {
    /// Where claims and outcomes live.
    pub store: Arc<dyn IdempotencyStore>,
    /// How to name the caller a key is scoped to.
    pub principal: PrincipalResolver,
}

impl std::fmt::Debug for IdempotencyLayerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyLayerState")
            .finish_non_exhaustive()
    }
}

/// Enforce idempotency keys on the routes [`policy_for`] names.
///
/// A request with no `Idempotency-Key` passes straight through, keyed route or
/// not: the header is opt-in, and making it mandatory would break every caller
/// for the benefit of the ones that retry.
pub async fn idempotency_middleware(
    State(state): State<IdempotencyLayerState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(raw_key) = request.headers().get(IDEMPOTENCY_KEY_HEADER).cloned() else {
        return next.run(request).await;
    };

    let key_str = match raw_key.to_str() {
        Ok(k) if !k.trim().is_empty() && k.len() <= MAX_KEY_LEN => k.trim().to_owned(),
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Malformed Idempotency Key",
                &format!(
                    "`Idempotency-Key` must be non-empty printable ASCII of at most \
                     {MAX_KEY_LEN} characters."
                ),
            );
        }
    };

    let template = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();

    // Refused, not ignored. Accepting the header here would tell the caller its
    // retry is protected on a route where nothing is recording it.
    let Some(policy) = policy_for(request.method(), &template) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Idempotency Key Not Accepted Here",
            &format!(
                "`{} {template}` does not accept an `Idempotency-Key`. It is idempotent by \
                 shape — repeating it reaches the same state — so a key would record nothing. \
                 Retry it directly.",
                request.method()
            ),
        );
    };

    let Some(principal) = (state.principal)(&request) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Idempotency Key Without A Caller",
            "`Idempotency-Key` is scoped to the authenticated caller, and this request has \
             none. Authenticate, or omit the header.",
        );
    };

    let key = RequestKey {
        principal,
        method: request.method().as_str().to_owned(),
        path: template,
        key: key_str,
    };

    // The body has to be buffered to be digested, and buffering consumes it, so
    // the request is rebuilt around the bytes before the handler ever sees it.
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_BUFFER).await {
        Ok(b) => b,
        Err(_) => {
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request Too Large To Make Idempotent",
                "The request body exceeds what can be buffered to fingerprint it. Resend \
                 without an `Idempotency-Key`, or send a smaller body.",
            );
        }
    };
    let fp = fingerprint(&bytes);

    match state
        .store
        .claim(&key, &fp, DEFAULT_LEASE, DEFAULT_RETENTION)
        .await
    {
        Ok(Claim::Replay(stored)) => return replay(&stored),
        Ok(Claim::InFlight) => {
            return problem(
                StatusCode::CONFLICT,
                "Idempotent Request In Flight",
                "An earlier attempt with this `Idempotency-Key` is still running. Retry \
                 shortly; do not change the body.",
            )
            .tap_header("retry-after", "1");
        }
        Ok(Claim::FingerprintMismatch) => {
            // 422 rather than 409: 409 means "the resource is in the wrong
            // state" everywhere else in this API, and this is a statement about
            // the *request*. Matches the IETF idempotency-key draft.
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Idempotency Key Reuse",
                "This `Idempotency-Key` was already used for a request with a different body. \
                 A retry must resend byte-identical bytes — member order and whitespace count, \
                 because the fingerprint is over the raw body. Use a new key for a new request.",
            );
        }
        Ok(Claim::Claimed) => {}
        Err(e) => {
            // Fail closed. Running the handler anyway would execute the write
            // with no record, which is exactly the outcome the caller asked to
            // be protected from.
            tracing::error!(error = %e, "idempotency store unavailable; refusing the write");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Idempotency Store Unavailable",
                "The record that makes this request safe to retry could not be written, so \
                 the request was not run. Retry with the same key.",
            );
        }
    }

    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;

    record_outcome(&state, &key, policy, response).await
}

/// Store the outcome and hand the response on unchanged.
async fn record_outcome(
    state: &IdempotencyLayerState,
    key: &RequestKey,
    policy: RoutePolicy,
    response: Response,
) -> Response {
    let status = response.status();

    // A `5xx` releases the claim rather than recording it: the request failed
    // in a way the client should be able to retry, and a recorded server error
    // would replay the failure for a day. A `4xx` is a deterministic rejection
    // of this exact body — replaying it is correct and costs nothing.
    if status.is_server_error() {
        if let Err(e) = state.store.release(key).await {
            tracing::warn!(error = %e, "could not release an idempotency claim after a 5xx");
        }
        return response;
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let (parts, body) = response.into_parts();
    let bytes = match to_bytes(body, MAX_BUFFER).await {
        Ok(b) => b,
        Err(e) => {
            // The body is consumed and cannot be recovered. Release rather than
            // record — better a re-executed retry than a replayed empty body.
            tracing::warn!(error = %e, "response too large to record for replay; releasing the claim");
            if let Err(e) = state.store.release(key).await {
                tracing::warn!(error = %e, "could not release an idempotency claim");
            }
            return Response::from_parts(parts, Body::empty());
        }
    };

    let stored = StoredResponse {
        status: status.as_u16(),
        body: redact(&bytes, policy),
        content_type,
    };

    // The residual window this whole design leaves open: the handler has
    // already committed, and if this fails the key expires `in_flight` and a
    // later retry re-executes. Unavoidable without enlisting in the handler's
    // transaction, which the per-operation repository ports do not permit. It
    // is today's behaviour, so it is never a regression — but it is a warning,
    // not a debug line, because it is the one case a duplicate can still occur.
    if let Err(e) = state.store.complete(key, &stored).await {
        tracing::warn!(
            error = %e,
            "the write committed but its idempotency record did not; a retry may duplicate"
        );
    }

    Response::from_parts(parts, Body::from(bytes))
}

/// Remove the members `policy` names from a JSON body, marking that a secret
/// was already delivered.
///
/// A body that is not JSON, or that names none of them, is returned untouched.
fn redact(bytes: &[u8], policy: RoutePolicy) -> Vec<u8> {
    if policy.redact.is_empty() {
        return bytes.to_vec();
    }
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        // Not JSON, so nothing can be named — but the policy says this route
        // returns a secret, so storing the bytes is not safe. Store nothing
        // recognisable rather than guessing.
        return Vec::new();
    };
    if let Some(obj) = value.as_object_mut() {
        for member in policy.redact {
            obj.remove(*member);
        }
        if policy.secret_already_delivered_marker {
            obj.insert(
                "secretAlreadyDelivered".to_owned(),
                serde_json::Value::Bool(true),
            );
        }
    }
    serde_json::to_vec(&value).unwrap_or_default()
}

/// Rebuild a stored response.
fn replay(stored: &StoredResponse) -> Response {
    let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    let mut response = (status, stored.body.clone()).into_response();
    if let Some(ct) = stored
        .content_type
        .as_deref()
        .and_then(|v| HeaderValue::from_str(v).ok())
    {
        response.headers_mut().insert(CONTENT_TYPE, ct);
    }
    // So a client can tell a replay from a first execution without diffing
    // anything — it is the difference between "my retry worked" and "my retry
    // created a second one", and the whole point is that it should not have to
    // guess.
    response
        .headers_mut()
        .insert("idempotency-replayed", HeaderValue::from_static("true"));
    response
}

/// An RFC 7807 refusal with its own `type` URI.
///
/// Built from `Problem` directly rather than through a status-derived helper:
/// the `type` is derived from the *title*, so a shared "Unprocessable Entity"
/// title would make every one of these indistinguishable from every other
/// validation failure — which is exactly the thing a client needs to branch on
/// here.
fn problem(status: StatusCode, title: &str, detail: &str) -> Response {
    Problem::new(status, title)
        .with_detail(detail)
        .into_response()
}

/// Small helper so a refusal can carry one extra header without unpacking.
trait TapHeader {
    fn tap_header(self, name: &'static str, value: &'static str) -> Self;
}

impl TapHeader for Response {
    fn tap_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers_mut()
            .insert(name, HeaderValue::from_static(value));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn secret_policy() -> RoutePolicy {
        policy_for(&axum::http::Method::POST, "/vault/api/v1/api-keys").unwrap()
    }

    fn plain_policy() -> RoutePolicy {
        policy_for(&axum::http::Method::POST, "/vault/api/v1/dpp").unwrap()
    }

    #[test]
    fn a_verbatim_route_is_stored_byte_for_byte() {
        let body = br#"{"id":"abc","name":"n"}"#;
        assert_eq!(redact(body, plain_policy()), body.to_vec());
    }

    #[test]
    fn a_secret_is_never_stored_and_its_absence_is_stated() {
        let body = serde_json::to_vec(&json!({
            "key": { "id": "k1", "keyPrefix": "odal_ab" },
            "secret": "odal_ab_thisisthesecret",
        }))
        .unwrap();

        let stored = redact(&body, secret_policy());
        let back: serde_json::Value = serde_json::from_slice(&stored).unwrap();

        assert!(
            !String::from_utf8_lossy(&stored).contains("thisisthesecret"),
            "the plaintext secret must not reach the store"
        );
        assert_eq!(back["secretAlreadyDelivered"], json!(true));
        // The rest of the resource survives, so the replay still identifies
        // which key was created — that is what makes the orphan actionable.
        assert_eq!(back["key"]["id"], json!("k1"));
    }

    /// A secret-bearing route that answered with something unparseable stores
    /// nothing rather than storing bytes it cannot inspect.
    #[test]
    fn an_unparseable_secret_bearing_body_stores_nothing() {
        assert!(redact(b"odal_ab_rawsecret", secret_policy()).is_empty());
    }

    #[test]
    fn a_replay_says_so_in_a_header() {
        let stored = StoredResponse {
            status: 201,
            body: b"{}".to_vec(),
            content_type: Some("application/json".into()),
        };
        let response = replay(&stored);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("idempotency-replayed").unwrap(),
            "true"
        );
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    /// The assumption the whole policy table rests on, asserted rather than
    /// trusted: inside a `route_layer` on a doubly-nested router, `MatchedPath`
    /// reports the **full** template including both `nest` prefixes.
    ///
    /// If axum ever reported only the innermost segment, every lookup in
    /// [`policy_for`] would miss, every keyed route would silently stop being
    /// keyed, and nothing else in this crate would notice. That is the failure
    /// this test exists to make loud.
    #[tokio::test]
    async fn matched_path_inside_a_nested_route_layer_is_the_full_template() {
        use axum::{Router, body::Body, extract::Request, routing::post};
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;

        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured = seen.clone();

        let inner = Router::new()
            .route("/dpp/{dppId}/evidence", post(|| async { "ok" }))
            .route_layer(axum::middleware::from_fn(
                move |request: Request, next: Next| {
                    let captured = captured.clone();
                    async move {
                        *captured.lock().unwrap() = request
                            .extensions()
                            .get::<axum::extract::MatchedPath>()
                            .map(|m| m.as_str().to_owned());
                        next.run(request).await
                    }
                },
            ));

        // Mirrors the real assembly: the vault nests `/api/v1`, the node nests
        // `/vault` over that.
        let app = Router::new().nest("/vault", Router::new().nest("/api/v1", inner));

        app.oneshot(
            Request::post("/vault/api/v1/dpp/abc/evidence")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some("/vault/api/v1/dpp/{dppId}/evidence"),
            "the policy table is written in full-path form; if this is the \
             inner template instead, every keyed route has silently stopped \
             being keyed"
        );
    }

    /// Every refusal this middleware raises must be distinguishable by `type`,
    /// which is derived from the title. Two sharing a title would collapse into
    /// one URI and a client could not branch on them.
    #[test]
    fn every_refusal_has_its_own_problem_type() {
        let titles = [
            "Malformed Idempotency Key",
            "Idempotency Key Not Accepted Here",
            "Idempotency Key Without A Caller",
            "Request Too Large To Make Idempotent",
            "Idempotent Request In Flight",
            "Idempotency Key Reuse",
            "Idempotency Store Unavailable",
        ];
        let mut types: Vec<String> = titles
            .iter()
            .map(|t| Problem::new(StatusCode::BAD_REQUEST, *t).problem_type)
            .collect();
        types.sort();
        let before = types.len();
        types.dedup();
        assert_eq!(before, types.len(), "two refusals share a problem type URI");
    }
}
