//! Client-supplied idempotency keys: the port, the route policy, and the
//! middleware that enforces both.
//!
//! # What this is for
//!
//! A client whose `POST` times out cannot tell whether it landed. The internal
//! outbox makes *our* side of event delivery idempotent; it does nothing for
//! the caller. This lets a caller resend the same request under the same
//! `Idempotency-Key` and get the first outcome back, without creating a second
//! resource.
//!
//! # Why it lives in `dpp-common`
//!
//! Two crates mount keyed routes — `dpp-vault` and `dpp-integrator` — and
//! neither depends on the other. `dpp-common` is the only crate both already
//! reach that has `axum`, and the contents here carry no domain types: a key, a
//! digest, a status and some bytes. Putting the port in `dpp-types` with every
//! other port was the alternative, and it would have meant `dpp-common`
//! depending on `dpp-types`, which drags `dpp-types` and `dpp-rules` into
//! `dpp-resolver`'s build for nothing.
//!
//! # Scope is chosen by effect, not by verb
//!
//! See [`policy`]. The test is not "is this method idempotent" but *does a
//! replay create a second thing, or spend something that cannot be un-spent*.
//! `PUT` and the lifecycle transitions converge on their own and are
//! deliberately unkeyed; a key sent to one of those is **refused**, not
//! ignored, because accepting it would tell a client its retry is protected
//! when it is not.

mod middleware;
mod policy;
mod store;

pub use middleware::{
    IDEMPOTENCY_KEY_HEADER, IdempotencyLayerState, PrincipalResolver, idempotency_middleware,
};
pub use policy::{RoutePolicy, policy_for};
pub use store::{
    Claim, DEFAULT_LEASE, DEFAULT_RETENTION, IdempotencyError, IdempotencyStore, RequestKey,
    StoredResponse, fingerprint,
};
