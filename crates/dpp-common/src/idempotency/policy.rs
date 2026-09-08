//! Which routes accept an idempotency key, and what may be stored for each.
//!
//! # The test is effect, not verb
//!
//! A route is keyed when a replay would **create a second thing, or spend
//! something that cannot be un-spent**. It is not keyed when a second call
//! converges on the same state.
//!
//! That distinction is why `PUT /dpp/{dppId}` and every lifecycle transition
//! are absent below. They converge — and the honest qualification is that they
//! converge in *state*, not in *effects*: a second publish appends an audit row
//! and re-signs. The seal outbox already handles its half (migration 0028 keys
//! on `(passport_id, payload_hash)`, so re-enqueuing unchanged content is
//! free), and a duplicate audit entry is a faithful record that the operation
//! was invoked twice.
//!
//! # A key on an unkeyed route is refused
//!
//! [`policy_for`] returning `None` is not "ignore the header". The middleware
//! answers `400`. Accepting and discarding the key would tell a client its
//! retry is protected when it is not, which is the one failure mode worse than
//! having no keys at all.

use axum::http::Method;

/// What the middleware may store for one keyed route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutePolicy {
    /// JSON member names stripped from the response before it is stored.
    ///
    /// Non-empty for exactly the two routes whose success body carries a
    /// secret shown once. Storing those verbatim would park a live credential
    /// in a table for a day, breaking a property the code states explicitly:
    /// the secret is returned once and listings expose only the prefix.
    ///
    /// The replay therefore differs in shape from the first response — the only
    /// such divergence in the set, and a deliberate one. A pointer-to-resource
    /// design would have diverged for *every* route, and could not have worked
    /// for these two at all, since the secret is not readable from the resource
    /// afterwards.
    pub redact: &'static [&'static str],
    /// Inserted as `true` alongside a redaction, so the replay says plainly
    /// that the secret was already delivered and is unrecoverable — which is
    /// the fact the operator needs in order to act (revoke the orphan, or find
    /// where the first response went).
    pub secret_already_delivered_marker: bool,
}

impl RoutePolicy {
    /// A route whose response may be stored and replayed verbatim.
    const fn verbatim() -> Self {
        Self {
            redact: &[],
            secret_already_delivered_marker: false,
        }
    }

    /// A route whose response carries a once-only secret.
    const fn secret_bearing(redact: &'static [&'static str]) -> Self {
        Self {
            redact,
            secret_already_delivered_marker: true,
        }
    }
}

/// The keyed routes, by method and **matched route template**.
///
/// Templates, not concrete URIs: the template identifies the operation and is
/// drawn from a bounded set, so a caller cannot mint unbounded distinct store
/// rows by varying a path parameter.
///
/// Paths are as the service crate registers them, before the node's `nest`
/// prefix — `axum`'s `MatchedPath` reports the full nested template, so the
/// prefixes appear here too. The route-coverage half of the OpenAPI contract
/// test is what keeps these strings honest against the routers.
const KEYED: &[(Method, &str, RoutePolicy)] = &[
    // ── Creates: a new row with a server-minted id ───────────────────────────
    (Method::POST, "/vault/api/v1/dpp", RoutePolicy::verbatim()),
    (
        Method::POST,
        "/vault/api/v1/dpp/{dppId}/evidence",
        RoutePolicy::verbatim(),
    ),
    (
        Method::POST,
        "/vault/api/v1/plugins",
        RoutePolicy::verbatim(),
    ),
    // Retire-not-delete (migrations 0013 and 0014 revoked the DELETE grants),
    // so an accidental duplicate here is permanent — the sharpest case in the
    // set after the two secret-bearing ones.
    (
        Method::POST,
        "/vault/api/v1/facilities",
        RoutePolicy::verbatim(),
    ),
    (
        Method::POST,
        "/vault/api/v1/operator-identifiers",
        RoutePolicy::verbatim(),
    ),
    // ── Creates whose response carries a once-only secret ────────────────────
    (
        Method::POST,
        "/vault/api/v1/api-keys",
        RoutePolicy::secret_bearing(&["secret"]),
    ),
    (
        Method::POST,
        "/vault/api/v1/webhooks",
        RoutePolicy::secret_bearing(&["secret"]),
    ),
    // ── The importer: one job, which then creates passports ──────────────────
    (
        Method::POST,
        "/integrator/api/v1/import/{productGroup}",
        RoutePolicy::verbatim(),
    ),
    // ── The one keyed route that creates nothing ─────────────────────────────
    //
    // Scan ingest is an *additive* write —
    // `count = odal.scan_telemetry.count + EXCLUDED.count` — so a re-sent
    // window is added twice. That is not "a second resource" but it is the same
    // harm under the same test: a replay spends something that cannot be
    // un-spent, because there is no way to subtract a count nobody knows was
    // double-added.
    //
    // It is also the only route with a caller that actually retries today. The
    // resolver holds a failed window and re-sends it byte-for-byte under a
    // stable key; before that it folded the window back into its live counters,
    // which double-counted every request the node committed but never managed
    // to acknowledge.
    (
        Method::POST,
        "/vault/internal/scan-batch",
        RoutePolicy::verbatim(),
    ),
];

/// The policy for `method` + `template`, or `None` when the route is not keyed.
#[must_use]
pub fn policy_for(method: &Method, template: &str) -> Option<RoutePolicy> {
    KEYED
        .iter()
        .find(|(m, p, _)| m == method && *p == template)
        .map(|(_, _, policy)| *policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_creates_are_keyed_and_the_transitions_are_not() {
        assert!(policy_for(&Method::POST, "/vault/api/v1/dpp").is_some());
        // Converges: a second publish reaches the same state.
        assert!(policy_for(&Method::POST, "/vault/api/v1/dpp/{dppId}/publish").is_none());
        // A read wearing POST.
        assert!(policy_for(&Method::POST, "/vault/api/v1/dpp/validate").is_none());
        // Method matters: GET on a keyed path is not keyed.
        assert!(policy_for(&Method::GET, "/vault/api/v1/dpp").is_none());
    }

    #[test]
    fn only_the_two_secret_bearing_creates_redact() {
        let redacting: Vec<&str> = KEYED
            .iter()
            .filter(|(_, _, p)| !p.redact.is_empty())
            .map(|(_, path, _)| *path)
            .collect();
        assert_eq!(
            redacting,
            vec!["/vault/api/v1/api-keys", "/vault/api/v1/webhooks"],
            "a new redacting route is a deliberate divergence in replay shape \
             and must be argued for, not added quietly"
        );
    }

    /// Guards the count rather than the contents, so adding or removing a keyed
    /// route is a visible decision. The list itself is asserted above by kind,
    /// and `dpp-node`'s `idempotency_policy` suite asserts every template here
    /// is a route the assembled node actually serves.
    ///
    /// Eight creates plus the additive scan ingest. Not the ten the design note
    /// first counted: `POST /credentials` and `POST /unsold-goods` do not exist
    /// on `main`. They are on an unmerged branch, and both are creates, so both
    /// belong here the day it lands.
    #[test]
    fn the_keyed_set_is_nine_routes() {
        assert_eq!(KEYED.len(), 9);
    }

    /// Two entries for the same operation would make `policy_for` depend on
    /// declaration order, and the second would be unreachable.
    #[test]
    fn no_operation_is_listed_twice() {
        for (i, (m, p, _)) in KEYED.iter().enumerate() {
            assert!(
                !KEYED[i + 1..].iter().any(|(m2, p2, _)| m2 == m && p2 == p),
                "{m} {p} is listed twice"
            );
        }
    }
}
