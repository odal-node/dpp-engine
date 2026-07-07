//! Stable event codes for security and business events.
//!
//! Attach as a structured field so alerting rules survive message rewording:
//!
//! ```rust,ignore
//! tracing::warn!(code = event_codes::AUTH_FAILED, operator_id = %op, "auth failed");
//! ```
//!
//! Each code is a stable, named alert signal — alerting rules key on these
//! codes (not on log message text), so the codes must never be renamed.

// ── Authentication ───────────────────────────────────────────────────────────

/// Any authentication provider rejected the token after all were tried.
pub const AUTH_FAILED: &str = "AUTH_FAILED";

/// API key was found but has passed its expiry date.
pub const AUTH_KEY_EXPIRED: &str = "AUTH_KEY_EXPIRED";

/// API key was explicitly revoked before expiry.
pub const AUTH_KEY_REVOKED: &str = "AUTH_KEY_REVOKED";

// ── JWS / passport integrity ─────────────────────────────────────────────────

/// JWS signature check failed or served content differs from signed payload.
/// A spike indicates a tampering attempt or a key-rotation bug.
pub const JWS_TAMPER: &str = "JWS_TAMPER";

/// Publish was blocked because signing failed and the node is configured
/// fail-closed (post W-1 fix).
pub const JWS_UNSIGNED_PUBLISH_BLOCKED: &str = "JWS_UNSIGNED_PUBLISH_BLOCKED";

/// Operator DID document could not be fetched or parsed.
pub const DID_UNREACHABLE: &str = "DID_UNREACHABLE";

// ── Plugin sandbox ───────────────────────────────────────────────────────────

/// Plugin loader rejected a .wasm file (bad signature, wrong ABI, or
/// schema range mismatch).
pub const PLUGIN_REFUSED: &str = "PLUGIN_REFUSED";

/// Plugin hit the per-invocation fuel limit imposed by the sandbox.
pub const PLUGIN_FUEL_EXHAUSTED: &str = "PLUGIN_FUEL_EXHAUSTED";

/// Plugin hit the per-invocation memory cap imposed by the sandbox.
pub const PLUGIN_MEM_CAPPED: &str = "PLUGIN_MEM_CAPPED";

// ── Data retention ───────────────────────────────────────────────────────────

/// Archive request was blocked by the ESPR retention policy.
pub const RETENTION_BLOCKED: &str = "RETENTION_BLOCKED";

// ── EU registry sync ─────────────────────────────────────────────────────────

/// Registry sync failed after exhausting all retries, or the registry is
/// permanently unreachable. Also used for status-enqueue failures on
/// suspend/archive/EOL (`dpp-vault::domain::service`) — these are non-fatal,
/// the local passport state is authoritative.
pub const REGISTRY_SYNC_FAILED: &str = "REGISTRY_SYNC_FAILED";

// ── Ruleset (compliance calculators) ─────────────────────────────────────────

/// A ruleset bundle failed to load at boot; the node stays on its baseline
/// bundle (fail-closed). Fires in `dpp-node::main`.
pub const RULESET_LOAD_FAILED: &str = "RULESET_LOAD_FAILED";

// ── Trust / ghost-honesty guard ──────────────────────────────────────────────

/// A production node refused to boot because a required trust port (seal,
/// registry sync, archive) resolved to a ghost. Fires in `dpp-node::main`,
/// immediately before the process exits — logged for boot-loop diagnosis.
pub const TRUST_GHOST_BOOT_REFUSED: &str = "TRUST_GHOST_BOOT_REFUSED";

// ── Transfer of responsibility ───────────────────────────────────────────────

/// The incoming operator's `accept_transfer` rejected the outgoing operator's
/// signature — fail-closed, the handover is not completed. Fires in
/// `dpp-vault::domain::service`.
pub const TRANSFER_SIGNATURE_INVALID: &str = "TRANSFER_SIGNATURE_INVALID";

// ── Key store ────────────────────────────────────────────────────────────────

/// Key store HMAC validation failed on open — the store may be corrupted or
/// tampered with.  Must page; never scroll past.
pub const KEYSTORE_INTEGRITY_FAIL: &str = "KEYSTORE_INTEGRITY_FAIL";

// ─── Cross-service passport-mutability contract ──────────────────────────────

/// Passport JSON fields that legitimately change after the initial signing
/// (status transitions, QR URL, publication timestamp, etc.) and are therefore
/// excluded from the resolver's content-binding comparison.
///
/// **Single source of truth.** The DB retention trigger's `mutable_keys` array
/// in `0004_passport.sql` is manually maintained to match this list. A CI test
/// in `dpp-resolver` asserts the two sets are equal so they cannot silently
/// diverge (DAL D2).
pub const MUTABLE_FIELDS: &[&str] = &[
    "status",
    "jwsSignature",
    "publicJwsSignature",
    "qrCodeUrl",
    "publishedAt",
    "retentionLocked",
    "updatedAt",
];
