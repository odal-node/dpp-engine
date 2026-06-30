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
/// permanently unreachable.
pub const REGISTRY_SYNC_FAILED: &str = "REGISTRY_SYNC_FAILED";

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
