# Authentication and Authorization

This document covers the authentication model in dpp-engine: how API requests are authenticated, what the auth context contains, and how new auth providers can be added.

---

## 1. Auth Context

Every authenticated request carries an `AuthContext` injected into Axum request extensions by the auth middleware. The node is single-tenant, so the context identifies *which user/key* made the request — **not** an operator or tenant scope:

```rust
pub struct AuthContext {
    pub user_id: String,        // Authenticated user/key identifier
    pub plan: String,           // Operator plan label (reserved; not used for gating)
    pub scope: ApiKeyScope,     // Credential authorization scope (N-2): Admin / Write / Read
    pub key_id: Option<Uuid>,   // Id of the authenticating API key; None for admin Basic auth.
                                // Used to forbid a key from revoking itself (self-lockout guard).
}
```

Handlers extract this from the request:

```rust
async fn create_handler(
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateRequest>,
) -> Result<Json<Passport>, AppError> {
    // auth.user_id is available here
}
```

---

## 2. Auth Middleware

The `auth_middleware` function wraps all `/api/v1/*` routes in `dpp-vault`. It runs before any handler and:

1. Extracts the `Authorization` header
2. Passes it to the `CompositeAuthProvider`
3. On success: injects `AuthContext` into request extensions
4. On failure: returns 401 Unauthorized

```rust
.route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
```

Public routes (`/health`, `/ready`, `/public/dpp/{id}`) are outside this middleware layer.

---

## 3. Auth Providers

### 3.1 CompositeAuthProvider

Chains multiple providers. Each provider returns one of:
- `Ok(AuthContext)` — authenticated successfully
- `Err(NotApplicable)` — this provider doesn't handle this token format, try the next
- `Err(...)` — hard failure (invalid key, expired, suspended)

The chain stops on the first success or hard failure.

### 3.2 ApiKeyAuthProvider

Matches `Bearer odal_sk_...` tokens.

**Flow:**
1. Extract token from `Authorization: Bearer odal_sk_...` header
2. Derive prefix from the token (first 12 characters)
3. Look up active API key record by prefix via `ApiKeyRepository::find_active_by_prefix()`
4. Compute SHA-256 hash of the full token
5. Compare against stored `keyHash`
6. If match: return an `AuthContext` carrying the key's `scope` and its `key_id` (single-tenant — no operator scope)

**Security properties:**
- The full key is never stored — only the SHA-256 hash
- The prefix allows efficient DB lookup without scanning all keys
- Revoked keys (`isActive = false`) are rejected
- Expired keys (`expiresAt < now`) are rejected
- **Self-lockout guard:** `DELETE /api/v1/api-keys/{id}` returns `409 Conflict` when `{id}` is the key authenticating the request — a key cannot revoke itself. Admin Basic auth (whose `key_id` is `None`) can revoke any key, which is the lockout-recovery path (`odal bootstrap --force`).

### 3.3 LocalAuthProvider

Matches HTTP Basic authentication against environment variables.

**Flow:**
1. Extract `Authorization: Basic base64(user:pass)` header
2. Compare against `ADMIN_USERNAME` and `ADMIN_PASSWORD` env vars
3. If match: return an admin-scoped `AuthContext` with `key_id: None` (no backing key row)

This provider is only active when both env vars are set. It provides a simple admin login for self-hosted deployments without needing to manage API keys.

### 3.4 DevAuthProvider — removed (Phase 0 / audit finding V0)

`DevAuthProvider` (unsigned JWT extraction for integration tests) was removed in the Phase 0 strip. Integration tests now define their own test-local auth stub rather than relying on a shipped bypass provider. `AuthContext` carries no operator/tenant scope; it is `{ user_id, plan }` only.

---

## 4. Adding a New Auth Provider

1. Implement the `AuthProvider` trait:

```rust
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, req: &Request) -> Result<AuthContext, AuthError>;
}
```

2. Add the provider to the composite chain in `dpp-node/src/main.rs`:

```rust
let mut providers: Vec<Box<dyn AuthProvider>> = vec![
    Box::new(ApiKeyAuthProvider::new(api_key_repo)),
    Box::new(YourNewProvider::new(...)),
];
```

3. Return `Err(AuthError::NotApplicable)` if the token format doesn't match your provider. This lets the chain continue to the next provider.

---

## 5. Route Protection Summary

| Route Pattern | Auth Required | Notes |
|---|---|---|
| `/health`, `/ready` | No | Infrastructure probes |
| `/vault/health`, `/vault/ready` | No | Service health |
| `/vault/api/v1/info` | No | Build info |
| `/vault/public/dpp/{id}` | No | Public passport read |
| `/vault/api/v1/*` | Yes | All DPP CRUD, operator config, API keys |
| `/identity/*` | No / mTLS | Health is open; signing/rotation require internal access |
| `/integrator/api/v1/import/*` | Yes | Bearer token forwarded from vault |
| `/integrator/api/v1/imports/*` | No | Job status polling |

---

## 6. Future: OAuth / OIDC

Post-MVP, an `OAuthAuthProvider` can be added to the composite chain. The existing middleware and handler code does not change — only the provider list grows. The `AuthContext` struct already carries `plan` as a reserved operator label (not used for gating).
