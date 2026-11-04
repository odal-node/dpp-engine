# Authentication and authorisation

How API requests are authenticated in `dpp-engine`, what the auth context carries, and how
to add an auth provider.

---

## 1. Auth context

Every authenticated request carries an `AuthContext`, which the auth middleware puts into
the Axum request extensions. The node is single-tenant, so the context identifies *which
user or key* made the request, not an operator or tenant:

```rust
pub struct AuthContext {
    pub user_id: String,        // the authenticated user or key
    pub scope: ApiKeyScope,     // Admin, Write or Read
    pub key_id: Option<Uuid>,   // the API key's id; None for local admin Basic auth.
                                // Used to stop a key from revoking itself.
}
```

Handlers extract it from the request:

```rust
async fn create_handler(
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreatePassportRequest>,
) -> Result<Json<Passport>, AppError> {
    // auth.user_id and auth.scope are available here
}
```

Admin-only and write-only routes check the scope in the handler (`require_admin`,
`require_write`), not in the middleware. `GET /vault/api/v1/whoami` returns the presented
credential's `userId`, `scope` and `keyId`.

---

## 2. Auth middleware

`auth_middleware` wraps every `/api/v1/*` route in `dpp-vault`. It runs before any handler
and:

1. Reads the `Authorization` header and its scheme (`Bearer` or `Basic`).
2. Routes by scheme: `Bearer` goes to the Bearer provider chain (`CompositeAuthProvider`,
   §3.1), and `Basic` to the local admin provider (§3.3), never the other way round. The
   split matters: `LocalAuthProvider` base64-decodes whatever string it is given, so
   without it a `Bearer base64(user:pass)` token would authenticate as admin.
3. On success, puts the `AuthContext` into the request extensions.
4. On failure, returns `401 Unauthorized`.

```rust
.route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
```

Public routes (`/health`, `/ready`, `/public/dpp/{id}`) are outside this layer.

---

## 3. Auth providers

All providers implement:

```rust
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError>;
}
```

`AuthError` is `Missing` (no credentials), `Invalid(String)` (unrecognised, expired or
revoked) or `Suspended`.

### 3.1 CompositeAuthProvider

Chains the **Bearer** providers. Only `ApiKeyAuthProvider` exists today; an OAuth provider
would join here (§6). Each provider returns:

- `Ok(AuthContext)`: authenticated;
- `Err(AuthError::Suspended)`: a hard failure that stops the chain;
- `Err(AuthError::Invalid(_))`: this provider does not recognise the token (wrong format,
  or no matching record), so the chain tries the next one.

The chain stops at the first success or at `Suspended`. If every provider returns
`Invalid`, the last error is returned. `Basic` credentials never reach this chain (§3.3).

### 3.2 ApiKeyAuthProvider

Handles `Bearer odal_sk_...` tokens:

1. Take the token from `Authorization: Bearer odal_sk_...`.
2. Derive its prefix (the first 12 characters).
3. Look up the active key by prefix with `ApiKeyRepository::find_active_by_prefix()`.
4. Hash the full token with SHA-256.
5. Compare with the stored `keyHash`.
6. On a match, return an `AuthContext` with the key's `scope` and `key_id`.

**Security properties:**

- Only the SHA-256 hash of a key is stored, never the key.
- The prefix allows an indexed lookup without scanning all keys.
- Revoked keys (`isActive = false`) are rejected.
- Expired keys (`expiresAt < now`) are rejected.
- **A key cannot revoke itself:** `DELETE /api/v1/api-keys/{id}` returns `409 Conflict`
  when `{id}` is the key making the request. Local admin Basic auth (whose `key_id` is
  `None`) can revoke any key, which is the lockout-recovery path
  (`odal bootstrap --force`).

### 3.3 LocalAuthProvider

Handles HTTP Basic authentication against environment variables:

1. Take `Authorization: Basic base64(user:pass)`.
2. Compare with `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
3. On a match, return an admin-scoped `AuthContext` with `key_id: None` (no key row behind
   it).

The provider exists only when both variables are set, and is reached only through the
`Basic` scheme. It is not part of `CompositeAuthProvider` and is never tried against a
`Bearer` token, even one carrying the same `base64(user:pass)` payload. It is the
bootstrap and lockout-recovery credential for a self-hosted node; set it while
bootstrapping and unset it afterwards.

### 3.4 No development bypass provider

An earlier `DevAuthProvider` accepted unsigned JWTs for integration tests. It was removed
because it allowed an authentication bypass. Integration tests define their own test-only
provider instead of relying on one that ships.

---

## 4. Adding an auth provider

1. Implement `AuthProvider` (§3).
2. Add it to the composite chain where the node is assembled, in `dpp-node`:

   ```rust
   let providers: Vec<Box<dyn AuthProvider>> = vec![
       Box::new(ApiKeyAuthProvider::new(api_key_repo)),
       Box::new(YourNewProvider::new(...)),
   ];
   ```

3. Return `Err(AuthError::Invalid(_))` for a token your provider does not recognise, so the
   chain moves on to the next provider.

---

## 5. Route protection

| Route pattern | Auth | Notes |
|---|---|---|
| `/health`, `/ready` | None | Infrastructure probes |
| `/vault/health`, `/vault/ready` | None | Service health |
| `/vault/api/v1/info` | None | Build information |
| `/vault/public/dpp/{id}` | None | Public passport read |
| `/vault/credential/dpp/{id}` | `X-DPP-Credential` header | Audience-scoped read for credential holders; without a credential, the public view |
| `/vault/api/v1/*` | Bearer or Basic | Passports, operator configuration, API keys; some routes also need the `write` or `admin` scope |
| `/vault/internal/scan-batch` | mTLS | The resolver's scan-count flush |
| `/identity/*` | None | The node mounts only the public identity routes (health, DID document) |
| `/integrator/api/v1/import/*` | Bearer | The token is validated against the vault and forwarded |
| `/integrator/api/v1/imports/*` | Bearer | Job status, validated against the vault |
| `/integrator/api/v1/templates/*` | None | CSV templates |

The OpenAPI description in [`api/`](../../api/) is the authoritative list of routes and the
scheme each one accepts.

---

## 6. Later: OAuth and OIDC

An `OAuthAuthProvider` can be added to the composite chain without changing the middleware
or handler code; only the provider list grows.
