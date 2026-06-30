//! `LocalAuthProvider` — Basic auth provider backed by `ADMIN_USERNAME`/`ADMIN_PASSWORD` env vars.

use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha256};

use dpp_types::{
    api_key::ApiKeyScope,
    auth::{AuthContext, AuthError, AuthProvider},
};

/// Auth provider for local bootstrap access via HTTP Basic auth.
///
/// Used to mint the first API key via the CLI before any API key exists.
/// Credentials are read from environment variables at startup; the password
/// is stored as a SHA-256 hash in memory, never as plaintext.
pub struct LocalAuthProvider {
    username: String,
    password_hash: String,
}

impl LocalAuthProvider {
    /// Construct with raw credentials — password is hashed and the plaintext is dropped.
    pub fn new(username: String, password: String) -> Self {
        let password_hash = hex::encode(Sha256::digest(password.as_bytes()));
        Self {
            username,
            password_hash,
        }
    }
}

#[async_trait]
impl AuthProvider for LocalAuthProvider {
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError> {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token)
            && let Ok(creds) = String::from_utf8(decoded)
            && let Some((user, pass)) = creds.split_once(':')
        {
            let pass_hash = hex::encode(Sha256::digest(pass.as_bytes()));
            use subtle::ConstantTimeEq;
            let hashes_match =
                bool::from(pass_hash.as_bytes().ct_eq(self.password_hash.as_bytes()));
            if user == self.username && hashes_match {
                return Ok(AuthContext {
                    user_id: "admin".to_owned(),
                    // Local admin (Basic) auth is always full-admin: it is
                    // the operator's own bootstrap credential (N-2).
                    scope: ApiKeyScope::Admin,
                    // No API key row backs admin Basic auth, so it can
                    // revoke any key (this is the lockout-recovery path).
                    key_id: None,
                });
            }
        }

        Err(AuthError::Invalid("invalid credentials".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[tokio::test]
    async fn valid_credentials_succeed() {
        let p = LocalAuthProvider::new("alice".into(), "secret123".into());
        let ctx = p.authenticate(&encode("alice:secret123")).await.unwrap();
        assert_eq!(ctx.user_id, "admin");
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let p = LocalAuthProvider::new("alice".into(), "secret123".into());
        assert!(matches!(
            p.authenticate(&encode("alice:wrongpass")).await,
            Err(AuthError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn wrong_username_rejected() {
        let p = LocalAuthProvider::new("alice".into(), "secret123".into());
        assert!(matches!(
            p.authenticate(&encode("bob:secret123")).await,
            Err(AuthError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn no_colon_separator_rejected() {
        let p = LocalAuthProvider::new("alice".into(), "secret123".into());
        assert!(matches!(
            p.authenticate(&encode("alicesecret123")).await,
            Err(AuthError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn non_base64_token_rejected() {
        let p = LocalAuthProvider::new("alice".into(), "secret123".into());
        assert!(matches!(
            p.authenticate("not valid base64!!!").await,
            Err(AuthError::Invalid(_))
        ));
    }
}
