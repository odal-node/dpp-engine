//! Shared Axum application state for the identity service.

use std::sync::Arc;

use dpp_crypto::keystore::KeyStore;

/// Shared Axum application state — cloned cheaply per-request.
#[derive(Clone)]
pub struct AppState {
    /// The AES-256-GCM encrypted Ed25519 key store — holds all operator signing keys.
    pub store: Arc<KeyStore>,
    /// Base URL used when constructing `did:web` DID document identifiers,
    /// e.g. `https://identity.odal-node.io`.
    pub did_web_base_url: String,
}

impl AppState {
    /// The absolute DID URL of the verification method that names `operator_id`'s
    /// current key: this service's DID, `#`, and the key's thumbprint URI.
    ///
    /// It is the identifier [`dpp_vc::did_builder::build_did_document`] gives the
    /// key, so it is both the `kid` a token signed with the key carries and the
    /// `id` of its method. A thumbprint is derived from the public key alone, so
    /// the name does not change when the key is rotated out.
    ///
    /// # Errors
    ///
    /// When the operator has no key, or its recorded public key is unreadable.
    pub(crate) fn verification_method_url(&self, operator_id: &str) -> anyhow::Result<String> {
        let key = self
            .store
            .public_key(operator_id)
            .ok_or_else(|| anyhow::anyhow!("no key found for {operator_id}"))?;
        Ok(format!(
            "{}#{}",
            dpp_vc::did_builder::did_for(&self.did_web_base_url),
            key.thumbprint_uri()?
        ))
    }

    /// Sign `payload` as `operator_id`, under the name of the key that signs it.
    ///
    /// # Errors
    ///
    /// When the key cannot be named or the signature cannot be made, and when the
    /// key was rotated while the token was being made: see [`sign_naming_key`].
    pub(crate) fn sign(
        &self,
        operator_id: &str,
        payload: &serde_json::Value,
    ) -> anyhow::Result<String> {
        sign_naming_key(
            || self.verification_method_url(operator_id),
            |kid| dpp_crypto::jws::sign(&self.store, operator_id, payload, kid),
        )
    }
}

/// Make a token under the name `name` gives the signing key, and refuse it if the
/// key changed while it was being made.
///
/// The `kid` is read from the key store and the signature is made from a second
/// read of it, and the store locks per read, not across both. A rotation landing
/// between them would put the old key's name on the new key's signature: a token
/// that never verifies, which publish would then store in a record that is frozen
/// and cannot be re-signed. Reading the name again afterwards catches it: a
/// rotation between the two reads always leaves the second name different. A
/// rotation that lands after the key was read costs only a retry.
fn sign_naming_key(
    name: impl Fn() -> anyhow::Result<String>,
    sign: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let kid = name()?;
    let jws = sign(&kid)?;
    anyhow::ensure!(
        name()? == kid,
        "the signing key was rotated while signing; retry"
    );
    Ok(jws)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::sign_naming_key;

    #[test]
    fn a_token_made_under_one_key_is_returned() {
        let jws = sign_naming_key(
            || Ok("did:web:x#key-a".to_owned()),
            |kid| Ok(format!("signed under {kid}")),
        )
        .expect("the key did not change");
        assert_eq!(jws, "signed under did:web:x#key-a");
    }

    /// 🚨 The key is rotated after it was named and before it signs: the name on
    /// the token would be the old key's, the signature the new key's. It must be
    /// refused, not returned.
    #[test]
    fn a_rotation_between_naming_and_signing_is_refused() {
        let rotated = Cell::new(false);
        let result = sign_naming_key(
            || {
                Ok(if rotated.get() {
                    "did:web:x#key-new"
                } else {
                    "did:web:x#key-old"
                }
                .to_owned())
            },
            |_| {
                rotated.set(true);
                Ok("a token signed by the new key under the old key's name".to_owned())
            },
        );
        let error = result.expect_err("a token whose key changed under it must not be returned");
        assert!(
            error.to_string().contains("rotated while signing"),
            "{error}"
        );
    }
}
