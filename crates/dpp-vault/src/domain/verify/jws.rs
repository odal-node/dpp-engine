//! Dossier-side JWS helpers on top of `dpp_crypto::jws`.
//!
//! `dpp-crypto` exposes the raw verifier and the DID-document key resolution;
//! what it does not expose is payload decoding and content binding, which
//! dossier verification needs — those live here.

use anyhow::anyhow;
use base64::Engine;
use dpp_crypto::jws::{canonicalize, resolve_verification_key, verify_jws};

/// Resolve the public key to verify `jws` against, from a DID document.
///
/// The `kid` must name a verification method the document publishes and
/// references from `assertionMethod` (this includes rotation-archived keys). A
/// `kid` that names none (revoked, rotated out, or simply wrong) returns `None`
/// so the caller surfaces an accurate "kid does not resolve" diagnosis. So does a
/// token with no `kid` at all: it is not checked against a key chosen for it.
pub(crate) fn resolve_public_key(jws: &str, did_document: &serde_json::Value) -> Option<String> {
    resolve_verification_key(did_document, jws)
}

/// Decode the payload segment of a compact JWS to raw bytes (post-base64,
/// pre-JSON-parse).
pub(crate) fn decode_payload_bytes(jws: &str) -> anyhow::Result<Vec<u8>> {
    let payload_b64 = jws
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("JWS has no payload segment"))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| anyhow!("payload base64: {e}"))
}

/// Verify both that `jws` is validly signed under `public_key_b64` **and**
/// that its embedded payload is exactly the JCS-canonical bytes of
/// `expected`.
///
/// The plain `verify_jws` only checks the signature is internally
/// consistent — it says nothing about *what* was signed. Every signer in
/// this system embeds `base64url(JCS(payload))` as the payload segment
/// (`dpp-crypto`'s `jws::signer`), so content-binding means recomputing
/// those same canonical bytes and comparing. Without this step a validly
/// signed JWS over the *wrong* content would incorrectly verify.
pub(crate) fn verify_jws_content(
    jws: &str,
    public_key_b64: &str,
    expected: &serde_json::Value,
) -> anyhow::Result<bool> {
    if !verify_jws(jws, public_key_b64)? {
        return Ok(false);
    }
    let actual = decode_payload_bytes(jws)?;
    let expected_bytes = canonicalize(expected)?;
    Ok(actual == expected_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(signing_key: &SigningKey, payload: &serde_json::Value) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(serde_json::to_vec(&serde_json::json!({"alg": "EdDSA"})).unwrap());
        let body = b64.encode(canonicalize(payload).unwrap());
        let signing_input = format!("{header}.{body}");
        let sig = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64.encode(sig.to_bytes()))
    }

    fn sign_with_kid(signing_key: &SigningKey, payload: &serde_json::Value, kid: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64
            .encode(serde_json::to_vec(&serde_json::json!({"alg": "EdDSA", "kid": kid})).unwrap());
        let body = b64.encode(canonicalize(payload).unwrap());
        let signing_input = format!("{header}.{body}");
        let sig = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64.encode(sig.to_bytes()))
    }

    /// The method the document publishes, which a `kid` names in full.
    const METHOD: &str = "did:web:example.com#root";

    fn did_doc_for(signing_key: &SigningKey) -> serde_json::Value {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let x = b64.encode(signing_key.verifying_key().to_bytes());
        serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": METHOD,
                "type": "JsonWebKey",
                "controller": "did:web:example.com",
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
            }],
            "assertionMethod": [METHOD],
        })
    }

    #[test]
    fn content_binding_rejects_signature_over_different_content() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let did_doc = did_doc_for(&signing_key);

        let signed = serde_json::json!({"a": 1});
        let jws = sign_with_kid(&signing_key, &signed, METHOD);
        let key = resolve_public_key(&jws, &did_doc).unwrap();

        assert!(verify_jws_content(&jws, &key, &signed).unwrap());
        let other = serde_json::json!({"a": 2});
        assert!(
            !verify_jws_content(&jws, &key, &other).unwrap(),
            "a valid signature over different content must not verify"
        );
    }

    #[test]
    fn a_token_without_a_kid_resolves_to_no_key() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let did_doc = did_doc_for(&signing_key);
        let jws = sign(&signing_key, &serde_json::json!({"a": 1})); // header has no kid
        assert!(
            resolve_public_key(&jws, &did_doc).is_none(),
            "a token that names no key must not be checked against the document's only one"
        );
    }

    #[test]
    fn resolve_returns_none_for_present_but_unresolvable_kid() {
        // A kid that resolves to no key in the DID document (revoked/rotated
        // out/wrong) must NOT silently substitute the primary key — return None
        // so the caller reports the accurate "kid does not resolve" diagnosis.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let did_doc = did_doc_for(&signing_key);
        let jws = sign_with_kid(
            &signing_key,
            &serde_json::json!({"a": 1}),
            "did:web:example.com#not-a-real-method",
        );
        assert!(
            resolve_public_key(&jws, &did_doc).is_none(),
            "an unresolvable kid must not fall back to the primary key"
        );
    }

    #[test]
    fn decode_payload_bytes_rejects_segmentless_input() {
        assert!(decode_payload_bytes("no-dots-here").is_err());
    }
}
