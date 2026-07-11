//! Dossier-side JWS helpers on top of `dpp_crypto::jws`.
//!
//! `dpp-crypto` exposes the raw verifier and the DID-document key-extraction
//! functions; what it does not expose is payload decoding and content
//! binding, which dossier verification needs — those live here.

use anyhow::anyhow;
use base64::Engine;
use dpp_crypto::jws::{
    canonicalize, extract_key_by_fingerprint, extract_kid_from_jws, extract_primary_public_key,
    verify_jws,
};

/// Resolve the public key to verify `jws` against, from a DID document.
///
/// If the JWS carries a `kid`, it must resolve to a key by fingerprint (this
/// includes rotation-archived keys). A present-but-unresolvable `kid` (revoked,
/// rotated out, or simply wrong) returns `None` so the caller surfaces an
/// accurate "kid does not resolve" diagnosis — it does **not** silently
/// substitute the primary key. The primary-key fallback is reserved for legacy
/// tokens signed before `kid` was added, i.e. tokens carrying no `kid` at all.
pub(crate) fn resolve_public_key(jws: &str, did_document: &serde_json::Value) -> Option<String> {
    match extract_kid_from_jws(jws) {
        Some(kid) => extract_key_by_fingerprint(did_document, &kid),
        None => extract_primary_public_key(did_document),
    }
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

    fn did_doc_for(signing_key: &SigningKey) -> serde_json::Value {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let x = b64.encode(signing_key.verifying_key().to_bytes());
        serde_json::json!({
            "verificationMethod": [{
                "id": "did:web:example.com#root",
                "type": "JsonWebKey2020",
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
            }],
            "assertionMethod": ["did:web:example.com#root"],
        })
    }

    #[test]
    fn content_binding_rejects_signature_over_different_content() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let did_doc = did_doc_for(&signing_key);
        let key = resolve_public_key("x.x.x", &did_doc).unwrap();

        let signed = serde_json::json!({"a": 1});
        let jws = sign(&signing_key, &signed);

        assert!(verify_jws_content(&jws, &key, &signed).unwrap());
        let other = serde_json::json!({"a": 2});
        assert!(
            !verify_jws_content(&jws, &key, &other).unwrap(),
            "a valid signature over different content must not verify"
        );
    }

    #[test]
    fn resolve_falls_back_to_primary_key_without_kid() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let did_doc = did_doc_for(&signing_key);
        let jws = sign(&signing_key, &serde_json::json!({"a": 1})); // header has no kid
        let key = resolve_public_key(&jws, &did_doc);
        assert!(key.is_some(), "must fall back to the primary key");
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
            "not-a-real-fingerprint",
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
