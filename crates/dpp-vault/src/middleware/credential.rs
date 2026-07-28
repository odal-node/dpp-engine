//! `X-DPP-Credential` — presenting, authenticating and authorising an access credential.
//!
//! # Wire format: VC-JWT
//!
//! The header carries a **compact JWS** whose payload is the RFC 8785 (JCS)
//! canonical form of a [`DppAccessCredential`]. The credential model itself is
//! untouched — the envelope is external.
//!
//! Chosen over an embedded W3C Data Integrity `proof` member for four reasons,
//! recorded here because it is a wire-format decision that binds every issuer:
//!
//! 1. It reuses the verification path this workspace already has —
//!    [`extract_kid_from_jws`] → issuer DID document → [`extract_key_by_fingerprint`]
//!    → [`verify_jws`], with EdDSA pinned and `alg:none` rejected.
//! 2. One canonicalisation scheme (JCS) rather than two. A second signing scheme
//!    would be a permanent review burden on the most security-sensitive code here.
//! 3. Header-safe by construction: base64url, no escaping.
//! 4. It is the cheaper thing to change *from*. EN 18246 is unread and the ESPR
//!    Art. 11 credential implementing acts are unadopted, so this may need
//!    revisiting — and only the unwrap step would change, not the credential.
//!
//! # Why a dedicated header
//!
//! `Authorization` already routes by scheme in [`super::auth`]: `Bearer` reaches
//! the API-key providers, `Basic` the local admin. A credential is a different
//! axis — who the *reader* is, not whether the caller may write — and a machine
//! integration can hold both, so they must not compete for one slot.
//!
//! # What a [`VerifiedCredential`] means, and the one gap left
//!
//! It means: the JWS verified against a key published in the issuer's `did:web`
//! document, the claims window is current, and the issuer is trusted to attest
//! the audience the credential claims.
//!
//! Revocation is included: the status list is fetched after the signature holds
//! (an unsigned document's status URL is attacker chosen) and handed to core's
//! composed verifier, which treats an unreachable list as revoked whenever the
//! credential declares a status.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use dpp_common::http_problem;
use dpp_crypto::jws::verifier::{
    extract_key_by_fingerprint, extract_kid_from_jws, extract_primary_public_key, verify_jws,
};
use dpp_crypto::{DppAccessCredential, StatusList, TrustedIssuerRegistry};
use dpp_domain::Audience;

/// The header a caller presents an access credential in.
pub const CREDENTIAL_HEADER: &str = "X-DPP-Credential";

/// The network lookups credential verification needs.
///
/// A port rather than a concrete fetcher so the verification logic below stays
/// pure and testable: the network lives in the adapter, and a test supplies
/// documents directly. Returning `None` for any failure — unreachable,
/// malformed, unknown — keeps the fail-closed decision in one place rather than
/// spreading error mapping through the verifier.
///
/// Both lookups are on one trait because they share a client, a timeout and a
/// fail-closed rule; see [`crate::infra::credential_directory`].
#[async_trait::async_trait]
pub trait CredentialDirectory: Send + Sync {
    /// The issuer's `did:web` document, for the signing key.
    async fn did_document(&self, issuer_did: &str) -> Option<serde_json::Value>;

    /// The credential's revocation status list.
    ///
    /// `None` means **revoked** whenever the credential declares a status —
    /// core applies that policy, and it is why an unreachable list denies
    /// rather than passes.
    async fn status_list(&self, credential: &DppAccessCredential) -> Option<StatusList>;
}

/// A credential that verified against its issuer's published key, is within its
/// validity window, is not revoked, and whose issuer is trusted for the audience
/// it claims.
///
/// This is a grant: every check the engine can make has been made.
#[derive(Debug, Clone)]
pub struct VerifiedCredential(DppAccessCredential);

impl VerifiedCredential {
    /// The Art. 77(2) audience this credential grants.
    #[must_use]
    pub fn audience(&self) -> Audience {
        self.0.credential_subject.role.audience()
    }

    /// The underlying credential, for revocation checking and audit.
    #[must_use]
    pub fn credential(&self) -> &DppAccessCredential {
        &self.0
    }
}

/// Outcome of looking for a credential on a request.
pub enum CredentialOutcome {
    /// No `X-DPP-Credential` header. The caller is the general public.
    Absent,
    /// Verified, and trusted for the audience it claims.
    Verified(Box<VerifiedCredential>),
    /// Presented and unusable.
    Rejected(Response),
}

/// Decode the credential from a compact JWS payload segment.
///
/// Does not verify anything — the payload of an unverified JWS is attacker
/// controlled. Separate from verification so the ordering is impossible to get
/// wrong at a call site.
fn decode_payload(jws: &str) -> Option<DppAccessCredential> {
    let payload_b64 = jws.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Read, authenticate and authorise the credential on `request`.
///
/// Returns [`CredentialOutcome::Absent`] when the header is missing — the
/// ordinary public path, which must never be an error. ESPR Art. 11(b) requires
/// access free of charge, and the toy and detergent regulations forbid requiring
/// consumers to register or supply a password, so an unauthenticated read is the
/// product's baseline rather than a degraded case.
pub async fn read_and_verify(
    headers: &HeaderMap,
    directory: &dyn CredentialDirectory,
    trust: &dyn TrustedIssuerRegistry,
) -> CredentialOutcome {
    let Some(raw) = headers.get(CREDENTIAL_HEADER) else {
        return CredentialOutcome::Absent;
    };
    let Ok(jws) = raw.to_str() else {
        return CredentialOutcome::Rejected(reject("Credential header is not valid UTF-8."));
    };

    let Some(credential) = decode_payload(jws) else {
        return CredentialOutcome::Rejected(reject(
            "Credential is not a compact JWS carrying a DPP access credential.",
        ));
    };

    // Authenticate before doing anything with the claims: until the signature
    // verifies, `issuer` is a string the caller chose.
    let Some(did_doc) = directory.did_document(&credential.issuer).await else {
        return CredentialOutcome::Rejected(reject("Credential issuer DID could not be resolved."));
    };
    let key = extract_kid_from_jws(jws)
        .and_then(|kid| extract_key_by_fingerprint(&did_doc, &kid))
        .or_else(|| extract_primary_public_key(&did_doc));
    let Some(key) = key else {
        return CredentialOutcome::Rejected(reject(
            "Credential issuer DID document has no matching verification key.",
        ));
    };
    if !verify_jws(jws, &key).unwrap_or(false) {
        return CredentialOutcome::Rejected(reject("Credential signature did not verify."));
    }

    // Only now that the signature holds is it worth spending a network round
    // trip on revocation: an unsigned document's status URL is attacker chosen.
    let status_list = directory.status_list(&credential).await;

    // Claims, issuer trust and revocation in core's composed path, so the
    // fail-closed revocation policy is applied where it is defined rather than
    // re-implemented here. `required_sector`/`required_product_category` are
    // None: this layer does not know which passport is being read — scoping
    // belongs to the read handler, which does.
    let result = dpp_crypto::verify_credential_with_revocation_and_trust(
        &credential,
        None,
        None,
        chrono::Utc::now(),
        status_list.as_ref(),
        trust,
    );
    if !result.is_valid() {
        return CredentialOutcome::Rejected(reject(&format!(
            "Credential is not valid: {result:?}"
        )));
    }

    CredentialOutcome::Verified(Box::new(VerifiedCredential(credential)))
}

/// RFC 7807 rejection. 401 rather than 400: the request is well-formed HTTP; it
/// is the credential that failed, and the client's remedy is a different one.
///
/// The detail deliberately does not distinguish "unknown issuer" from "bad
/// signature" beyond what a holder needs to act on — enough to debug a genuine
/// integration, not a probe oracle for which issuers a node trusts.
fn reject(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            CREDENTIAL_HEADER.to_ascii_lowercase(),
        )],
        axum::Json(
            http_problem::Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail(detail),
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use dpp_crypto::{
        CredentialBuilder, CredentialRole, DppCredentialSubject, StaticTrustedIssuers,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const ISSUER: &str = "did:web:issuer.example";
    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// Mint a compact JWS over the JCS-canonical credential, exactly as
    /// `dpp_crypto::jws::sign` does — header `{alg,kid}`, JCS payload, EdDSA.
    fn sign_credential(key: &SigningKey, kid: &str, cred: &DppAccessCredential) -> String {
        let header = B64.encode(format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#).as_bytes());
        let value = serde_json::to_value(cred).expect("to value");
        let canonical = dpp_crypto::jws::canonicalize(&value).expect("canonicalize");
        let payload = B64.encode(&canonical);
        let signing_input = format!("{header}.{payload}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
    }

    fn credential(role: CredentialRole, days: i64) -> DppAccessCredential {
        CredentialBuilder::new(
            ISSUER.to_owned(),
            DppCredentialSubject {
                id: "did:web:holder.example".to_owned(),
                name: "Example Co".to_owned(),
                role,
                country: "DE".to_owned(),
                sectors: vec!["battery".to_owned()],
                product_categories: Vec::new(),
            },
        )
        .expires_at(Utc::now() + Duration::days(days))
        .build()
    }

    /// A DID document publishing `key` under `kid`.
    ///
    /// `assertionMethod` must reference the method: the shared extractor only
    /// accepts keys the document authorises for assertions, so a key published
    /// for some other purpose cannot sign a credential. Omitting it is a
    /// realistic issuer mistake and correctly yields no usable key.
    fn did_doc(key: &SigningKey, kid: &str) -> serde_json::Value {
        json!({
            "id": ISSUER,
            "assertionMethod": [format!("{ISSUER}#{kid}")],
            "verificationMethod": [{
                "id": format!("{ISSUER}#{kid}"),
                "type": "JsonWebKey2020",
                "controller": ISSUER,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": B64.encode(key.verifying_key().to_bytes()),
                }
            }]
        })
    }

    /// Stub directory: a DID document, and an optional status list.
    ///
    /// `status` is `None` by default, which is the *unrevoked* answer for a
    /// credential that declares no status — the fixtures here do not. A
    /// credential that *does* declare one and gets `None` is treated as revoked
    /// by core, which `a_declared_status_that_cannot_be_fetched_denies` covers.
    struct Directory {
        doc: Option<serde_json::Value>,
        status: Option<StatusList>,
    }

    impl Directory {
        fn with(doc: Option<serde_json::Value>) -> Self {
            Self { doc, status: None }
        }
    }

    #[async_trait::async_trait]
    impl CredentialDirectory for Directory {
        async fn did_document(&self, _issuer: &str) -> Option<serde_json::Value> {
            self.doc.clone()
        }
        async fn status_list(&self, _c: &DppAccessCredential) -> Option<StatusList> {
            self.status.clone()
        }
    }

    fn headers_with(header: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = header {
            h.insert(CREDENTIAL_HEADER, v.parse().expect("header value"));
        }
        h
    }

    fn trusting() -> StaticTrustedIssuers {
        StaticTrustedIssuers::single(ISSUER)
    }

    fn key_and_kid() -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        (key, "test-kid".to_owned())
    }

    #[tokio::test]
    async fn absent_header_is_the_public_path_not_an_error() {
        // Public access must not require registration (toy and detergent
        // regulations state this outright), so "no credential" is the norm.
        let out = read_and_verify(&headers_with(None), &Directory::with(None), &trusting()).await;
        assert!(matches!(out, CredentialOutcome::Absent));
    }

    #[tokio::test]
    async fn a_signed_credential_from_a_trusted_issuer_verifies() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(
            &key,
            &kid,
            &credential(CredentialRole::AuthorisedRepairer, 30),
        );
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trusting(),
        )
        .await;
        match out {
            CredentialOutcome::Verified(c) => {
                assert_eq!(c.audience(), Audience::LegitimateInterest);
            }
            _ => panic!("a correctly signed, trusted credential must verify"),
        }
    }

    #[tokio::test]
    async fn a_tampered_subject_fails_the_signature() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, &credential(CredentialRole::Recycler, 30));

        // Swap the payload for one claiming an authority role, keeping the
        // original signature — the escalation this check exists to stop.
        let forged = credential(CredentialRole::MarketSurveillanceAuthority, 30);
        let value = serde_json::to_value(&forged).expect("to value");
        let canonical = dpp_crypto::jws::canonicalize(&value).expect("canonicalize");
        let parts: Vec<&str> = jws.split('.').collect();
        let tampered = format!("{}.{}.{}", parts[0], B64.encode(&canonical), parts[2]);

        let out = read_and_verify(
            &headers_with(Some(&tampered)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trusting(),
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn an_unresolvable_issuer_fails_closed() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, &credential(CredentialRole::Recycler, 30));
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(None), // DID unreachable
            &trusting(),
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn a_signature_from_the_wrong_key_is_rejected() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, &credential(CredentialRole::Recycler, 30));
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&other, &kid))), // issuer publishes a different key
            &trusting(),
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn an_expired_credential_is_rejected_even_when_correctly_signed() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, &credential(CredentialRole::Recycler, -1));
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trusting(),
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    /// A valid signature from an issuer nobody trusts grants nothing. This is
    /// the authorisation half: authentication says *who signed*, trust says
    /// *whether that issuer may vouch for this audience*.
    #[tokio::test]
    async fn an_untrusted_issuer_is_rejected_despite_a_valid_signature() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, &credential(CredentialRole::Recycler, 30));
        let nobody = StaticTrustedIssuers::new(Vec::<String>::new(), Vec::<String>::new());
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &nobody,
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    /// An issuer trusted only for legitimate interest cannot mint an authority
    /// credential — the escalation the hierarchy must not permit.
    #[tokio::test]
    async fn a_lower_trusted_issuer_cannot_attest_authority() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(
            &key,
            &kid,
            &credential(CredentialRole::MarketSurveillanceAuthority, 30),
        );
        let li_only = StaticTrustedIssuers::new(vec![ISSUER], Vec::<String>::new());
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &li_only,
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    /// A key the issuer publishes but does not authorise for assertions cannot
    /// sign a credential — the `assertionMethod` reference is load-bearing.
    #[tokio::test]
    async fn a_key_not_authorised_for_assertions_is_rejected() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, &credential(CredentialRole::Recycler, 30));
        let mut doc = did_doc(&key, &kid);
        doc.as_object_mut().expect("obj").remove("assertionMethod");
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(doc)),
            &trusting(),
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    /// A credential declaring a revocation status whose list cannot be fetched
    /// must be denied, not admitted. This is the fail-closed half of revocation:
    /// an attacker who can make the status endpoint unreachable must not thereby
    /// turn a revoked credential into a working one.
    #[tokio::test]
    async fn a_declared_status_that_cannot_be_fetched_denies() {
        let (key, kid) = key_and_kid();
        let mut cred = credential(CredentialRole::Recycler, 30);
        cred.credential_status = Some(dpp_crypto::CredentialStatus {
            id: "https://issuer.example/status#4".to_owned(),
            status_type: "BitstringStatusListEntry".to_owned(),
            status_list_index: Some("4".to_owned()),
            status_list_credential: Some("https://issuer.example/status".to_owned()),
        });
        let jws = sign_credential(&key, &kid, &cred);
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            // signature resolves, but the status list does not
            &Directory {
                doc: Some(did_doc(&key, &kid)),
                status: None,
            },
            &trusting(),
        )
        .await;
        assert!(
            matches!(out, CredentialOutcome::Rejected(_)),
            "an unfetchable status list must deny"
        );
    }

    #[tokio::test]
    async fn a_malformed_envelope_is_rejected() {
        for bad in ["not a jws", "{\"still\":\"json\"}", "a.b"] {
            let out = read_and_verify(
                &headers_with(Some(bad)),
                &Directory::with(None),
                &trusting(),
            )
            .await;
            assert!(
                matches!(out, CredentialOutcome::Rejected(_)),
                "{bad:?} must be rejected"
            );
        }
    }
}
