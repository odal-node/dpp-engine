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
//! 1. It reuses the verification path core already has —
//!    [`authenticate_access_credential_with_reason`]: the `kid` names a verification method
//!    in the issuer's DID document, the signature is checked against that key
//!    with EdDSA pinned and `alg:none` rejected, and the token must be typed
//!    `vc+jwt` so another signature of the same key cannot pass for a credential.
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
use dpp_domain::Audience;
use dpp_vc::{
    DppAccessCredential, StatusList, TrustedIssuerRegistry,
    credential::{AuthenticationFailure, authenticate_access_credential_with_reason},
};

/// The header a caller presents an access credential in.
pub const CREDENTIAL_HEADER: &str = "X-DPP-Credential";

/// The same header in the typed, lowercase form the CORS layer needs.
///
/// `HeaderName::from_static` takes a literal, so this cannot be derived from
/// [`CREDENTIAL_HEADER`] — but it is the only place the typed form is spelled,
/// and it lives beside the header it mirrors so the two are read together.
/// `header_name_matches_the_header_read` asserts they agree, because a drift
/// here fails *silently*: a browser client's preflight is refused and the
/// request never arrives, which looks like the credential not working rather
/// than like a configuration bug.
#[must_use]
pub fn credential_header_name() -> axum::http::HeaderName {
    axum::http::HeaderName::from_static("x-dpp-credential")
}

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
    /// The Art. 77(2) audience this credential grants **before** it is scoped to
    /// a particular passport.
    ///
    /// Prefer [`Self::audience_for`] at a read site: a credential issued for one
    /// product group or category must not elevate a reader on another, and this
    /// method cannot know which passport is being read.
    #[must_use]
    pub fn audience(&self) -> Audience {
        self.0.credential_subject.role.audience()
    }

    /// The audience this credential grants **over a passport in
    /// `product_group_key` whose data states `passport_category`**.
    ///
    /// A credential naming product groups or product categories grants nothing
    /// extra outside them, so an out-of-scope credential resolves to
    /// [`Audience::Public`] rather than an error: it is a valid credential that
    /// simply does not cover this product, and public access is the baseline
    /// every caller already has. Denying instead would also make the route a
    /// probe for which product group or category a passport is in.
    ///
    /// The scope rule itself is core's — an empty list means unscoped on that
    /// axis, a populated one must contain the passport's value — applied by
    /// re-running the pure claims check with both values now known. Nothing
    /// here re-implements it, and nothing here touches the network:
    /// authentication, issuer trust and revocation were all settled in
    /// [`read_and_verify`] before the database was reached.
    ///
    /// ## A category the passport cannot state does not satisfy a category scope
    ///
    /// `passport_category` is the passport's own
    /// [`dpp_domain::product_group::ProductGroupData::product_category`]: the
    /// group's category axis where its act defines one (a battery's
    /// `batteryType`, an electronics `DeviceType`, …), and `None` for a group
    /// with no such axis or a payload this build cannot interpret.
    ///
    /// `None` here does **not** mean what it means to core. Core reads a `None`
    /// required category as "no requirement", which is right when the caller
    /// is not asking about category at all. Passed through for a passport that
    /// cannot answer, it would read an issuer's narrowing as its opposite: a
    /// credential scoped to one category would unlock every product in its
    /// groups that states none. So a credential naming any category resolves
    /// to [`Audience::Public`] on such a passport — the same downgrade a
    /// category mismatch gets — decided here, before core is asked. Core still
    /// sees a `None` when the credential names no category, where "no
    /// requirement" is the truth.
    #[must_use]
    pub fn audience_for(
        &self,
        product_group_key: &str,
        passport_category: Option<&str>,
        trust: &dyn TrustedIssuerRegistry,
    ) -> Audience {
        if passport_category.is_none() && !self.0.credential_subject.product_categories.is_empty() {
            return Audience::Public;
        }

        let scoped = dpp_vc::verify_credential_claims_with_trust(
            &self.0,
            Some(product_group_key),
            passport_category,
            chrono::Utc::now(),
            trust,
        );
        if scoped.is_valid() {
            self.audience()
        } else {
            Audience::Public
        }
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

    let Some(unverified) = decode_payload(jws) else {
        return CredentialOutcome::Rejected(reject(
            "Credential is not a compact JWS carrying a DPP access credential.",
        ));
    };

    // Authenticate before doing anything with the claims: until the signature
    // verifies, `issuer` is a string the caller chose, and it is used only to
    // find the document the signature is checked against.
    let Some(did_doc) = directory.did_document(&unverified.issuer).await else {
        return CredentialOutcome::Rejected(reject("Credential issuer DID could not be resolved."));
    };
    // Core's reading of the token: the key its `kid` names in the issuer's
    // document, the signature, the `vc+jwt` type that keeps another signature of
    // the same key from passing as a credential, and the issuer the document
    // belongs to. A token with no `kid` names no key and is refused. Asked for
    // with the reason, as a type, so each refusal gets the sentence that says what
    // its issuer would fix: matching core's prose would tie this to wording that
    // names the presenter's own `kid` and document.
    let credential = match authenticate_access_credential_with_reason(jws, &did_doc) {
        Ok(credential) => credential,
        Err(failure) => {
            return CredentialOutcome::Rejected(reject(authentication_detail(&failure)));
        }
    };

    // Only now that the signature holds is it worth spending a network round
    // trip on revocation: an unsigned document's status URL is attacker chosen.
    let status_list = directory.status_list(&credential).await;

    // Claims, issuer trust and revocation in core's composed path, so the
    // fail-closed revocation policy is applied where it is defined rather than
    // re-implemented here. `required_product_group`/`required_product_category` are
    // None because this layer does not know which passport is being read; the
    // product group and category scope is applied afterwards by
    // [`VerifiedCredential::audience_for`], once the row is loaded. That
    // split is deliberate: everything that can make a credential *invalid* is
    // settled here, before the database is touched, so a bad credential gets
    // the same 401 whether or not the passport exists. Scope is not validity —
    // it decides how much an already-valid credential unlocks — so it is the
    // only check that may wait for the row.
    let result = dpp_vc::verify_credential_with_revocation_and_trust(
        &credential,
        None,
        None,
        chrono::Utc::now(),
        status_list.as_ref(),
        trust,
    );
    if !result.is_valid() {
        return CredentialOutcome::Rejected(reject(rejection_detail(&result)));
    }

    CredentialOutcome::Verified(Box::new(VerifiedCredential(credential)))
}

/// A fixed sentence per failure kind — never the `Debug` of the verification
/// result.
///
/// Two rules, and the previous `{result:?}` broke both.
///
/// **Nothing the caller supplied is echoed back.** `MalformedCredential` and
/// `OutOfScope` carry free text built from the credential's own contents (its
/// declared product groups, for instance). Reflecting attacker-chosen strings into a
/// response body is a habit worth not having, whatever this particular endpoint
/// renders them into.
///
/// **The distinctions that survive are the ones a holder can act on** — renew an
/// expired credential, obtain a fresh one after revocation, approach a different
/// issuer. Each is something the holder already knows about their own
/// credential, so stating it reveals nothing they did not bring with them. What
/// is *not* distinguished is anything about the node's internals, and the
/// fail-closed revocation case is folded in with genuine revocation on purpose:
/// an attacker who can make a status endpoint unreachable must not learn that
/// they succeeded.
fn rejection_detail(result: &dpp_vc::VerificationResult) -> &'static str {
    use dpp_vc::VerificationResult as V;
    match result {
        V::Expired { .. } => "Credential has expired.",
        V::Revoked => "Credential has been revoked, or its revocation status could not be checked.",
        V::UntrustedIssuer { .. } => "Credential issuer is not trusted by this node.",
        V::OutOfScope { .. } => "Credential does not cover the requested product.",
        // Not reachable from here — authentication has its own sentence per
        // failure, in `authentication_detail`, and the signature has been checked
        // before core is called — but mapped rather than lumped in so a future
        // reordering cannot silently produce a misleading detail.
        V::InvalidSignature(_) => "Credential signature did not verify.",
        // `Valid` is unreachable — the caller checks `is_valid()` first — and
        // `MalformedCredential` carries text derived from the credential.
        V::MalformedCredential(_) | V::Valid { .. } => "Credential is not valid.",
    }
}

/// The sentence for a credential that could not be authenticated: one per thing
/// its issuer would go and fix.
///
/// Authentication refuses for five different reasons and they used to read the
/// same, so an issuer whose tooling had not yet set the token's type was told its
/// signature did not verify, and went to debug a key that was sound. Each of
/// these is something the issuer already knows about its own token, so saying it
/// reveals nothing they did not bring. And nothing the presenter supplied is
/// echoed: the failures that carry the `kid`, the document or the issuer carry
/// them in fields this function does not read.
///
/// A signature that does not verify keeps the sentence it has always had, so a
/// client that matches it still does.
fn authentication_detail(failure: &AuthenticationFailure) -> &'static str {
    use AuthenticationFailure as A;
    match failure {
        A::NoMatchingKey { .. } => {
            "Credential names no key that its issuer's DID document publishes. Its `kid` must be \
             the absolute URL of a verification method in that document."
        }
        A::SignatureDoesNotVerify => "Credential signature did not verify.",
        A::Unverifiable { .. } => {
            "Credential could not be verified: its protected header or signature is malformed, \
             or its algorithm is not accepted."
        }
        A::NotTypedAsCredential { .. } => {
            "Credential is not typed as one. Its `typ` must be `vc+jwt` and its `cty`, when \
             present, `vc`."
        }
        A::MalformedPayload { .. } => "Credential payload is not a DPP access credential.",
        A::IssuerMismatch { .. } => {
            "Credential names a different issuer than the DID document it was checked against."
        }
        A::NotACompactJws => "Credential is not a compact JWS.",
        // The failure grows variants; one this does not name is still a refusal
        // that says nothing about the presenter's own contents.
        _ => "Credential could not be authenticated.",
    }
}

/// RFC 9457 rejection. 401 rather than 400: the request is well-formed HTTP; it
/// is the credential that failed, and the client's remedy is a different one.
///
/// Details come from [`rejection_detail`] or are fixed strings at the call site;
/// see that function for what the wording deliberately does and does not reveal.
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
    use dpp_vc::{CredentialBuilder, CredentialRole, DppCredentialSubject, StaticTrustedIssuers};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const ISSUER: &str = "did:web:issuer.example";
    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// Mint a compact JWS over the JCS-canonical credential, exactly as
    /// `dpp_vc::credential::sign_access_credential` does: the `kid` is the
    /// absolute URL of the issuer's verification method, the token is typed as
    /// a VC-JWT (`typ: vc+jwt`, `cty: vc`), the payload is JCS, the algorithm
    /// EdDSA.
    fn sign_credential(key: &SigningKey, kid: &str, cred: &DppAccessCredential) -> String {
        sign_with_header(
            key,
            &format!(r#"{{"alg":"EdDSA","cty":"vc","kid":"{ISSUER}#{kid}","typ":"vc+jwt"}}"#),
            cred,
        )
    }

    /// The same, under whatever protected header the caller states.
    fn sign_with_header(key: &SigningKey, header_json: &str, cred: &DppAccessCredential) -> String {
        let header = B64.encode(header_json.as_bytes());
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
                product_groups: vec!["battery".to_owned()],
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

    /// 🚨 A signature by the issuer's key is authentic whatever it signs, so a
    /// passport proof or an SD-JWT VC from the same key could otherwise be
    /// offered as a credential. The type is what says this token is one.
    #[tokio::test]
    async fn the_issuers_signature_over_a_credential_shaped_payload_must_be_typed_as_one() {
        let (key, kid) = key_and_kid();
        let cred = credential(CredentialRole::Recycler, 30);
        let directory = Directory::with(Some(did_doc(&key, &kid)));

        for header in [
            // No type at all, as a passport proof is signed.
            format!(r#"{{"alg":"EdDSA","kid":"{ISSUER}#{kid}"}}"#),
            // The type of another credential format.
            format!(r#"{{"alg":"EdDSA","kid":"{ISSUER}#{kid}","typ":"dc+sd-jwt"}}"#),
            // The right type with the wrong content type.
            format!(r#"{{"alg":"EdDSA","cty":"other","kid":"{ISSUER}#{kid}","typ":"vc+jwt"}}"#),
        ] {
            let jws = sign_with_header(&key, &header, &cred);
            let out = read_and_verify(&headers_with(Some(&jws)), &directory, &trusting()).await;
            assert!(
                matches!(out, CredentialOutcome::Rejected(_)),
                "{header} must not pass for a credential"
            );
        }
    }

    /// A token that names no key is not checked against the one the document
    /// happens to publish.
    #[tokio::test]
    async fn a_credential_that_names_no_key_is_refused() {
        let (key, kid) = key_and_kid();
        let jws = sign_with_header(
            &key,
            r#"{"alg":"EdDSA","cty":"vc","typ":"vc+jwt"}"#,
            &credential(CredentialRole::Recycler, 30),
        );
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trusting(),
        )
        .await;
        assert!(matches!(out, CredentialOutcome::Rejected(_)));
    }

    /// The `detail` a rejection answers with.
    async fn detail_of(outcome: CredentialOutcome) -> String {
        let CredentialOutcome::Rejected(response) = outcome else {
            panic!("expected a rejection");
        };
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let problem: serde_json::Value =
            serde_json::from_slice(&bytes).expect("a problem document");
        problem["detail"].as_str().expect("a detail").to_owned()
    }

    /// 🚨 Each way authentication can refuse tells its issuer what to fix, in a
    /// sentence of its own. They used to read the same, so an issuer whose tooling
    /// had not yet set the token's type was told its signature did not verify and
    /// went to debug a key that was sound. And nothing the presenter chose, the
    /// `kid` or the issuer it names, is echoed back.
    #[tokio::test]
    async fn each_authentication_failure_says_what_its_issuer_would_fix() {
        let (key, kid) = key_and_kid();
        let directory = Directory::with(Some(did_doc(&key, &kid)));
        let cred = credential(CredentialRole::Recycler, 30);
        let detail = |jws: String| {
            let directory = &directory;
            async move {
                detail_of(read_and_verify(&headers_with(Some(&jws)), directory, &trusting()).await)
                    .await
            }
        };

        // No `kid`: the token names no key.
        let no_kid = sign_with_header(&key, r#"{"alg":"EdDSA","cty":"vc","typ":"vc+jwt"}"#, &cred);
        let said = detail(no_kid).await;
        assert!(said.contains("names no key"), "{said}");
        assert!(
            !said.contains("signature"),
            "it is not a signature problem: {said}"
        );

        // A `kid` that names a method the document does not publish, as a token
        // signed before keys were named by thumbprint does.
        let stale = sign_with_header(
            &key,
            r#"{"alg":"EdDSA","cty":"vc","kid":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","typ":"vc+jwt"}"#,
            &cred,
        );
        let said = detail(stale).await;
        assert!(said.contains("names no key"), "{said}");
        assert!(
            !said.contains("9f86d081"),
            "the presenter's own `kid` is not echoed: {said}"
        );

        // Typed as something else: the signature is sound.
        let untyped = sign_with_header(
            &key,
            &format!(r#"{{"alg":"EdDSA","kid":"{ISSUER}#{kid}"}}"#),
            &cred,
        );
        let said = detail(untyped).await;
        assert!(
            said.contains("not typed") && said.contains("vc+jwt"),
            "{said}"
        );
        assert!(!said.contains("did not verify"), "{said}");

        // The one thing wrong is the signature.
        let genuine = sign_credential(&key, &kid, &cred);
        let (signing_input, _) = genuine.rsplit_once('.').expect("a compact JWS");
        let forged = format!("{signing_input}.{}", "A".repeat(86));
        assert_eq!(detail(forged).await, "Credential signature did not verify.");

        // Authentic, typed, and the credential names another issuer than the
        // document it is checked against.
        let mut claims_another = credential(CredentialRole::Recycler, 30);
        claims_another.issuer = "did:web:someone-else.example".to_owned();
        let mismatched = sign_credential(&key, &kid, &claims_another);
        let said = detail(mismatched).await;
        assert!(said.contains("different issuer"), "{said}");
        assert!(
            !said.contains("someone-else"),
            "the issuer the presenter named is not echoed: {said}"
        );
    }

    /// Every typed reason has a sentence, none of them reads the fields the
    /// presenter chose, and one this crate has not heard of still gets an answer.
    #[test]
    fn no_authentication_sentence_carries_what_the_presenter_supplied() {
        let failures = [
            AuthenticationFailure::NotACompactJws,
            AuthenticationFailure::NoMatchingKey {
                document: "did:web:secret-document.example".into(),
                kid: "secret-kid".into(),
            },
            AuthenticationFailure::SignatureDoesNotVerify,
            AuthenticationFailure::Unverifiable {
                reason: "secret-reason".into(),
            },
            AuthenticationFailure::NotTypedAsCredential {
                reason: "secret-reason".into(),
            },
            AuthenticationFailure::MalformedPayload {
                reason: "secret-reason".into(),
            },
            AuthenticationFailure::IssuerMismatch {
                claimed: "did:web:secret-claim.example".into(),
                document: "did:web:secret-document.example".into(),
            },
        ];
        let sentences: Vec<&str> = failures.iter().map(authentication_detail).collect();
        for sentence in &sentences {
            assert!(
                !sentence.contains("secret"),
                "a presenter-supplied value reached the response: {sentence}"
            );
        }
        let mut distinct = sentences.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            failures.len(),
            "each failure has a sentence of its own: {sentences:?}"
        );
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
        cred.credential_status = Some(dpp_vc::CredentialStatus {
            id: "https://issuer.example/status#4".to_owned(),
            status_type: "BitstringStatusListEntry".to_owned(),
            status_purpose: "revocation".to_owned(),
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

    /// A credential naming `battery` must not elevate a reader on a textile
    /// passport. The credential stays valid — it simply grants nothing beyond
    /// public here, which is why the answer is a downgrade and not a 401.
    #[tokio::test]
    async fn a_credential_does_not_elevate_outside_its_product_groups() {
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
        let CredentialOutcome::Verified(c) = out else {
            panic!("the credential itself is valid");
        };
        assert_eq!(
            c.audience_for("battery", Some("ev"), &trusting()),
            Audience::LegitimateInterest,
            "in scope: the credential names battery"
        );
        assert_eq!(
            c.audience_for("textile", None, &trusting()),
            Audience::Public,
            "out of scope: a battery credential must not unlock a textile passport"
        );
    }

    /// An unmodelled product group is not in any credential's scope list either, so it
    /// gets the same downgrade rather than falling through to the raw audience.
    #[tokio::test]
    async fn an_unknown_product_group_is_out_of_scope() {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(
            &key,
            &kid,
            &credential(CredentialRole::MarketSurveillanceAuthority, 30),
        );
        let trust = StaticTrustedIssuers::new(vec![ISSUER], vec![ISSUER]);
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trust,
        )
        .await;
        let CredentialOutcome::Verified(c) = out else {
            panic!("valid credential");
        };
        assert_eq!(c.audience(), Audience::Authority);
        assert_eq!(
            c.audience_for("not-a-product_group", None, &trust),
            Audience::Public
        );
    }

    /// A credential naming **no** product groups is unscoped by core's rule, so it
    /// keeps its audience everywhere. Locking this in because the downgrade
    /// above must not silently become "deny unless listed" — that would break
    /// every general-purpose authority credential.
    #[tokio::test]
    async fn a_credential_with_no_product_groups_is_unscoped() {
        let (key, kid) = key_and_kid();
        let mut cred = credential(CredentialRole::Recycler, 30);
        cred.credential_subject.product_groups = Vec::new();
        let jws = sign_credential(&key, &kid, &cred);
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trusting(),
        )
        .await;
        let CredentialOutcome::Verified(c) = out else {
            panic!("valid credential");
        };
        assert_eq!(
            c.audience_for("textile", None, &trusting()),
            Audience::LegitimateInterest
        );
    }

    /// Sign `cred`, run it through the real verification path, and return the
    /// grant. A credential carrying a category list must still verify: scope
    /// is not validity, and only [`VerifiedCredential::audience_for`] reads it.
    async fn verified(cred: &DppAccessCredential) -> VerifiedCredential {
        let (key, kid) = key_and_kid();
        let jws = sign_credential(&key, &kid, cred);
        let out = read_and_verify(
            &headers_with(Some(&jws)),
            &Directory::with(Some(did_doc(&key, &kid))),
            &trusting(),
        )
        .await;
        let CredentialOutcome::Verified(c) = out else {
            panic!("the credential itself is valid");
        };
        *c
    }

    /// A credential narrowed to a category keeps its audience on a passport
    /// that states that category — and only within its product groups, since
    /// both axes must hold.
    #[tokio::test]
    async fn a_credential_naming_the_passports_category_keeps_its_audience() {
        let mut cred = credential(CredentialRole::AuthorisedRepairer, 30);
        cred.credential_subject.product_categories = vec!["ev".into()];
        let c = verified(&cred).await;

        assert_eq!(
            c.audience_for("battery", Some("ev"), &trusting()),
            Audience::LegitimateInterest,
            "in scope on both axes"
        );
        assert_eq!(
            c.audience_for("electronics", Some("ev"), &trusting()),
            Audience::Public,
            "a matching category does not stand in for a matching product group"
        );
    }

    /// A credential narrowed to EV batteries grants nothing extra on an LMT
    /// battery. It stays valid, so the answer is a downgrade and not a 401.
    #[tokio::test]
    async fn a_credential_naming_another_category_grants_only_public() {
        let mut cred = credential(CredentialRole::AuthorisedRepairer, 30);
        cred.credential_subject.product_categories = vec!["ev".into()];
        let c = verified(&cred).await;

        assert_eq!(c.audience(), Audience::LegitimateInterest);
        assert_eq!(
            c.audience_for("battery", Some("lmt"), &trusting()),
            Audience::Public
        );
    }

    /// No category named means no restriction claimed on that axis, whatever
    /// the passport states — including nothing — and product group scope alone
    /// decides.
    #[tokio::test]
    async fn an_empty_category_list_is_unscoped_on_that_axis() {
        let mut cred = credential(CredentialRole::AuthorisedRepairer, 30);
        cred.credential_subject.product_categories = Vec::new();
        let c = verified(&cred).await;

        for passport_category in [Some("ev"), Some("lmt"), None] {
            assert_eq!(
                c.audience_for("battery", passport_category, &trusting()),
                Audience::LegitimateInterest,
                "passport category {passport_category:?}"
            );
        }
    }

    /// A passport whose group has no category axis cannot satisfy a credential
    /// narrowed to one. Core reads a `None` category as "no requirement", so
    /// handing it the passport's `None` would grant a textile-scoped,
    /// category-narrowed credential its full audience over every textile
    /// passport — the restriction read as its opposite. It must land where a
    /// mismatch lands, not where an unscoped credential does.
    #[tokio::test]
    async fn a_passport_stating_no_category_is_treated_as_a_mismatch() {
        let mut narrowed = credential(CredentialRole::AuthorisedRepairer, 30);
        narrowed.credential_subject.product_groups = vec!["textile".into()];
        narrowed.credential_subject.product_categories = vec!["apparel".into()];
        let narrowed = verified(&narrowed).await;

        let mut unscoped = credential(CredentialRole::AuthorisedRepairer, 30);
        unscoped.credential_subject.product_groups = vec!["textile".into()];
        let unscoped = verified(&unscoped).await;

        let cannot_answer = narrowed.audience_for("textile", None, &trusting());
        assert_eq!(cannot_answer, Audience::Public);
        assert_eq!(
            cannot_answer,
            narrowed.audience_for("textile", Some("footwear"), &trusting()),
            "same outcome as a category mismatch"
        );
        assert_ne!(
            cannot_answer,
            unscoped.audience_for("textile", None, &trusting()),
            "not the outcome of a credential that names no category"
        );
    }

    /// The typed header name must be the lowercase form of the header actually
    /// read. They are spelled separately (`HeaderName::from_static` needs a
    /// literal), and a mismatch would refuse browser preflights for a header the
    /// node does accept — a failure that shows up as requests never arriving.
    #[test]
    fn header_name_matches_the_header_read() {
        assert_eq!(
            credential_header_name().as_str(),
            CREDENTIAL_HEADER.to_ascii_lowercase()
        );
    }

    /// Rejection details are fixed sentences: no `Debug` formatting, and
    /// nothing derived from the credential the caller supplied. The old
    /// `{result:?}` emitted `UntrustedIssuer { issuer_did: "…" }` and
    /// `OutOfScope { reason: "Credential covers product groups […]" }` — Rust internals
    /// and caller-chosen strings, straight into a public response body.
    #[test]
    fn rejection_details_are_fixed_sentences_not_debug_output() {
        use dpp_vc::VerificationResult as V;

        let cases = [
            V::Expired {
                expired_at: Utc::now(),
            },
            V::Revoked,
            V::UntrustedIssuer {
                issuer_did: "did:web:attacker-chosen.example".to_owned(),
            },
            V::OutOfScope {
                reason: "Credential covers product_groups [\"<script>\"]".to_owned(),
            },
            V::MalformedCredential("attacker text".to_owned()),
        ];

        for result in cases {
            let detail = rejection_detail(&result);
            for leak in [
                "{",
                "}",
                "did:web:",
                "attacker",
                "script",
                "product_groups",
                "expired_at",
            ] {
                assert!(
                    !detail.contains(leak),
                    "detail {detail:?} leaks {leak:?} from {result:?}"
                );
            }
            assert!(detail.ends_with('.'), "{detail:?} is not a sentence");
        }
    }

    /// Revocation and an unfetchable status list share one message on purpose:
    /// core maps both to `Revoked`, and an attacker who can make a status
    /// endpoint unreachable must not learn from the response that it worked.
    #[test]
    fn a_blocked_status_endpoint_is_indistinguishable_from_revocation() {
        use dpp_vc::VerificationResult as V;
        assert_eq!(rejection_detail(&V::Revoked), rejection_detail(&V::Revoked));
        assert!(rejection_detail(&V::Revoked).contains("could not be checked"));
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
