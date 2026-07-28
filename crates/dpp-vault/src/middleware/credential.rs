//! `X-DPP-Credential` transport — parsing and claims-checking an access credential.
//!
//! # Why a dedicated header
//!
//! `Authorization` already routes by scheme in [`super::auth`]: `Bearer` reaches
//! the API-key providers, `Basic` the local-admin provider. An access credential
//! is a *different axis* — it says who the reader is, not whether the caller may
//! write. A machine integration can legitimately hold both an API key and a
//! credential, so they must not compete for one header slot.
//!
//! # What this layer does, and deliberately does not
//!
//! It parses the credential and checks the claims core can check without a
//! network: structure, and the `validFrom` / `validUntil` window.
//!
//! It does **not** establish that the credential can be trusted, and it does not
//! resolve an [`Audience`] into request extensions. Three checks are still
//! missing, and each is its own change:
//!
//! 1. **Signature.** `dpp_crypto::verify_credential_claims` documents itself as
//!    "no signature check — that is the JWS verifier's responsibility". The
//!    primitive exists (`dpp_crypto::jws::verify_jws`) but needs the issuer's
//!    public key, which means resolving the issuer `did:web`.
//! 2. **Issuer trust** — whether this issuer may attest this audience at all.
//! 3. **Revocation** — `crate::infra::status_list::fetch_status_list_for` is
//!    implemented and fail-closed, and is not yet wired to anything.
//!
//! So this module injects [`PresentedCredential`] — the credential as presented,
//! with its claims window checked — and **not** an `Audience`. That is the whole
//! point of the type: a bare `Audience` in extensions would look authoritative
//! and be trivially forgeable, since anyone can mint this JSON. Nothing may gate
//! disclosure on it until the three checks above land.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use dpp_common::http_problem;
use dpp_crypto::{DppAccessCredential, verify_credential_claims};
use dpp_domain::Audience;

/// The header a caller presents an access credential in.
pub const CREDENTIAL_HEADER: &str = "X-DPP-Credential";

/// A credential that was presented and whose claims window is valid.
///
/// **Not a grant.** Signature, issuer trust and revocation are unchecked — see
/// the module docs. Held as a distinct type so that a handler cannot mistake it
/// for an authorisation decision, and so the compiler flags every place that
/// will need revisiting once verification lands.
#[derive(Debug, Clone)]
pub struct PresentedCredential(pub DppAccessCredential);

impl PresentedCredential {
    /// The audience this credential *claims*, per the Art. 77(2) role mapping.
    ///
    /// Deliberately a method rather than something injected into extensions:
    /// reading it is an explicit act at the call site, which keeps the unverified
    /// state visible instead of letting an `Audience` circulate as if it were a
    /// decision.
    #[must_use]
    pub fn claimed_audience(&self) -> Audience {
        self.0.credential_subject.role.audience()
    }
}

/// Outcome of looking for a credential on a request.
pub enum CredentialOutcome {
    /// No `X-DPP-Credential` header. The caller is the general public.
    Absent,
    /// A credential was presented and its claims window is valid.
    Presented(Box<PresentedCredential>),
    /// A credential was presented and is unusable.
    Rejected(Response),
}

/// Read and claims-check the credential on `request`.
///
/// Returns [`CredentialOutcome::Absent`] when the header is missing — that is
/// the ordinary public path and must never be an error. ESPR Art. 11(b) and the
/// toy and detergent regulations require public access to be free of charge and
/// available without registration, so an unauthenticated read is the norm rather
/// than a degraded case.
pub fn read_credential(request: &Request) -> CredentialOutcome {
    let Some(raw) = request.headers().get(CREDENTIAL_HEADER) else {
        return CredentialOutcome::Absent;
    };
    let Ok(raw) = raw.to_str() else {
        return CredentialOutcome::Rejected(reject("Credential header is not valid UTF-8."));
    };

    let credential: DppAccessCredential = match serde_json::from_str(raw) {
        Ok(c) => c,
        Err(e) => {
            return CredentialOutcome::Rejected(reject(&format!(
                "Credential is not a valid DPP access credential: {e}"
            )));
        }
    };

    // `required_sector` is None here: this layer does not know which passport is
    // being read. Sector scoping belongs to the read handler, which does.
    let result = verify_credential_claims(&credential, None, chrono::Utc::now());
    if !result.is_valid() {
        return CredentialOutcome::Rejected(reject(&format!(
            "Credential claims are not valid: {result:?}"
        )));
    }

    CredentialOutcome::Presented(Box::new(PresentedCredential(credential)))
}

/// RFC 7807 rejection. 401 rather than 400: the request is well-formed HTTP, it
/// is the *credential* that failed, and a client's remedy is to present a
/// different one.
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
    use dpp_crypto::{CredentialBuilder, CredentialRole, DppCredentialSubject};

    fn subject(role: CredentialRole) -> DppCredentialSubject {
        DppCredentialSubject {
            id: "did:web:repairer.example".to_owned(),
            name: "Example Repair Co".to_owned(),
            role,
            country: "DE".to_owned(),
            sectors: vec!["battery".to_owned()],
            product_categories: Vec::new(),
        }
    }

    fn request_with(header: Option<&str>) -> Request {
        let mut b = Request::builder();
        if let Some(v) = header {
            b = b.header(CREDENTIAL_HEADER, v);
        }
        b.body(axum::body::Body::empty()).expect("request")
    }

    fn json_for(role: CredentialRole, days: i64) -> String {
        let cred = CredentialBuilder::new("did:web:issuer.example".to_owned(), subject(role))
            .expires_at(Utc::now() + Duration::days(days))
            .build();
        serde_json::to_string(&cred).expect("serialize")
    }

    #[test]
    fn absent_header_is_the_public_path_not_an_error() {
        // Public access must not require registration (toy and detergent
        // regulations state this outright), so "no credential" is the norm.
        assert!(matches!(
            read_credential(&request_with(None)),
            CredentialOutcome::Absent
        ));
    }

    #[test]
    fn a_valid_credential_is_presented_and_claims_its_audience() {
        let json = json_for(CredentialRole::AuthorisedRepairer, 30);
        match read_credential(&request_with(Some(&json))) {
            CredentialOutcome::Presented(c) => {
                assert_eq!(c.claimed_audience(), Audience::LegitimateInterest);
            }
            _ => panic!("a well-formed, unexpired credential must be presented"),
        }
    }

    #[test]
    fn an_authority_role_claims_the_authority_audience() {
        let json = json_for(CredentialRole::MarketSurveillanceAuthority, 30);
        match read_credential(&request_with(Some(&json))) {
            CredentialOutcome::Presented(c) => {
                assert_eq!(c.claimed_audience(), Audience::Authority);
            }
            _ => panic!("authority credential must be presented"),
        }
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let json = json_for(CredentialRole::Recycler, -1);
        assert!(matches!(
            read_credential(&request_with(Some(&json))),
            CredentialOutcome::Rejected(_)
        ));
    }

    #[test]
    fn a_malformed_credential_is_rejected() {
        assert!(matches!(
            read_credential(&request_with(Some("{\"not\":\"a credential\"}"))),
            CredentialOutcome::Rejected(_)
        ));
        assert!(matches!(
            read_credential(&request_with(Some("plainly not json"))),
            CredentialOutcome::Rejected(_)
        ));
    }

    /// The lattice property, asserted here because this is where roles first
    /// become audiences in the engine: an authority does not thereby gain
    /// Annex XIII point 4 individual-item data, and a recycler does not gain
    /// point 3 conformity evidence.
    #[test]
    fn neither_non_public_audience_contains_the_other() {
        use dpp_domain::Disclosure;
        let authority = CredentialRole::NotifiedBody.audience();
        let interest = CredentialRole::Recycler.audience();
        assert!(!authority.may_see(Disclosure::Individual));
        assert!(interest.may_see(Disclosure::Individual));
        assert!(authority.may_see(Disclosure::Conformity));
        assert!(!interest.may_see(Disclosure::Conformity));
    }
}
