//! `GET /api/v1/dpp/{dppId}/seal` — the passport's eIDAS qualified seal.
//!
//! The seal needs its own route because it is stripped from every audience view:
//! it covers the *full*-payload `jwsSignature`, so attaching it to a redacted
//! body would hand the reader a proof that verifies against nothing they were
//! given (see `crate::public_view::audience_view`). Here it travels with the
//! signature it actually attests to, and with the digest a verifier needs to
//! check it against.
//!
//! What this route does **not** do is validate the CAdES. A seal is worth
//! exactly as much as the independence of whoever checked it, so a verdict from
//! the node that bought the seal would attest nothing — the response instead
//! carries everything an external validator needs and states plainly what has
//! and has not been verified.
//!
//! It also names **who declared the content**, which is a different party from
//! whoever sealed it. A seal says a document came from the certificate holder
//! and nothing about scope, so serving one with no declarer beside it invites
//! the reader to conclude the sealer authored what it covers. Since every
//! audience view strips the seal, this is the only surface where that
//! conclusion is reachable — see [`SealDeclarer`].
//!
//! It does answer one narrower question, because it can: **is this seal stale?**
//! The envelope carries no preimage, but the outbox row that bought it does, and
//! those rows are never deleted — so a passport re-published after sealing is
//! detectable here with a lookup and a string comparison, no AdES tooling
//! involved. That is a record of what was *requested*, not proof of what the
//! CAdES covers; the validator's extracted digest is the cross-check, and
//! `coverage` never pretends to be the verdict.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use crate::domain::service::seal::seal_digest;
use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id};

/// Who declared the content a seal covers, which is not who sealed it.
///
/// A seal proves a document came from whoever holds the certificate. It carries
/// no statement about *scope*: "we vouch for this content" and "we transmitted
/// this intact" look identical. A response that serves a seal and names no
/// declaring party invites the reader to collapse the two, whatever anyone
/// intended.
///
/// Every audience view strips the seal, so this is the only surface where that
/// collapse is reachable — and its readers being authenticated and technical
/// makes them more likely to build on the assumption, not less.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealDeclarer {
    /// The manufacturer named in the sealed passport, frozen at publish.
    pub manufacturer: String,
    /// The Annex III(k) unique operator identifier recorded at publish, if one
    /// was. `null` means none was recorded — never that none applies.
    pub operator_identifier: Option<String>,
    /// True when this passport's transfer chain records a completed handover, so
    /// the party responsible **now** is not the one named above.
    ///
    /// The names above are frozen into the sealed bytes and cannot be rewritten:
    /// a published passport's content is immutable, and the seal covers it. So
    /// this flag is the only honest way to say that the answer above is a
    /// historical fact rather than a current one.
    pub responsibility_may_have_transferred: bool,
    /// Stated rather than left to inference, in the same spirit as
    /// [`SealResponse::verification`].
    pub note: &'static str,
}

const DECLARER_NOTE: &str = "the seal attests that this document came from the holder of the sealing certificate; it makes \
     no statement about who authored the content. `manufacturer` is the party that declared it, \
     frozen at publish. Where `responsibilityMayHaveTransferred` is true, the operator responsible \
     today is a different question — this node's transfer chain records what it was told, and the \
     EU registry holds the authoritative record between verified actors.";

/// The seal, plus what is needed to check it and what we did not check.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealResponse {
    /// Who declared the content, as distinct from who sealed it.
    pub declared_by: SealDeclarer,
    /// AdES format of `sealValue` — `CADES` for the eID Easy backend.
    pub format: String,
    /// Base64 detached CAdES (`.p7s`) as returned by the QTSP.
    pub seal_value: String,
    /// When the QTSP produced it.
    pub sealed_at: chrono::DateTime<chrono::Utc>,

    /// Hex SHA-256 of the certificate the seal names as its signer, **as
    /// reported by the seal** — read out of the CAdES, never verified.
    ///
    /// It answers *which* certificate to ask about, not whether that certificate
    /// was qualified or on the EU Trusted List when the seal was made. Both of
    /// those are the independent validator's question. Without this an auditor
    /// has to be handed the `.p7s` and parse it by hand to learn even the first.
    ///
    /// `null` when the seal predates extraction or could not be parsed.
    pub signing_cert_ref: Option<String>,
    /// True when this is a `GhostSeal` placeholder with no legal validity.
    pub placeholder: bool,
    /// The passport's **current** compact JWS.
    pub current_jws: String,
    /// Hex SHA-256 of `currentJws` — the digest a seal over this passport's
    /// present signature would be taken over.
    pub current_payload_hash: String,

    /// Hex SHA-256 this node **asked** the backend to seal, from the outbox row
    /// that bought `sealValue`.
    ///
    /// `null` when this node holds no such row — a seal restored from a backup
    /// or produced elsewhere. This is a record, not proof: it says what was
    /// requested, and the validator's extracted message digest is what says what
    /// the CAdES actually covers. The two agreeing is the cross-check.
    pub sealed_payload_hash: Option<String>,

    /// Whether the stored seal covers the passport's current signature.
    pub coverage: SealCoverage,
    /// Stated, not implied: this node did not cryptographically validate the
    /// CAdES, and says so rather than letting the response read as a verdict.
    pub verification: &'static str,
}

const NOT_VALIDATED: &str = "not validated by this node — a detached CAdES must be checked by an independent AdES \
     validator against the EU Trusted List. `coverage` answers a narrower question from this \
     node's own records and is not a substitute: it reports which digest was requested, while \
     only the validator establishes which digest the CAdES actually covers. Compare the two.";

/// Whether the stored seal covers the passport's current signature.
///
/// Answered from `sealedPayloadHash`, which is this node's record of what it
/// asked for. That is weaker than a validator's verdict and stronger than
/// nothing: it cannot confirm the CAdES, but a passport re-published after
/// sealing is knowable here without any AdES tooling at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SealCoverage {
    /// The requested digest is the passport's current one.
    Current,
    /// The passport was re-published after this seal was bought. The seal stays
    /// valid for the signature it does cover; a seal over the new signature has
    /// not landed yet.
    Superseded,
    /// No record of what was sealed — restored from a backup, produced by
    /// another node, or sealed before this node kept the row. Only the external
    /// validator can answer.
    Unknown,
}

/// The coverage rule, as a pure function over the two digests.
///
/// Split out from the handler so it is testable without a database: the whole
/// rule is which of three answers a pair of digests warrants, and that should not
/// need Postgres and an `AppState` to exercise.
fn coverage_of(sealed: Option<&str>, current: &str) -> SealCoverage {
    match sealed {
        Some(sealed) if sealed == current => SealCoverage::Current,
        Some(_) => SealCoverage::Superseded,
        None => SealCoverage::Unknown,
    }
}

/// `GET /api/v1/dpp/{dppId}/seal` — return the qualified seal and its preimage.
///
/// `404` when the passport does not exist, and `404` when it exists but carries
/// no seal — an unsealed passport has no seal resource, and inventing an empty
/// one would blur "not sealed yet" into "sealed with nothing".
pub async fn seal_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let passport = match state.service.find_by_id(passport_id).await {
        Ok(p) => p,
        Err(dpp_domain::DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    };

    let Some(seal) = passport.seal.as_ref() else {
        return not_found_error(
            "This passport carries no qualified seal. It may not be published, or its seal may \
             still be queued.",
        );
    };
    // A seal cannot exist without the signature it was taken over, so a passport
    // holding one and no JWS is a corrupt row rather than an empty response.
    let Some(jws) = passport.jws_signature.clone() else {
        return internal_error(dpp_domain::DppError::Internal(
            "passport carries a seal but no jwsSignature".into(),
        ));
    };
    let payload_hash = seal_digest(&passport).unwrap_or_default();

    // A node with no outbox wired (no seal provider selected) can still be
    // serving seals it bought earlier, so an absent outbox is `Unknown` rather
    // than an error — the same answer as a row this node never had.
    let sealed_payload_hash = match &state.service.seal_outbox {
        Some(outbox) => match outbox.sealed_digest(passport_id).await {
            Ok(h) => h,
            Err(e) => return internal_error(e),
        },
        None => None,
    };
    let coverage = coverage_of(sealed_payload_hash.as_deref(), &payload_hash);

    // Has responsibility moved since this passport was sealed? Only a *completed*
    // handover counts: an initiated one that nobody accepted has moved nothing,
    // and reporting it would claim a transfer that may still be rejected. A node
    // with no transfer store configured records no handovers, so the honest
    // answer there is `false` rather than an error.
    //
    // A store that *errors*, though, fails the whole read. `false` is not a safe
    // default here — it is a positive claim that responsibility has not moved,
    // and serving it beside a seal on the strength of a failed query is the one
    // outcome worse than serving nothing. So the seal becomes unreadable while
    // the transfer store is down, deliberately.
    let responsibility_may_have_transferred = match state.service.transfer_store.as_ref() {
        Some(store) => match store.get_chain(passport_id).await {
            Ok(Some(chain)) => chain.transfer_count() > 0,
            Ok(None) => false,
            Err(e) => return internal_error(e),
        },
        None => false,
    };

    (
        StatusCode::OK,
        Json(SealResponse {
            declared_by: SealDeclarer {
                manufacturer: passport.manufacturer.name.clone(),
                operator_identifier: passport.operator_identifier.clone(),
                responsibility_may_have_transferred,
                note: DECLARER_NOTE,
            },
            format: serde_json::to_value(&seal.format)
                .ok()
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
                .unwrap_or_default(),
            seal_value: seal.seal_value.clone(),
            sealed_at: seal.sealed_at,
            signing_cert_ref: seal.signing_cert_ref.clone(),
            placeholder: seal.placeholder,
            current_jws: jws,
            current_payload_hash: payload_hash,
            sealed_payload_hash,
            coverage,
            verification: NOT_VALIDATED,
        }),
    )
        .into_response()
}

/// Operator-wide sealing state.
///
/// `unsealedPublished` is the headline and the other three are context, not the
/// other way round. The counts describe outbox *rows*; the obligation is about
/// *passports*, and the two come apart exactly where it matters most — a crash
/// between commit and enqueue publishes a passport that no row will ever cover,
/// so `pending: 0, exhausted: 0` is consistent with any number of unsealed
/// passports.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealSummaryResponse {
    /// Published passports carrying no seal at all. `0` is the healthy state.
    pub unsealed_published: i64,
    /// Rows awaiting a sealing attempt.
    pub pending: i64,
    /// Rows whose seal is on the passport.
    pub sealed: i64,
    /// Rows that gave up after exhausting their retries.
    pub exhausted: i64,
    /// False when no seal provider is configured, in which case every number
    /// above is `0` because this node has no outbox — not because it has
    /// nothing outstanding. Stated so a reader cannot mistake "not sealing" for
    /// "all sealed".
    pub sealing_configured: bool,
}

/// `GET /api/v1/seal` — operator-wide sealing state.
///
/// Exists because the per-passport route cannot answer "is anything unsealed"
/// without the caller already knowing which passport to ask about, and the
/// gauges that do answer it are only reachable through Prometheus.
pub async fn seal_summary_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let Some(outbox) = state.service.seal_outbox.as_ref() else {
        return (
            StatusCode::OK,
            Json(SealSummaryResponse {
                unsealed_published: 0,
                pending: 0,
                sealed: 0,
                exhausted: 0,
                sealing_configured: false,
            }),
        )
            .into_response();
    };

    let counts = match outbox.status_counts().await {
        Ok(c) => c,
        Err(e) => return internal_error(e),
    };
    let unsealed_published = match outbox.unsealed_published_count().await {
        Ok(n) => n,
        Err(e) => return internal_error(e),
    };

    (
        StatusCode::OK,
        Json(SealSummaryResponse {
            unsealed_published,
            pending: counts.pending,
            sealed: counts.sealed,
            exhausted: counts.exhausted,
            sealing_configured: true,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aa";
    const B: &str = "bb";

    #[test]
    fn a_matching_digest_is_current() {
        assert_eq!(coverage_of(Some(A), A), SealCoverage::Current);
    }

    /// The case the whole lookup exists for: the passport was re-published, so
    /// the stored seal covers a signature it no longer carries.
    #[test]
    fn a_differing_digest_is_superseded() {
        assert_eq!(coverage_of(Some(A), B), SealCoverage::Superseded);
    }

    /// No record is not the same as no coverage.
    ///
    /// A seal restored from a backup is very likely current; this node simply
    /// cannot say so, and reporting `superseded` would brand a sound passport as
    /// stale on the strength of a missing row.
    #[test]
    fn no_record_is_unknown_rather_than_superseded() {
        assert_eq!(coverage_of(None, A), SealCoverage::Unknown);
    }

    /// The wire values are part of the published contract.
    #[test]
    fn coverage_serialises_to_the_documented_strings() {
        let rendered = |c: SealCoverage| serde_json::to_string(&c).expect("serialise");
        assert_eq!(rendered(SealCoverage::Current), "\"current\"");
        assert_eq!(rendered(SealCoverage::Superseded), "\"superseded\"");
        assert_eq!(rendered(SealCoverage::Unknown), "\"unknown\"");
    }
}
