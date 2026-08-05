//! `GET /api/v1/dpp/{dppId}/seal` — the passport's eIDAS qualified seal.
//!
//! The seal needs its own route because it is stripped from every audience view:
//! it covers the *full*-payload `jwsSignature`, so attaching it to a redacted
//! body would hand the reader a proof that verifies against nothing they were
//! given (see `crate::public_view::audience_view`). Here it travels with the
//! signature it actually attests to, and with the digest a verifier needs to
//! check it against.
//!
//! What this route does **not** do is validate the CAdES. No Rust AdES validator
//! exists, and a seal is worth exactly as much as the independence of whoever
//! checked it — so the response carries everything an external validator needs
//! and states plainly what has and has not been verified.

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

/// The seal, plus what is needed to check it and what we did not check.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealResponse {
    /// AdES format of `sealValue` — `CADES` for the eID Easy backend.
    pub format: String,
    /// Base64 detached CAdES (`.p7s`) as returned by the QTSP.
    pub seal_value: String,
    /// When the QTSP produced it.
    pub sealed_at: chrono::DateTime<chrono::Utc>,
    /// True when this is a `GhostSeal` placeholder with no legal validity.
    pub placeholder: bool,
    /// The passport's **current** compact JWS.
    pub current_jws: String,
    /// Hex SHA-256 of `currentJws` — the digest a seal over this passport's
    /// present signature would have been taken over.
    ///
    /// Deliberately labelled "current" rather than "sealed": `SealedEnvelope`
    /// does not record its own preimage, so this node cannot assert that the
    /// seal above was taken over *this* digest. It is one half of the comparison,
    /// and the external validator supplies the other half by extracting the
    /// signed message digest from the CAdES itself.
    pub current_payload_hash: String,
    /// Stated, not implied: this node did not cryptographically validate the
    /// CAdES, and says so rather than letting the response read as a verdict.
    pub verification: &'static str,
}

const NOT_VALIDATED: &str = "not validated by this node — a detached CAdES must be checked by an independent AdES \
     validator against the EU Trusted List. That check also establishes whether this seal covers \
     currentPayloadHash: compare the validator's extracted message digest against it. A mismatch \
     means the passport was re-published after sealing and a seal over the new signature has not \
     landed yet — the seal remains valid for the signature it does cover.";

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

    (
        StatusCode::OK,
        Json(SealResponse {
            format: serde_json::to_value(&seal.format)
                .ok()
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
                .unwrap_or_default(),
            seal_value: seal.seal_value.clone(),
            sealed_at: seal.sealed_at,
            placeholder: seal.placeholder,
            current_jws: jws,
            current_payload_hash: payload_hash,
            verification: NOT_VALIDATED,
        }),
    )
        .into_response()
}
