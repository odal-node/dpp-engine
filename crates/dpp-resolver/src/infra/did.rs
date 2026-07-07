//! Passport JWS verification against the operator's `did:web` document.

use axum::http::StatusCode;
use base64::Engine;
use dpp_common::event_codes;
use metrics;
use serde_json::Value;
use tracing;

use dpp_crypto::jws::verifier as jws;

/// Verify a published passport's **public** signature (`publicJwsSignature`)
/// against the operator's did:web document and return the verified public view.
///
/// The signature is over the canonical public (redacted) view, so the decoded
/// payload *is* the authoritative content — the resolver renders from it rather
/// than from the separately-served JSON, removing any need for content-binding.
///
/// **Fails closed.** Any missing/unreachable/invalid input is an error, never a
/// silent pass. Returns:
/// - `Ok(view)` — signature valid; `view` is the verified public passport (or
///   the served value verbatim when verification is disabled via an empty
///   `operator_did_url`, dev/test only).
/// - `Err(CONFLICT)` (409) — missing/invalid signature, or the proof's `id` does
///   not match the requested passport.
/// - `Err(SERVICE_UNAVAILABLE)` (503) — the operator DID document could not be
///   fetched/parsed, so the passport cannot be verified right now.
#[tracing::instrument(skip(http, passport))]
pub async fn verify_passport_jws(
    http: &reqwest::Client,
    operator_did_url: &str,
    passport: &Value,
) -> Result<Value, StatusCode> {
    // Verification explicitly disabled (dev/test only): trust the served view.
    if operator_did_url.is_empty() {
        metrics::counter!("jws_verify_total", "outcome" => "disabled").increment(1);
        return Ok(passport.clone());
    }

    // The public passport carries a JWS over its *public (redacted) view*
    // (`publicJwsSignature`). We verify it and render from the signed payload, so
    // there is nothing separately-served left to tamper.
    let jws = match passport
        .get("publicJwsSignature")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(j) => j,
        // A passport served by the resolver is published and MUST be signed.
        None => {
            metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
            tracing::warn!(
                code = event_codes::JWS_TAMPER,
                "published passport has no public signature — refusing to serve as valid"
            );
            return Err(StatusCode::CONFLICT);
        }
    };

    // Fetch the operator DID document; fail closed (503) on any transport/parse error.
    let did_doc = fetch_did(http, operator_did_url).await?;

    // Select the key by kid (fingerprint) so rotation-archived keys remain usable.
    // Fall back to the primary key for old kid-less JWS tokens.
    let pub_key = {
        let kid = jws::extract_kid_from_jws(jws);
        kid.as_deref()
            .and_then(|k| jws::extract_key_by_fingerprint(&did_doc, k))
            .or_else(|| jws::extract_primary_public_key(&did_doc))
            .ok_or_else(|| {
                tracing::warn!(
                    code = event_codes::DID_UNREACHABLE,
                    operator_did_url,
                    "operator DID has no matching verification key"
                );
                StatusCode::SERVICE_UNAVAILABLE
            })?
    };

    // 1) Signature must verify against the operator key.
    match jws::verify_jws(jws, &pub_key) {
        Ok(true) => {}
        Ok(false) => {
            metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
            tracing::warn!(
                code = event_codes::JWS_TAMPER,
                "JWS signature does not verify against the operator DID"
            );
            return Err(StatusCode::CONFLICT);
        }
        Err(e) => {
            metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
            tracing::warn!(
                code = event_codes::JWS_TAMPER,
                error = %e,
                "JWS verification error"
            );
            return Err(StatusCode::CONFLICT);
        }
    }

    // The signed public view is the authoritative content the resolver renders;
    // there is no separately-served payload to bind against.
    let signed = decode_jws_payload(jws).ok_or_else(|| {
        metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
        tracing::warn!(
            code = event_codes::JWS_TAMPER,
            "could not decode the public JWS payload"
        );
        StatusCode::CONFLICT
    })?;

    // Bind the proof to the requested passport: the signed view's id must match
    // the served passport's id (fetched by the requested id). Stops a valid proof
    // for one passport being replayed under another id.
    if signed.get("id") != passport.get("id") {
        metrics::counter!("jws_verify_total", "outcome" => "tampered").increment(1);
        tracing::warn!(
            code = event_codes::JWS_TAMPER,
            "signed public view id does not match the served passport id"
        );
        return Err(StatusCode::CONFLICT);
    }

    metrics::counter!("jws_verify_total", "outcome" => "ok").increment(1);
    Ok(signed)
}

async fn fetch_did(http: &reqwest::Client, url: &str) -> Result<Value, StatusCode> {
    let resp = http.get(url).send().await.map_err(|e| {
        tracing::warn!(code = event_codes::DID_UNREACHABLE, url, error = %e, "could not fetch operator DID document");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    if !resp.status().is_success() {
        tracing::warn!(code = event_codes::DID_UNREACHABLE, url, status = %resp.status(), "operator DID endpoint returned non-2xx");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    resp.json().await.map_err(|e| {
        tracing::warn!(code = event_codes::DID_UNREACHABLE, url, error = %e, "operator DID document is not valid JSON");
        StatusCode::SERVICE_UNAVAILABLE
    })
}

/// Decode the (already-verified) payload segment of a compact JWS into JSON.
fn decode_jws_payload(jws: &str) -> Option<Value> {
    let payload_b64 = jws.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use dpp_common::event_codes::MUTABLE_FIELDS;

    // ── DAL D2: MUTABLE_FIELDS parity guard ─────────────────────────────────

    /// `MUTABLE_FIELDS` must equal the DB retention trigger's `mutable_keys`
    /// array (`0004_passport.sql`, amended by `0011_public_jws_mutable.sql`):
    /// the fields a retention-locked passport may still change. Machine-checks
    /// the DAL D2 invariant so the two cannot silently diverge.
    #[test]
    fn mutable_fields_matches_db_trigger_mutable_keys() {
        let expected: &[&str] = &[
            "status",
            "jwsSignature",
            "publicJwsSignature",
            "qrCodeUrl",
            "publishedAt",
            "retentionLocked",
            "updatedAt",
        ];
        let mut actual = MUTABLE_FIELDS.to_vec();
        let mut want = expected.to_vec();
        actual.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            actual, want,
            "MUTABLE_FIELDS in dpp-common must match the DB trigger's mutable_keys"
        );
    }
}
