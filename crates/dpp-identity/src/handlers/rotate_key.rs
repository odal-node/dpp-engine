//! `POST /internal/keys/rotate` — rotate the Ed25519 signing key for an operator.
//!
//! Accessible only behind the mTLS middleware (`CN=odal-vault`).
//!
//! Before rotating a production operator's key, follow the custody procedure
//! in `docs/ops/PRODUCTION-RUNBOOK.md`'s key-rotation section — it covers the
//! archive-then-generate ordering this handler performs and what to verify
//! before and after.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use dpp_common::http_problem;
use serde::Deserialize;
use serde_json::json;

use dpp_crypto::identity::did_builder;

use crate::state::AppState;

/// Request body for the key rotation endpoint.
#[derive(Debug, Deserialize)]
pub struct RotateRequest {
    /// The operator whose active signing key is to be rotated.
    pub operator_id: String,
}

/// Rotate the Ed25519 signing key for an operator.
///
/// Workflow:
///   1. Archive the existing key under a timestamped entry (so old signatures
///      remain verifiable after the rotation).
///   2. Generate and persist a new key pair.
///   3. Rebuild the DID document: new key is `#key-1` (primary / `authentication`);
///      archived keys are appended as `#key-2`, `#key-3`, … under `assertionMethod`
///      so historical passport signatures remain verifiable.
///   4. Return the new fingerprint and the updated DID document.
pub async fn rotate_key_handler(
    State(state): State<AppState>,
    Json(body): Json<RotateRequest>,
) -> impl IntoResponse {
    if !super::sign::is_valid_operator_id(&body.operator_id) {
        return http_problem::unprocessable(
            "operator_id must be 1-64 characters of [A-Za-z0-9._:-]",
        )
        .into_response();
    }

    // Archive first — and ABORT if it fails. Generating a new key overwrites the
    // current record, so proceeding without a successful archive would destroy
    // the old key with no backup and permanently invalidate every JWS it signed.
    if let Err(e) = state.store.archive_key(&body.operator_id) {
        tracing::error!(operator_id = %body.operator_id, error = %e, "aborting rotation — could not archive the current signing key");
        return http_problem::internal_error(
            "could not archive the current signing key; rotation aborted to avoid losing it",
        )
        .into_response();
    }

    let new_key = match state.store.generate_key(&body.operator_id) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(operator_id = %body.operator_id, error = %e, "key rotation failed");
            return http_problem::internal_error(e.to_string()).into_response();
        }
    };

    // Rebuild the DID document with the new primary key and all archived keys.
    let did_document = match did_builder::build_did_document(
        &state.store,
        &state.did_web_base_url,
        &body.operator_id,
    ) {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!(operator_id = %body.operator_id, error = %e, "failed to build DID document after rotation");
            return http_problem::internal_error(e.to_string()).into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "operator_id": body.operator_id,
            "new_key_id": format!("{}#key-1", did_document["id"].as_str().unwrap_or("")),
            "fingerprint": new_key.fingerprint,
            "rotated": true,
            "did_document": did_document
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dpp_crypto::jws::{signer, verifier};

    use super::*;
    use crate::state::AppState;

    fn temp_store() -> dpp_crypto::keystore::KeyStore {
        let path = std::env::temp_dir().join(format!("rotate-test-{}.json", uuid::Uuid::now_v7()));
        dpp_crypto::keystore::KeyStore::open(path, "test").expect("open store")
    }

    /// Regression (custody runbook §"key rotation"): a JWS signed before a key
    /// rotation must still verify afterwards, via `kid`-based lookup against
    /// the archived key the rotation appends to the DID document's
    /// `assertionMethod` set. Without this, rotating a production operator's
    /// key would silently invalidate every passport signed before the
    /// rotation — this is the fix the runbook flags as needing a green test.
    #[tokio::test]
    async fn signature_signed_before_rotation_still_verifies_after() {
        let store = temp_store();
        store.generate_key("op1").expect("provision initial key");

        let payload = json!({"id": "dpp:test:1", "status": "published"});
        let jws_before = signer::sign(&store, "op1", &payload).expect("sign before rotation");
        let kid = verifier::extract_kid_from_jws(&jws_before).expect("kid present in header");

        let state = AppState {
            store: Arc::new(store),
            did_web_base_url: "http://localhost".into(),
        };

        let resp = rotate_key_handler(
            State(state.clone()),
            Json(RotateRequest {
                operator_id: "op1".into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let did_document =
            did_builder::build_did_document(&state.store, &state.did_web_base_url, "op1")
                .expect("build did document after rotation");

        // The pre-rotation key must still resolve by its kid fingerprint...
        let archived_key = verifier::extract_key_by_fingerprint(&did_document, &kid)
            .expect("archived key still resolvable by kid after rotation");
        assert!(
            verifier::verify_jws(&jws_before, &archived_key).expect("verify_jws parses cleanly"),
            "JWS signed before rotation must still verify against the archived key"
        );

        // ...and it must genuinely be the archived key, not the new primary —
        // otherwise this test would pass even if archival were broken.
        let new_primary =
            verifier::extract_primary_public_key(&did_document).expect("new primary key present");
        assert_ne!(
            archived_key, new_primary,
            "archived key must differ from the new primary"
        );
    }
}
