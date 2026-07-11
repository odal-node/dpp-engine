//! Transfer-chain signature verification.
//!
//! Nothing else in the engine verifies a whole [`TransferChain`] standalone —
//! signature checking normally happens inline, one record at a time, as
//! part of accepting a transfer. This is the "verify the whole chain
//! after the fact" implementation; it reuses `TransferRecord::signing_payload`
//! (the exact bytes both operators sign) and the same JWS verification used
//! everywhere else, just applied per-record.

use std::collections::BTreeMap;

use dpp_domain::domain::transfer::TransferChain;

use super::jws::{resolve_public_key, verify_jws_content};

/// Which signature(s) on a transfer record failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferSignatureIssue {
    /// The `from_operator`'s signature is missing, or failed to verify, or
    /// their DID document was not available to check against.
    From(String),
    /// The `to_operator`'s signature is missing, or failed to verify, or
    /// their DID document was not available to check against.
    To(String),
}

/// The first broken record found while verifying a transfer chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferChainBreak {
    /// 0-based position of the offending record in `chain.transfers`.
    pub index: usize,
    pub issue: TransferSignatureIssue,
}

/// Verify every completed transfer record's signatures against the DID
/// documents available in `did_documents` (keyed by DID).
///
/// A **completed** record (has `completed_at`, not rejected/cancelled) must
/// carry both operator signatures — an absent signature fails closed rather than
/// being treated as "nothing to verify", so a record a producing node marked
/// completed without signing can never pass with zero cryptographic checks. A
/// still-`Initiated` record's not-yet-present signature is skipped. A record
/// whose signer's DID document is missing from `did_documents` fails closed
/// (reported, not silently skipped) so a verifier never reports false-green on
/// an unresolvable cross-operator DID.
///
/// # Errors
/// [`TransferChainBreak`] at the first record with a missing (on a completed
/// record), bad, or unverifiable signature.
pub fn verify_transfer_chain(
    chain: &TransferChain,
    did_documents: &BTreeMap<String, serde_json::Value>,
) -> Result<(), TransferChainBreak> {
    for (index, record) in chain.transfers.iter().enumerate() {
        // A completed transfer must be fully signed by both parties.
        let is_completed = record.completed_at.is_some()
            && record.rejected_at.is_none()
            && record.cancelled_at.is_none();

        let payload = record.signing_payload();

        match &record.from_signature {
            Some(sig) => {
                check_signature(&record.from_operator.did, sig, &payload, did_documents).map_err(
                    |reason| TransferChainBreak {
                        index,
                        issue: TransferSignatureIssue::From(reason),
                    },
                )?;
            }
            None if is_completed => {
                return Err(TransferChainBreak {
                    index,
                    issue: TransferSignatureIssue::From(
                        "completed transfer is missing the from-operator signature".into(),
                    ),
                });
            }
            None => {}
        }

        match &record.to_signature {
            Some(sig) => {
                check_signature(&record.to_operator.did, sig, &payload, did_documents).map_err(
                    |reason| TransferChainBreak {
                        index,
                        issue: TransferSignatureIssue::To(reason),
                    },
                )?;
            }
            None if is_completed => {
                return Err(TransferChainBreak {
                    index,
                    issue: TransferSignatureIssue::To(
                        "completed transfer is missing the to-operator signature".into(),
                    ),
                });
            }
            None => {}
        }
    }
    Ok(())
}

fn check_signature(
    did: &str,
    jws: &str,
    payload: &serde_json::Value,
    did_documents: &BTreeMap<String, serde_json::Value>,
) -> Result<(), String> {
    let did_doc = did_documents
        .get(did)
        .ok_or_else(|| format!("no DID document available for {did} — cannot verify"))?;
    let key = resolve_public_key(jws, did_doc)
        .ok_or_else(|| format!("no usable assertion key found in DID document for {did}"))?;

    match verify_jws_content(jws, &key, payload) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "signature does not verify against {did}'s key, or covers different content than the transfer terms"
        )),
        Err(e) => Err(format!("malformed signature: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use dpp_crypto::jws::canonicalize;
    use dpp_domain::domain::{
        passport::PassportId,
        transfer::{OperatorRole, ResponsibleOperator, TransferReason, TransferRecord},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use uuid::Uuid;

    fn operator(did: &str) -> ResponsibleOperator {
        ResponsibleOperator {
            did: did.to_owned(),
            name: "Acme".into(),
            role: OperatorRole::Distributor,
            eu_operator_id: None,
            country: "DE".into(),
        }
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

    fn sign(signing_key: &SigningKey, payload: &serde_json::Value) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(serde_json::to_vec(&serde_json::json!({"alg": "EdDSA"})).unwrap());
        let body = b64.encode(canonicalize(payload).unwrap());
        let signing_input = format!("{header}.{body}");
        let sig = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64.encode(sig.to_bytes()))
    }

    fn record_with_signatures(
        from_key: &SigningKey,
        to_key: &SigningKey,
        from_did: &str,
        to_did: &str,
    ) -> TransferRecord {
        let mut record = TransferRecord {
            transfer_id: Uuid::now_v7(),
            passport_id: PassportId::new(),
            from_operator: operator(from_did),
            to_operator: operator(to_did),
            reason: TransferReason::Sale,
            from_signature: None,
            to_signature: None,
            initiated_at: Utc::now(),
            completed_at: None,
            rejected_at: None,
            cancelled_at: None,
            notes: None,
        };
        let payload = record.signing_payload();
        record.from_signature = Some(sign(from_key, &payload));
        record.to_signature = Some(sign(to_key, &payload));
        record
    }

    #[test]
    fn intact_chain_verifies() {
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let to_key = SigningKey::from_bytes(&[2u8; 32]);
        let record = record_with_signatures(
            &from_key,
            &to_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));
        docs.insert("did:web:to.example".to_string(), did_doc_for(&to_key));

        assert!(verify_transfer_chain(&chain, &docs).is_ok());
    }

    #[test]
    fn tampered_to_signature_is_detected() {
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let to_key = SigningKey::from_bytes(&[2u8; 32]);
        let mut record = record_with_signatures(
            &from_key,
            &to_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        record.to_signature = record.to_signature.map(|s| format!("{s}tampered"));
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));
        docs.insert("did:web:to.example".to_string(), did_doc_for(&to_key));

        let brk = verify_transfer_chain(&chain, &docs).expect_err("must detect tamper");
        assert_eq!(brk.index, 0);
        assert!(matches!(brk.issue, TransferSignatureIssue::To(_)));
    }

    #[test]
    fn missing_did_document_fails_closed() {
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let to_key = SigningKey::from_bytes(&[2u8; 32]);
        let record = record_with_signatures(
            &from_key,
            &to_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        // Only the "from" DID document is available.
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));

        let brk = verify_transfer_chain(&chain, &docs).expect_err("must fail closed");
        assert!(matches!(brk.issue, TransferSignatureIssue::To(_)));
    }

    #[test]
    fn completed_record_without_signatures_fails_closed() {
        // A record marked completed but carrying no signatures (a producing-node
        // workflow bug) must fail closed, not pass with zero cryptographic checks.
        let record = TransferRecord {
            transfer_id: Uuid::now_v7(),
            passport_id: PassportId::new(),
            from_operator: operator("did:web:from.example"),
            to_operator: operator("did:web:to.example"),
            reason: TransferReason::Sale,
            from_signature: None,
            to_signature: None,
            initiated_at: Utc::now(),
            completed_at: Some(Utc::now()),
            rejected_at: None,
            cancelled_at: None,
            notes: None,
        };
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        // No DID docs needed — it must fail on the missing signature first.
        let brk = verify_transfer_chain(&chain, &BTreeMap::new())
            .expect_err("a completed but unsigned record must fail closed");
        assert_eq!(brk.index, 0);
        assert!(matches!(brk.issue, TransferSignatureIssue::From(_)));
    }

    #[test]
    fn initiated_record_pending_countersignature_is_skipped() {
        // Still-Initiated (not completed): from signed, awaiting the to-operator.
        // The absent to-signature is skipped, not treated as a failure.
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut record = TransferRecord {
            transfer_id: Uuid::now_v7(),
            passport_id: PassportId::new(),
            from_operator: operator("did:web:from.example"),
            to_operator: operator("did:web:to.example"),
            reason: TransferReason::Sale,
            from_signature: None,
            to_signature: None,
            initiated_at: Utc::now(),
            completed_at: None,
            rejected_at: None,
            cancelled_at: None,
            notes: None,
        };
        let payload = record.signing_payload();
        record.from_signature = Some(sign(&from_key, &payload));
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));
        assert!(
            verify_transfer_chain(&chain, &docs).is_ok(),
            "an initiated (uncompleted) record must not fail on its pending countersignature"
        );
    }
}
