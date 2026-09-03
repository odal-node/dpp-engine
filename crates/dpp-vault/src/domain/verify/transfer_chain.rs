//! Transfer-chain signature verification.
//!
//! Nothing else in the engine verifies a whole [`TransferChain`] standalone —
//! signature checking normally happens inline, one record at a time, as
//! part of accepting a transfer. This is the "verify the whole chain
//! after the fact" implementation, using the same JWS verification as
//! everywhere else, applied per-record: `TransferRecord::signing_payload` for
//! the outgoing operator's signature, and [`acceptance_payload`] for the
//! hosting node's attestation.

use std::collections::BTreeMap;

use dpp_domain::transfer::TransferChain;

use super::jws::{resolve_public_key, verify_jws_content};

/// The bytes the hosting node signs to attest that it ran the acceptance step.
///
/// Deliberately **not** `TransferRecord::signing_payload()`. That is the
/// initiation payload, and the outgoing operator has already signed it — so
/// re-signing it says nothing the record did not already carry, and on a node
/// where the signer and the from-operator are the same key it produces a JWS
/// byte-identical to `from_signature`. An attestation that can be produced by
/// copying a field which existed *before* the step it attests is not evidence
/// of that step.
///
/// So the payload is discriminated (`attests: "acceptance"`) and binds the
/// terms being accepted, not merely the record's identity: accepting transfer
/// `X` is a statement about the operators and reason in `X`, and an attestation
/// that named only the id would still verify if those changed.
///
/// It carries no timestamp. `TransferRecord::complete()` refuses until the
/// attestation exists — the attestation is what moves the record to `Accepted`
/// — so `completed_at` is not yet set when these bytes are signed. Binding a
/// second, separately-generated time would put two answers for one fact in the
/// record; the chain's honest claim is *that* this node accepted, and `when` is
/// `completed_at`'s job.
pub fn acceptance_payload(record: &dpp_domain::transfer::TransferRecord) -> serde_json::Value {
    serde_json::json!({
        "attests": "acceptance",
        "transferId": record.transfer_id,
        "passportId": record.passport_id,
        "fromOperator": record.from_operator,
        "toOperator": record.to_operator,
        "reason": record.reason,
        "initiatedAt": record.initiated_at,
    })
}

/// Which signature(s) on a transfer record failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferSignatureIssue {
    /// The `from_operator`'s signature is missing, or failed to verify, or
    /// their DID document was not available to check against.
    From(String),
    /// The hosting node's acceptance attestation is missing from a completed
    /// transfer, or failed to verify against that node's key.
    ///
    /// It is checked against the **node's** DID, never the incoming operator's:
    /// the node produces it, and checking it against a counterparty would
    /// re-assert the two-party proof this crate deliberately stopped claiming.
    /// See [`verify_transfer_chain`] and [`acceptance_payload`].
    Acceptance(String),
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
/// carry the outgoing operator's signature *and* the hosting node's acceptance
/// attestation — an absent one fails closed rather than being treated as
/// "nothing to verify", so a record a producing node marked completed without
/// signing can never pass with zero checks.
///
/// **Both signatures are verified, against different parties.** The outgoing
/// operator's is checked against `from_operator.did`; the acceptance
/// attestation is checked against `node_did` — the hosting node, which is what
/// produces it. Checking the latter against `to_operator.did`, as this function
/// once did, claimed a two-party proof nobody produced; checking it against the
/// node claims only what is true, and the authority on who holds the
/// obligations remains the EU registry.
///
/// `node_did` is the dossier's `issuer_did`, which an evidence dossier always
/// carries — the generator inserts its own DID document before any
/// counterparty's, so the key needed for this check is never the one that is
/// missing.
///
/// A still-`Initiated` record's not-yet-present signature is skipped. A record
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
    node_did: &str,
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

        // The acceptance attestation is the hosting node's, so it is verified
        // against `node_did` — never against `to_operator.did`, which this
        // function used to do and which asserted a two-party proof nobody
        // produced. The core type is named `node_acceptance_attestation` for
        // that reason, and that correction stands.
        //
        // What changed is that the bit it carries is now actually carried.
        // Presence alone was the check, and the value was
        // `signing_payload()` — the *initiation* payload, which the outgoing
        // operator has already signed. On a single-operator node the node key
        // and the from-operator key are the same key, so the attestation came
        // out byte-identical to `from_signature`: 896 bytes, both, verified in
        // Postgres. Anything holding the initiated record could therefore
        // produce the "acceptance" by copying a field that existed before the
        // acceptance happened, and presence-checking it would pass.
        //
        // Signing a distinct payload is what makes the bit unforgeable from
        // data that predates the step. Who actually holds the obligations
        // remains a question for the EU registry under Impl. Reg. (EU)
        // 2026/1778 Art. 6a, not for this chain.
        match &record.node_acceptance_attestation {
            Some(sig) => {
                check_signature(node_did, sig, &acceptance_payload(record), did_documents)
                    .map_err(|reason| TransferChainBreak {
                        index,
                        issue: TransferSignatureIssue::Acceptance(reason),
                    })?;
            }
            None if is_completed => {
                return Err(TransferChainBreak {
                    index,
                    issue: TransferSignatureIssue::Acceptance(
                        "completed transfer is missing the node's acceptance attestation".into(),
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
    use dpp_domain::{
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
            eu_operator_id_scheme: None,
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

    /// The DID of the node hosting the chain — the party whose key signs the
    /// acceptance attestation. Distinct from `to_operator`, which signs nothing:
    /// that separation is the whole point of `node_acceptance_attestation`.
    const NODE_DID: &str = "did:web:node.example";

    fn record_with_signatures(
        from_key: &SigningKey,
        node_key: &SigningKey,
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
            node_acceptance_attestation: None,
            initiated_at: Utc::now(),
            completed_at: None,
            rejected_at: None,
            cancelled_at: None,
            notes: None,
        };
        record.from_signature = Some(sign(from_key, &record.signing_payload()));
        record.node_acceptance_attestation = Some(sign(node_key, &acceptance_payload(&record)));
        record
    }

    #[test]
    fn intact_chain_verifies() {
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let node_key = SigningKey::from_bytes(&[2u8; 32]);
        let record = record_with_signatures(
            &from_key,
            &node_key,
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
        docs.insert(NODE_DID.to_string(), did_doc_for(&node_key));

        assert!(verify_transfer_chain(&chain, &docs, NODE_DID).is_ok());
    }

    #[test]
    fn a_tampered_acceptance_attestation_is_detected() {
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let node_key = SigningKey::from_bytes(&[2u8; 32]);
        let mut record = record_with_signatures(
            &from_key,
            &node_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        record.node_acceptance_attestation = record
            .node_acceptance_attestation
            .map(|s| format!("{s}tampered"));
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));
        docs.insert(NODE_DID.to_string(), did_doc_for(&node_key));

        // This assertion has now been both ways, and the previous comment asked
        // for exactly this moment: it said that if verification were
        // reintroduced "against the node's own identity, where it would be
        // truthful — this test fails and the decision gets made again rather
        // than drifting back silently." It failed. This is that decision.
        //
        // What was wrong before was the *party*, not the checking. Verifying
        // against `to_operator.did` claimed the incoming operator had signed
        // something they never did. Verifying against the node claims only what
        // the node itself did, which is all this value has ever been.
        let brk = verify_transfer_chain(&chain, &docs, NODE_DID)
            .expect_err("a tampered attestation must not verify against the node key");
        assert!(
            matches!(brk.issue, TransferSignatureIssue::Acceptance(_)),
            "expected an Acceptance issue, got {:?}",
            brk.issue
        );
    }

    /// The defect that motivated verifying this at all.
    ///
    /// When the node key and the from-operator key are the same — every
    /// single-operator deployment — signing the *initiation* payload for both
    /// produced two byte-identical JWS values. Anyone holding the initiated
    /// record could then produce the "acceptance" by copying `from_signature`,
    /// and a presence check would accept it.
    ///
    /// Signing a discriminated payload is what breaks that equality, so this
    /// asserts on the one key where the old code could not tell them apart.
    #[test]
    fn the_attestation_differs_from_the_from_signature_under_one_key() {
        let one_key = SigningKey::from_bytes(&[3u8; 32]);
        let record = record_with_signatures(
            &one_key,
            &one_key,
            "did:web:solo.example",
            "did:web:to.example",
        );

        assert_ne!(
            record.from_signature, record.node_acceptance_attestation,
            "one key signing both payloads must still yield two distinct signatures,              or the acceptance is copyable from the initiation"
        );
    }

    #[test]
    fn missing_did_document_fails_closed() {
        let from_key = SigningKey::from_bytes(&[1u8; 32]);
        let node_key = SigningKey::from_bytes(&[2u8; 32]);
        let record = record_with_signatures(
            &from_key,
            &node_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        // Only the "to" DID document is available, so the outgoing operator's
        // signature — the one signature actually verified here — cannot be
        // checked. An unresolvable DID must be reported, never skipped into a
        // false green.
        //
        // The case used to be the mirror of this: withhold the *to* document
        // and expect a break. That stopped being a test of anything when the
        // acceptance attestation stopped being verified against the incoming
        // operator's DID — no `to` document is consulted at all now.
        let mut docs = BTreeMap::new();
        docs.insert(NODE_DID.to_string(), did_doc_for(&node_key));

        let brk = verify_transfer_chain(&chain, &docs, NODE_DID).expect_err("must fail closed");
        assert!(matches!(brk.issue, TransferSignatureIssue::From(_)));
    }

    #[test]
    fn a_completed_record_missing_only_the_attestation_fails_closed() {
        // The outgoing signature is present and valid, so verification reaches
        // the acceptance check rather than returning on the one before it.
        //
        // `completed_record_without_signatures_fails_closed` leaves both absent
        // and therefore stops at `From`, so it never exercised this branch —
        // which meant the acceptance check had no test at all.
        let from_key = SigningKey::from_bytes(&[7u8; 32]);
        let node_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut record = record_with_signatures(
            &from_key,
            &node_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        record.completed_at = Some(Utc::now());
        record.node_acceptance_attestation = None;

        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));

        let brk = verify_transfer_chain(&chain, &docs, NODE_DID)
            .expect_err("a completed transfer must carry the node's acceptance attestation");
        assert_eq!(brk.index, 0);
        assert!(
            matches!(brk.issue, TransferSignatureIssue::Acceptance(_)),
            "must fail on the acceptance step, not an earlier one; got: {:?}",
            brk.issue
        );
    }

    #[test]
    fn an_initiated_record_may_lack_the_attestation() {
        // The mirror of the above, and the reason the check is conditioned on
        // completion: a transfer awaiting acceptance legitimately has none.
        let from_key = SigningKey::from_bytes(&[7u8; 32]);
        let node_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut record = record_with_signatures(
            &from_key,
            &node_key,
            "did:web:from.example",
            "did:web:to.example",
        );
        record.node_acceptance_attestation = None;

        let chain = TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        };
        let mut docs = BTreeMap::new();
        docs.insert("did:web:from.example".to_string(), did_doc_for(&from_key));

        assert!(verify_transfer_chain(&chain, &docs, NODE_DID).is_ok());
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
            node_acceptance_attestation: None,
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
        let brk = verify_transfer_chain(&chain, &BTreeMap::new(), NODE_DID)
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
            node_acceptance_attestation: None,
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
            verify_transfer_chain(&chain, &docs, NODE_DID).is_ok(),
            "an initiated (uncompleted) record must not fail on its pending countersignature"
        );
    }
}
