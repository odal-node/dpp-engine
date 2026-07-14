//! The verification engine: runs every check independently against a
//! [`DossierV1`] and produces a [`VerificationReport`] — a single tamper
//! flips exactly one named check, never cascades into unrelated failures.

use dpp_types::audit::verify_audit_chain;
use dpp_types::evidence::{
    CheckResult, CheckStatus, DossierV1, VerificationReport, compute_content_hashes,
};

use super::jws::{resolve_public_key, verify_jws_content};
use super::transfer_chain::verify_transfer_chain;

/// A dossier that could not even be parsed — distinct from a dossier that
/// parsed fine but failed one or more checks (that's a [`VerificationReport`]
/// with `all_verified() == false`, exit code 1). This is exit code 2: the
/// input is not a dossier this verifier understands at all, including an
/// unrecognised field (`deny_unknown_fields`) — which may mean the dossier
/// was produced by a newer format version than this verifier knows.
#[derive(Debug, thiserror::Error)]
pub enum DossierParseError {
    #[error("not a valid dossier — malformed JSON or an unrecognised field: {0}")]
    Json(#[from] serde_json::Error),
}

/// Run every check against `dossier` and produce a full report.
///
/// For typed callers that already hold a `DossierV1`. Byte-level consumers
/// (the verify endpoints) should use [`verify_dossier_json`] instead — it
/// additionally runs the `input_fidelity` check, which needs the original
/// raw bytes.
pub fn verify_dossier(dossier: &DossierV1) -> VerificationReport {
    let mut checks = Vec::new();

    let issuer_key = dossier
        .did_documents
        .get(&dossier.manifest.issuer_did)
        .and_then(|doc| resolve_public_key(&dossier.manifest_jws, doc));

    // 1. Manifest authenticity.
    checks.push(CheckResult {
        name: "manifest_signature".into(),
        status: match &issuer_key {
            None => CheckStatus::Fail(format!(
                "no DID document available for issuer {}",
                dossier.manifest.issuer_did
            )),
            Some(key) => {
                let manifest_value = serde_json::to_value(&dossier.manifest)
                    .expect("DossierManifest serialises");
                match verify_jws_content(&dossier.manifest_jws, key, &manifest_value) {
                    Ok(true) => CheckStatus::Pass,
                    Ok(false) => CheckStatus::Fail(
                        "manifest signature invalid, or covers different content than this manifest".into(),
                    ),
                    Err(e) => CheckStatus::Fail(format!("malformed manifest signature: {e}")),
                }
            }
        },
    });

    // 2. Content integrity — every member hashes to what the signed
    //    manifest commits to.
    checks.push(CheckResult {
        name: "content_integrity".into(),
        status: {
            let recomputed = compute_content_hashes(dossier);
            if recomputed == dossier.manifest.content_hashes {
                CheckStatus::Pass
            } else {
                let mismatched: Vec<&String> = recomputed
                    .keys()
                    .filter(|k| recomputed.get(*k) != dossier.manifest.content_hashes.get(*k))
                    .collect();
                CheckStatus::Fail(format!(
                    "content hash mismatch for: {}",
                    mismatched
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        },
    });

    // 3. Full-view passport JWS.
    checks.push(layer_check(
        "full_view_signature",
        &issuer_key,
        &dossier.manifest.issuer_did,
        &dossier.full_view.jws,
        &dossier.full_view.payload,
    ));

    // 4. Public-view passport JWS.
    checks.push(layer_check(
        "public_view_signature",
        &issuer_key,
        &dossier.manifest.issuer_did,
        &dossier.public_view.jws,
        &dossier.public_view.payload,
    ));

    // 5. Audit chain.
    checks.push(CheckResult {
        name: "audit_chain".into(),
        status: match verify_audit_chain(&dossier.audit_entries) {
            Ok(()) => CheckStatus::Pass,
            Err(brk) => CheckStatus::Fail(format!("broken at entry {}: {}", brk.index, brk.reason)),
        },
    });

    // 6. Transfer chain.
    checks.push(CheckResult {
        name: "transfer_chain".into(),
        status: match &dossier.transfer_chain {
            None => CheckStatus::Absent("no transfer chain on this passport".into()),
            Some(chain) => match verify_transfer_chain(chain, &dossier.did_documents) {
                Ok(()) => CheckStatus::Pass,
                Err(brk) => {
                    CheckStatus::Fail(format!("broken at transfer {}: {:?}", brk.index, brk.issue))
                }
            },
        },
    });

    // 7. Checkpoint — always absent in v1, said honestly, never a failure.
    checks.push(CheckResult {
        name: "checkpoint".into(),
        status: match &dossier.checkpoint {
            None => CheckStatus::Absent(
                "checkpoint layer not yet implemented — audit chain integrity is checked, \
                 but nothing pins the chain head against third-party re-hash"
                    .into(),
            ),
            Some(_) => CheckStatus::Fail(
                "checkpoint present but this verifier build does not yet check it".into(),
            ),
        },
    });

    // 8. Calc receipts — always absent in v1, said honestly, never a failure.
    checks.push(CheckResult {
        name: "calc_receipts".into(),
        status: if dossier.calc_receipts.is_empty() {
            CheckStatus::Absent(
                "no calculation receipts — dpp-calc invocation is not yet wired (licensed \
                 factor data pending)"
                    .into(),
            )
        } else {
            CheckStatus::Fail(
                "calc receipts present but this verifier build does not yet check them".into(),
            )
        },
    });

    // 9. Component graph (BOM) — the embedded recursive tree-verification report.
    //    Tamper-evidence for the report itself comes from `content_integrity`
    //    above; this check grades its verdict, distinguishing a real integrity
    //    violation (Fail) from a node that merely couldn't be reached or fully
    //    walked at snapshot time (Absent — incomplete, not tampered).
    checks.push(CheckResult {
        name: "component_graph".into(),
        status: match &dossier.component_graph {
            None => CheckStatus::Absent("no component graph on this passport".into()),
            Some(report) => component_graph_status(report),
        },
    });

    VerificationReport {
        trust_anchor_note: format!(
            "trust anchored to the dossier's embedded DID-document snapshot dated {}",
            dossier.manifest.created_at
        ),
        checks,
    }
}

/// Grade an embedded component-tree report. A real integrity violation
/// (tamper / cycle / malformed ref) **fails**, with the path to the break. A
/// node that was only unreachable, not-yet-published, or beyond the walk's
/// bounds at snapshot time is reported as **incomplete** (Absent), not failed —
/// so a dossier is never invalidated merely because a component was offline when
/// it was assembled.
fn component_graph_status(report: &serde_json::Value) -> CheckStatus {
    const TAMPER: [&str; 3] = ["hashMismatch", "cycle", "malformedRef"];

    let unverified: Vec<&serde_json::Value> = report
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|n| n.get("verified").and_then(serde_json::Value::as_bool) == Some(false))
        .collect();

    if unverified.is_empty() {
        return CheckStatus::Pass;
    }
    if let Some(bad) = unverified.iter().find(|n| {
        n.get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| TAMPER.contains(&r))
    }) {
        let path = bad
            .get("path")
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "unknown".into());
        return CheckStatus::Fail(format!("component tree integrity violation at {path}"));
    }
    CheckStatus::Absent(format!(
        "{} component(s) could not be verified at snapshot time (unreachable or beyond walk bounds)",
        unverified.len()
    ))
}

/// Parse raw dossier bytes and verify them — the entry point the verify
/// endpoints use.
///
/// Two distinct failure modes:
/// - Malformed JSON, a missing required field, or an unrecognised field
///   anywhere in a strict (`deny_unknown_fields`) type — returns `Err`
///   before any check runs (exit 2). An unrecognised field is treated the
///   same as malformed input on purpose: it may mean this dossier was
///   produced by a newer format version this verifier doesn't know about,
///   and silently ignoring unknown content is exactly what a verifier must
///   never do.
/// - A recognised, well-formed dossier that fails one or more checks —
///   returns `Ok(report)` with `report.all_verified() == false` (exit 1),
///   including a possible `input_fidelity` failure: an unknown field nested
///   inside a *tolerant* type (e.g. a `TransferRecord`, a core `dpp-domain`
///   type this module doesn't make strict) parses fine but is silently
///   dropped by serde — `deny_unknown_fields` on our own types can't catch
///   that, so `input_fidelity` recomputes the canonical bytes of what was
///   *actually parsed* and compares them against the canonical bytes of what
///   was *received*. Any content lost in between fails this check.
///
/// # Errors
/// [`DossierParseError`] — see above.
pub fn verify_dossier_json(bytes: &[u8]) -> Result<VerificationReport, DossierParseError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)?;
    let dossier: DossierV1 = serde_json::from_value(raw.clone())?;

    let mut report = verify_dossier(&dossier);
    report.checks.push(input_fidelity_check(&raw, &dossier));
    Ok(report)
}

/// `JCS(raw) == JCS(reserialize(parse(raw)))` — catches content silently
/// dropped anywhere in the tree, including inside tolerant nested types
/// `deny_unknown_fields` doesn't reach. See `verify_dossier_json`'s doc for
/// the full rationale.
fn input_fidelity_check(raw: &serde_json::Value, parsed: &DossierV1) -> CheckResult {
    let status = (|| -> Result<CheckStatus, String> {
        let raw_bytes =
            dpp_crypto::jws::canonicalize(raw).map_err(|e| format!("canonicalising input: {e}"))?;
        let reparsed_value = serde_json::to_value(parsed)
            .map_err(|e| format!("reserialising parsed dossier: {e}"))?;
        let reparsed_bytes = dpp_crypto::jws::canonicalize(&reparsed_value)
            .map_err(|e| format!("canonicalising reserialised dossier: {e}"))?;
        if reparsed_bytes == raw_bytes {
            Ok(CheckStatus::Pass)
        } else {
            Ok(CheckStatus::Fail(
                "dossier content changed after parsing — a field was likely dropped silently \
                 (e.g. an unknown field nested inside a tolerant type such as a transfer record)"
                    .into(),
            ))
        }
    })()
    .unwrap_or_else(CheckStatus::Fail);

    CheckResult {
        name: "input_fidelity".into(),
        status,
    }
}

fn layer_check(
    name: &'static str,
    issuer_key: &Option<String>,
    issuer_did: &str,
    jws: &str,
    payload: &serde_json::Value,
) -> CheckResult {
    let status = match issuer_key {
        None => CheckStatus::Fail(format!("no DID document available for issuer {issuer_did}")),
        Some(key) => match verify_jws_content(jws, key, payload) {
            Ok(true) => CheckStatus::Pass,
            Ok(false) => CheckStatus::Fail(
                "signature invalid, or covers different content than this payload".into(),
            ),
            Err(e) => CheckStatus::Fail(format!("malformed signature: {e}")),
        },
    };
    CheckResult {
        name: name.into(),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use dpp_crypto::jws::canonicalize;
    use dpp_types::audit::AuditEntry;
    use dpp_types::evidence::{DossierManifest, SignedLayer};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn did_doc_for(signing_key: &SigningKey) -> serde_json::Value {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let x = b64.encode(signing_key.verifying_key().to_bytes());
        serde_json::json!({
            "verificationMethod": [{
                "id": "did:web:node.example#root",
                "type": "JsonWebKey2020",
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
            }],
            "assertionMethod": ["did:web:node.example#root"],
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

    fn genesis_entry(action: &str) -> AuditEntry {
        AuditEntry {
            id: Uuid::now_v7(),
            passport_id: "p1".into(),
            actor: "actor".into(),
            action: action.into(),
            previous_status: None,
            new_status: None,
            metadata: None,
            timestamp: Utc::now(),
            prev_hash: None,
            entry_hash: None,
        }
    }

    fn chain_entries(mut entries: Vec<AuditEntry>) -> Vec<AuditEntry> {
        let mut prev = String::new();
        for e in &mut entries {
            let h = e.chain_hash(&prev);
            e.prev_hash = Some(prev.clone());
            e.entry_hash = Some(h.clone());
            prev = h;
        }
        entries
    }

    fn valid_dossier(signing_key: &SigningKey) -> DossierV1 {
        let full_payload = serde_json::json!({"passportId": "p1", "status": "active"});
        let public_payload = serde_json::json!({"passportId": "p1"});
        let audit_entries =
            chain_entries(vec![genesis_entry("created"), genesis_entry("published")]);

        let mut dossier = DossierV1 {
            manifest: DossierManifest {
                format_version: "1".into(),
                passport_id: "p1".into(),
                issuer_did: "did:web:node.example".into(),
                created_at: Utc::now(),
                node_version: "test".into(),
                ruleset_version: None,
                content_hashes: BTreeMap::new(),
            },
            manifest_jws: String::new(),
            full_view: SignedLayer {
                payload: full_payload.clone(),
                jws: sign(signing_key, &full_payload),
            },
            public_view: SignedLayer {
                payload: public_payload.clone(),
                jws: sign(signing_key, &public_payload),
            },
            did_documents: BTreeMap::from([(
                "did:web:node.example".to_string(),
                did_doc_for(signing_key),
            )]),
            audit_entries,
            transfer_chain: None,
            eol_event: None,
            checkpoint: None,
            calc_receipts: Vec::new(),
            component_graph: None,
        };

        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign(signing_key, &manifest_value);
        dossier
    }

    fn by_name<'a>(report: &'a VerificationReport, n: &str) -> &'a CheckStatus {
        &report.checks.iter().find(|c| c.name == n).unwrap().status
    }

    #[test]
    fn clean_dossier_verifies_fully() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = valid_dossier(&signing_key);
        let report = verify_dossier(&dossier);
        assert!(report.all_verified(), "{report:?}");
        assert_eq!(report.exit_code(), 0);
    }

    /// Attach an attested component-graph report and re-bind + re-sign the
    /// manifest so it is covered by `content_hashes`.
    fn with_graph(signing_key: &SigningKey, graph: serde_json::Value) -> DossierV1 {
        let mut dossier = valid_dossier(signing_key);
        dossier.component_graph = Some(graph);
        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign(signing_key, &manifest_value);
        dossier
    }

    #[test]
    fn attested_component_graph_passes_when_report_is_verified() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = with_graph(
            &signing_key,
            serde_json::json!({ "verified": true, "nodes": [] }),
        );
        let report = verify_dossier(&dossier);
        assert_eq!(*by_name(&report, "component_graph"), CheckStatus::Pass);
        assert_eq!(*by_name(&report, "content_integrity"), CheckStatus::Pass);
        assert!(report.all_verified());
    }

    #[test]
    fn attested_component_graph_fails_when_report_shows_a_broken_node() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = with_graph(
            &signing_key,
            serde_json::json!({
                "verified": false,
                "nodes": [{ "path": ["u://leaf"], "verified": false, "reason": "hashMismatch" }]
            }),
        );
        let report = verify_dossier(&dossier);
        assert!(matches!(
            by_name(&report, "component_graph"),
            CheckStatus::Fail(_)
        ));
        // The report honestly reports a break; the dossier member itself is intact.
        assert_eq!(*by_name(&report, "content_integrity"), CheckStatus::Pass);
    }

    #[test]
    fn unreachable_component_is_incomplete_not_a_dossier_failure() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = with_graph(
            &signing_key,
            serde_json::json!({
                "verified": false,
                "nodes": [{ "path": ["u://remote"], "verified": false, "reason": "unreachable" }]
            }),
        );
        let report = verify_dossier(&dossier);
        // Unreachable-at-snapshot is incomplete, not tampered.
        assert!(matches!(
            by_name(&report, "component_graph"),
            CheckStatus::Absent(_)
        ));
        // And it must not drag the whole dossier to failed.
        assert!(report.all_verified());
    }

    #[test]
    fn tampering_the_attested_graph_flips_content_integrity() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = with_graph(
            &signing_key,
            serde_json::json!({ "verified": true, "nodes": [] }),
        );
        // Alter the attested report without re-signing the manifest.
        dossier.component_graph = Some(serde_json::json!({ "verified": false, "nodes": [] }));
        let report = verify_dossier(&dossier);
        assert!(matches!(
            by_name(&report, "content_integrity"),
            CheckStatus::Fail(_)
        ));
    }

    #[test]
    fn tampered_full_view_payload_flips_only_that_check() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        dossier.full_view.payload["status"] = serde_json::json!("draft"); // tamper, jws not re-signed
        let report = verify_dossier(&dossier);

        assert!(matches!(
            by_name(&report, "full_view_signature"),
            CheckStatus::Fail(_)
        ));
        assert!(matches!(
            by_name(&report, "content_integrity"),
            CheckStatus::Fail(_)
        ));
        // Unrelated checks stay green.
        assert_eq!(
            *by_name(&report, "public_view_signature"),
            CheckStatus::Pass
        );
        assert_eq!(*by_name(&report, "audit_chain"), CheckStatus::Pass);
    }

    #[test]
    fn tampered_jws_flips_only_that_signature_check() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        dossier.public_view.jws = format!("{}x", dossier.public_view.jws);
        let report = verify_dossier(&dossier);

        assert!(matches!(
            by_name(&report, "public_view_signature"),
            CheckStatus::Fail(_)
        ));
        assert_eq!(*by_name(&report, "full_view_signature"), CheckStatus::Pass);
    }

    #[test]
    fn tampered_audit_row_flips_only_audit_chain() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        dossier.audit_entries[0].action = "tampered".into();
        // Re-derive content_hashes/manifest_jws to isolate the audit-chain
        // check specifically (otherwise content_integrity also flips, which
        // is correct but not what this test is isolating).
        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign(&signing_key, &manifest_value);

        let report = verify_dossier(&dossier);
        assert!(matches!(
            by_name(&report, "audit_chain"),
            CheckStatus::Fail(_)
        ));
        assert_eq!(*by_name(&report, "full_view_signature"), CheckStatus::Pass);
        assert_eq!(*by_name(&report, "manifest_signature"), CheckStatus::Pass);
    }

    #[test]
    fn absent_checkpoint_and_receipts_are_informational_not_failures() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = valid_dossier(&signing_key);
        let report = verify_dossier(&dossier);
        assert!(matches!(
            by_name(&report, "checkpoint"),
            CheckStatus::Absent(_)
        ));
        assert!(matches!(
            by_name(&report, "calc_receipts"),
            CheckStatus::Absent(_)
        ));
        assert!(report.all_verified());
    }

    #[test]
    fn tampered_transfer_signature_flips_only_transfer_chain() {
        use dpp_domain::domain::passport::PassportId;
        use dpp_domain::domain::transfer::{
            OperatorRole, ResponsibleOperator, TransferChain, TransferReason, TransferRecord,
        };

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let from_key = SigningKey::from_bytes(&[3u8; 32]);
        let to_key = SigningKey::from_bytes(&[4u8; 32]);
        let mut dossier = valid_dossier(&signing_key);

        let operator = |did: &str| ResponsibleOperator {
            did: did.to_owned(),
            name: "Acme".into(),
            role: OperatorRole::Distributor,
            eu_operator_id: None,
            country: "DE".into(),
        };
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
        record.to_signature = Some(sign(&to_key, &payload));

        dossier.transfer_chain = Some(TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        });
        dossier
            .did_documents
            .insert("did:web:from.example".to_string(), did_doc_for(&from_key));
        dossier
            .did_documents
            .insert("did:web:to.example".to_string(), did_doc_for(&to_key));
        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign(&signing_key, &manifest_value);

        // Sanity: clean chain verifies before we tamper it.
        let clean_report = verify_dossier(&dossier);
        assert!(clean_report.all_verified(), "{clean_report:?}");

        // Tamper the to_signature, then re-sign the manifest so only the
        // transfer-chain check (not content_integrity) is isolated.
        if let Some(chain) = &mut dossier.transfer_chain {
            chain.transfers[0].to_signature = chain.transfers[0]
                .to_signature
                .clone()
                .map(|s| format!("{s}x"));
        }
        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign(&signing_key, &manifest_value);

        let report = verify_dossier(&dossier);
        assert!(matches!(
            by_name(&report, "transfer_chain"),
            CheckStatus::Fail(_)
        ));
        assert_eq!(*by_name(&report, "full_view_signature"), CheckStatus::Pass);
        assert_eq!(*by_name(&report, "audit_chain"), CheckStatus::Pass);
    }

    // ── verify_dossier_json / strictness / fidelity ────────────────────────

    fn valid_dossier_bytes() -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = valid_dossier(&signing_key);
        serde_json::to_vec(&dossier).unwrap()
    }

    #[test]
    fn clean_json_round_trips_through_verify_dossier_json() {
        let bytes = valid_dossier_bytes();
        let report = verify_dossier_json(&bytes).expect("parses");
        assert!(report.all_verified(), "{report:?}");
        assert_eq!(*by_name(&report, "input_fidelity"), CheckStatus::Pass);
    }

    #[test]
    fn unknown_top_level_field_is_a_parse_error() {
        let bytes = valid_dossier_bytes();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["notARealField"] = serde_json::json!("sneaky");
        let bytes = serde_json::to_vec(&value).unwrap();

        let err = verify_dossier_json(&bytes)
            .expect_err("unknown field must be a hard parse error, not a report");
        assert!(matches!(err, DossierParseError::Json(_)));
    }

    #[test]
    fn unknown_field_nested_in_a_tolerant_type_fails_input_fidelity() {
        // TransferRecord (a dpp-domain type) is not `deny_unknown_fields` —
        // an unknown field inside it parses fine and is silently dropped by
        // serde. `deny_unknown_fields` on our own types can't catch this;
        // `input_fidelity` must.
        use dpp_domain::domain::passport::PassportId;
        use dpp_domain::domain::transfer::{
            OperatorRole, ResponsibleOperator, TransferChain, TransferReason, TransferRecord,
        };

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        let operator = |did: &str| ResponsibleOperator {
            did: did.to_owned(),
            name: "Acme".into(),
            role: OperatorRole::Distributor,
            eu_operator_id: None,
            country: "DE".into(),
        };
        let record = TransferRecord {
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
        dossier.transfer_chain = Some(TransferChain {
            passport_id: record.passport_id,
            original_operator: operator("did:web:from.example"),
            transfers: vec![record],
        });
        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign(&signing_key, &manifest_value);

        let mut value = serde_json::to_value(&dossier).unwrap();
        value["transferChain"]["transfers"][0]["certificationStatus"] =
            serde_json::json!("approved");
        let bytes = serde_json::to_vec(&value).unwrap();

        let report = verify_dossier_json(&bytes)
            .expect("TransferRecord tolerates unknown fields, so this must parse");
        assert!(matches!(
            by_name(&report, "input_fidelity"),
            CheckStatus::Fail(_)
        ));
        assert!(!report.all_verified());
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let err = verify_dossier_json(b"not json").unwrap_err();
        assert!(matches!(err, DossierParseError::Json(_)));
    }

    use proptest::prelude::*;

    proptest! {
        /// Dossier verification parses attacker-supplied uploads — whatever bytes
        /// it is handed, it must return Ok/Err and never panic.
        #[test]
        fn verify_dossier_json_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            let _ = verify_dossier_json(&bytes);
        }
    }
}
