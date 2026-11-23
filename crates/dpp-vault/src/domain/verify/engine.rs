//! The verification engine: runs every check independently against a
//! [`DossierV1`] and produces a [`VerificationReport`] — a single tamper
//! flips exactly one named check, never cascades into unrelated failures.

use dpp_domain::transfer::TransferChain;
use dpp_types::audit::verify_audit_chain;
use dpp_types::evidence::{
    CheckResult, CheckStatus, DossierV1, VerificationReport, compute_content_hashes, content_hash,
};
use dpp_types::transfer::core_refusal_message;
use serde::Deserialize;

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
pub fn verify_dossier(
    dossier: &DossierV1,
    seals: Option<&dyn dpp_types::SealInspector>,
) -> VerificationReport {
    verify_members(dossier, None, seals)
}

/// A `transferChain` member that dpp-core refuses to read, so a dossier could
/// not hold it as a typed chain.
struct RefusedChainMember<'a> {
    /// The member as the document carries it.
    raw: &'a serde_json::Value,
    /// Core's refusal, naming the passport and the record it cited.
    refusal: String,
}

/// [`verify_dossier`], for a dossier read without its `transferChain` member
/// because dpp-core refuses that member (`refused`).
///
/// The member is checked as the document carries it: its hash is compared with
/// the one the manifest commits to, and the transfer-chain check fails with
/// core's refusal. Every other check reads the rest of the dossier as usual.
fn verify_members(
    dossier: &DossierV1,
    refused: Option<&RefusedChainMember<'_>>,
    seals: Option<&dyn dpp_types::SealInspector>,
) -> VerificationReport {
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
        status: match compute_content_hashes(dossier).and_then(|mut hashes| {
            if let Some(member) = refused {
                hashes.insert("transferChain".to_owned(), content_hash(member.raw)?);
            }
            Ok(hashes)
        }) {
            // A dossier whose members cannot be canonicalised cannot be
            // attested at all — fail the check rather than abort the verifier.
            Err(e) => CheckStatus::Fail(format!("cannot canonicalise dossier members: {e}")),
            Ok(recomputed) if recomputed == dossier.manifest.content_hashes => CheckStatus::Pass,
            Ok(recomputed) => {
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
        status: match (&dossier.transfer_chain, refused) {
            (_, Some(member)) => CheckStatus::Fail(format!(
                "the transfer chain is refused by dpp-core: {}",
                member.refusal
            )),
            (None, None) => CheckStatus::Absent("no transfer chain on this passport".into()),
            (Some(chain), None) => match verify_transfer_chain(
                chain,
                &dossier.did_documents,
                &dossier.manifest.issuer_did,
            ) {
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

    // 8. The seal covers the signature served beside it.
    //
    // A dossier is self-contained by design: it carries the CAdES *and* the
    // compact JWS it should be checked against, so this needs no database, no
    // node and no network — which is the point, since whoever opens the file is
    // typically neither of the first two.
    //
    // Note what is **not** trusted: the dossier's own `payloadHash`, nor the
    // `binding` the generator wrote into it. Both are recomputed here from
    // `signedOverJws`. The generator's claim is evidence of what it believed;
    // this check exists to say whether it was right.
    checks.push(CheckResult {
        name: "qualified_seal".into(),
        status: qualified_seal_status(dossier, seals),
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
/// Whether the dossier's seal covers the signature the dossier serves with it.
///
/// `Absent` rather than `Fail` wherever the question could not be put: a
/// passport with no seal, a caller that supplied no inspector, or bytes this
/// build cannot read. None of those is a finding about the seal, and a dossier
/// marked failed because nobody looked would be worse than one marked unchecked.
fn qualified_seal_status(
    dossier: &DossierV1,
    seals: Option<&dyn dpp_types::SealInspector>,
) -> CheckStatus {
    let Some(section) = &dossier.qualified_seal else {
        return CheckStatus::Absent("this passport carries no qualified seal".into());
    };
    let Some(seals) = seals else {
        return CheckStatus::Absent(
            "no seal reader was supplied, so the seal was not opened".into(),
        );
    };

    let envelope: dpp_domain::seal::SealedEnvelope =
        match serde_json::from_value(section.get("seal").cloned().unwrap_or_default()) {
            Ok(e) => e,
            Err(e) => return CheckStatus::Fail(format!("the seal member is malformed: {e}")),
        };
    let Some(jws) = section.get("signedOverJws").and_then(|v| v.as_str()) else {
        return CheckStatus::Fail(
            "the seal is served without the signature it should cover".into(),
        );
    };

    // The seal section names a signature of its own, and that name is only as
    // trustworthy as the dossier that carries it. The seal must cover the full
    // view this dossier verifies, so the digest is taken from that view and the
    // section's name for it is checked against it.
    if jws != dossier.full_view.jws {
        return CheckStatus::Fail(
            "the seal covers a signature other than the full view this dossier carries".into(),
        );
    }
    // Recomputed, never read off the dossier: a `payloadHash` taken on trust
    // would let an edited one make a mismatched seal look sound.
    let expected = dpp_types::digest_for_jws(&dossier.full_view.jws);

    match seals.binding(&envelope, &expected) {
        dpp_types::SealBinding::CoversThisSignature => {
            // The signature holds. Whether the certificate behind it did is a
            // separate question, and passing without asking it would put a
            // `Pass` on a dossier whose seal was made under a certificate its CA
            // had already revoked — the one reader of this file who cannot
            // check that for themselves is the one it is written for.
            //
            // Recomputed from the envelope rather than read from the dossier's
            // own `certificate` member: a stored finding is the generator's
            // word, and this check exists to be independent of it.
            let certificate = seals.certificate_standing(&envelope, chrono::Utc::now());
            let status = dpp_types::SealValidationStatus::of(
                &dpp_types::SealBinding::CoversThisSignature,
                certificate.as_ref(),
            );
            match status.indication {
                dpp_types::ValidationIndication::TotalFailed => CheckStatus::Fail(format!(
                    "the seal covers this signature, and its certificate was not valid when the                      seal was made ({:?}) — ETSI EN 319 102-1 reports this as TOTAL-FAILED, and                      re-sealing would not help: the replacement would come from the same                      certificate",
                    status.sub_indication
                )),
                // Everything this node checks, checked. Not a statement that the
                // seal is qualified: no chain was validated to a trust anchor,
                // which is what `TOTAL-PASSED` would need.
                dpp_types::ValidationIndication::Indeterminate => CheckStatus::Pass,
            }
        }
        dpp_types::SealBinding::CoversAnotherDigest { covered } => CheckStatus::Fail(format!(
            "the seal covers {covered}, not the signature served with it ({expected}) — the \
             passport was most likely re-published after sealing"
        )),
        dpp_types::SealBinding::NotIntact => CheckStatus::Fail(
            "the signature over the seal's own attributes does not verify, so nothing it says \
             about what it covers can be relied on"
                .into(),
        ),
        dpp_types::SealBinding::Unknown => CheckStatus::Absent(
            "the seal could not be read — a placeholder, or a format this build does not parse"
                .into(),
        ),
    }
}

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
            .map(ToString::to_string)
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
/// - A `transferChain` member that dpp-core refuses to read (a record for
///   another passport, a broken operator sequence, a completion without both
///   signatures, ...) is neither of the above: it returns `Ok(report)` with the
///   `transfer_chain` check failed, naming the passport and the record core
///   cited, and every other check run on the rest of the dossier. The member is
///   hashed as the document carries it, so `content_integrity` still attests it
///   against the manifest, and `input_fidelity` covers the rest of the
///   document. A document that fails to parse for any other reason keeps its
///   error, whether or not its chain is refused.
///
/// # Errors
/// [`DossierParseError`] — see above.
pub fn verify_dossier_json(
    bytes: &[u8],
    seals: Option<&dyn dpp_types::SealInspector>,
) -> Result<VerificationReport, DossierParseError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)?;
    // Parsed a second time directly from `bytes` rather than `raw.clone()` —
    // cheaper than deep-cloning an already-parsed `Value` tree, and this
    // function runs on every dossier verify (both stored and uploaded).
    let dossier: DossierV1 = match serde_json::from_slice(bytes) {
        Ok(dossier) => dossier,
        Err(error) => return verify_with_refused_chain(bytes, raw, seals, error),
    };

    let mut report = verify_dossier(&dossier, seals);
    report.checks.push(input_fidelity_check(&raw, &dossier));
    Ok(report)
}

/// Verify a document that did not parse as a dossier, if the only thing in the
/// way is a `transferChain` member that dpp-core refuses to read.
///
/// That is a dossier whose transfer-chain check fails, not one that cannot be
/// read. Four things must hold: `error`, the failure of the whole parse, is
/// itself core's refusal of a chain (so a document that fails for another reason,
/// such as a duplicated key ahead of the chain, keeps its error); no object in
/// `bytes` holds a key twice; the member alone is refused by core; and the
/// document without that member parses. Otherwise the duplicate's error, or
/// `error`, is returned. `raw` is taken apart rather than copied.
fn verify_with_refused_chain(
    bytes: &[u8],
    mut raw: serde_json::Value,
    seals: Option<&dyn dpp_types::SealInspector>,
    error: serde_json::Error,
) -> Result<VerificationReport, DossierParseError> {
    if core_refusal_message(&error).is_none() {
        return Err(error.into());
    }
    // The parse that failed stopped at the chain, so no key after it was checked
    // for a duplicate, and `raw` kept the last of any two. The document is read
    // again for that alone.
    serde_json::from_slice::<UniqueKeys>(bytes)?;
    let Some(chain) = raw
        .as_object_mut()
        .and_then(|members| members.remove("transferChain"))
    else {
        return Err(error.into());
    };
    let refusal = TransferChain::deserialize(&chain)
        .err()
        .and_then(|e| core_refusal_message(&e));
    let (Some(refusal), Ok(dossier)) = (refusal, DossierV1::deserialize(&raw)) else {
        return Err(error.into());
    };

    let member = RefusedChainMember {
        raw: &chain,
        refusal,
    };
    let mut report = verify_members(&dossier, Some(&member), seals);
    report.checks.push(input_fidelity_check(&raw, &dossier));
    Ok(report)
}

/// A JSON document in which no object holds the same key twice, at any depth.
/// Only that is read: the values are discarded.
struct UniqueKeys;

impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueKeysVisitor)
    }
}

struct UniqueKeysVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueKeysVisitor {
    type Value = UniqueKeys;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueKeys, A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(UniqueKeys)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<UniqueKeys, A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.contains(&key) {
                return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
            }
            map.next_value::<UniqueKeys>()?;
            seen.insert(key);
        }
        Ok(UniqueKeys)
    }
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
    use super::super::transfer_chain::acceptance_payload;
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use dpp_crypto::jws::canonicalize;
    use dpp_types::audit::PassportAuditEntry;
    use dpp_types::evidence::{DossierManifest, SignedLayer};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    /// The document `did` publishes: one method, `{did}#root`, controlled by it.
    fn did_doc_for(did: &str, signing_key: &SigningKey) -> serde_json::Value {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let x = b64.encode(signing_key.verifying_key().to_bytes());
        serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#root"),
                "type": "JsonWebKey",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
            }],
            "assertionMethod": [format!("{did}#root")],
        })
    }

    /// A signature by `did`'s key, naming it by the absolute URL of its method.
    fn sign(did: &str, signing_key: &SigningKey, payload: &serde_json::Value) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(
            serde_json::to_vec(&serde_json::json!({"alg": "EdDSA", "kid": format!("{did}#root")}))
                .unwrap(),
        );
        let body = b64.encode(canonicalize(payload).unwrap());
        let signing_input = format!("{header}.{body}");
        let sig = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64.encode(sig.to_bytes()))
    }

    fn genesis_entry(action: &str) -> PassportAuditEntry {
        PassportAuditEntry {
            id: Uuid::now_v7(),
            passport_id: "p1".into(),
            actor: "actor".into(),
            action: action.into(),
            previous_status: None,
            new_status: None,
            metadata: None,
            timestamp: Utc::now(),
            request_id: None,
            prev_hash: None,
            entry_hash: None,
        }
    }

    fn chain_entries(mut entries: Vec<PassportAuditEntry>) -> Vec<PassportAuditEntry> {
        let mut prev = String::new();
        for e in &mut entries {
            let h = e.chain_hash(&prev).expect("test entry hashes");
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
                core_version: "test".into(),
                ruleset_version: None,
                content_hashes: BTreeMap::new(),
            },
            manifest_jws: String::new(),
            full_view: SignedLayer {
                payload: full_payload.clone(),
                jws: sign("did:web:node.example", signing_key, &full_payload),
            },
            public_view: SignedLayer {
                payload: public_payload.clone(),
                jws: sign("did:web:node.example", signing_key, &public_payload),
            },
            did_documents: BTreeMap::from([(
                "did:web:node.example".to_string(),
                did_doc_for("did:web:node.example", signing_key),
            )]),
            audit_entries,
            transfer_chain: None,
            eol_event: None,
            checkpoint: None,
            calc_receipts: Vec::new(),
            component_graph: None,
            qualified_seal: None,
        };

        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", signing_key, &manifest_value);
        dossier
    }

    fn by_name<'a>(report: &'a VerificationReport, n: &str) -> &'a CheckStatus {
        &report.checks.iter().find(|c| c.name == n).unwrap().status
    }

    #[test]
    fn clean_dossier_verifies_fully() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = valid_dossier(&signing_key);
        let report = verify_dossier(&dossier, None);
        assert!(report.all_verified(), "{report:?}");
        assert_eq!(report.exit_code(), 0);
    }

    /// Attach an attested component-graph report and re-bind + re-sign the
    /// manifest so it is covered by `content_hashes`.
    fn with_graph(signing_key: &SigningKey, graph: serde_json::Value) -> DossierV1 {
        let mut dossier = valid_dossier(signing_key);
        dossier.component_graph = Some(graph);
        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", signing_key, &manifest_value);
        dossier
    }

    #[test]
    fn attested_component_graph_passes_when_report_is_verified() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let dossier = with_graph(
            &signing_key,
            serde_json::json!({ "verified": true, "nodes": [] }),
        );
        let report = verify_dossier(&dossier, None);
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
        let report = verify_dossier(&dossier, None);
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
        let report = verify_dossier(&dossier, None);
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
        let report = verify_dossier(&dossier, None);
        assert!(matches!(
            by_name(&report, "content_integrity"),
            CheckStatus::Fail(_)
        ));
    }

    /// The qualified seal is the one dossier member carrying an eIDAS Art. 35(2)
    /// presumption, so swapping it for another seal must be as detectable as
    /// swapping any other member.
    #[test]
    fn tampering_the_qualified_seal_flips_content_integrity() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        dossier.qualified_seal = Some(serde_json::json!({
            "seal": { "format": "CADES", "sealValue": "p7s-original" },
            "signedOverJws": "a.b.c",
            "payloadHash": "ab".repeat(32),
        }));
        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", &signing_key, &manifest_value);
        assert_eq!(
            *by_name(&verify_dossier(&dossier, None), "content_integrity"),
            CheckStatus::Pass
        );

        // Substitute a different seal without re-signing the manifest.
        dossier.qualified_seal = Some(serde_json::json!({
            "seal": { "format": "CADES", "sealValue": "p7s-substituted" },
            "signedOverJws": "a.b.c",
            "payloadHash": "ab".repeat(32),
        }));
        assert!(matches!(
            by_name(&verify_dossier(&dossier, None), "content_integrity"),
            CheckStatus::Fail(_)
        ));
    }

    /// An inspector that would accept any seal it is shown. With it in place, the
    /// only thing that can fail the seal check is the dossier's own claim about
    /// which signature the seal covers.
    struct AcceptingInspector;

    impl dpp_types::SealInspector for AcceptingInspector {
        fn origin(
            &self,
            _envelope: &dpp_domain::seal::SealedEnvelope,
        ) -> Option<dpp_types::SealOrigin> {
            None
        }
        fn binding(
            &self,
            _envelope: &dpp_domain::seal::SealedEnvelope,
            _payload_hash: &str,
        ) -> dpp_types::SealBinding {
            dpp_types::SealBinding::CoversThisSignature
        }
        fn evidenced_level(
            &self,
            _envelope: &dpp_domain::seal::SealedEnvelope,
        ) -> Option<dpp_domain::seal::SealConformanceLevel> {
            None
        }
        fn attested_sealing_time(
            &self,
            _envelope: &dpp_domain::seal::SealedEnvelope,
        ) -> Option<chrono::DateTime<Utc>> {
            None
        }
        fn archival_freshness(
            &self,
            _envelope: &dpp_domain::seal::SealedEnvelope,
            _now: chrono::DateTime<Utc>,
        ) -> dpp_types::ArchivalFreshness {
            dpp_types::ArchivalFreshness::NotArchived
        }
        fn certificate_standing(
            &self,
            _envelope: &dpp_domain::seal::SealedEnvelope,
            _now: chrono::DateTime<Utc>,
        ) -> Option<dpp_types::CertificateStanding> {
            None
        }
    }

    /// A seal must cover the full view this dossier carries. The section names the
    /// signature it covers, but that name is only as good as the dossier, so a seal
    /// naming another signature fails even under an inspector that accepts it.
    #[test]
    fn a_seal_naming_a_signature_other_than_the_full_view_fails() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        dossier.qualified_seal = Some(serde_json::json!({
            "seal": {
                "format": "CADES",
                "sealValue": "p7s",
                "sealedAt": "2026-11-12T00:00:00Z",
                "placeholder": false,
            },
            "signedOverJws": "another.signature.entirely",
            "payloadHash": "ab".repeat(32),
        }));
        assert_ne!(dossier.full_view.jws, "another.signature.entirely");
        let report = verify_dossier(&dossier, Some(&AcceptingInspector));
        assert!(
            matches!(
                by_name(&report, "qualified_seal"),
                CheckStatus::Fail(reason) if reason.contains("other than the full view")
            ),
            "{:?}",
            by_name(&report, "qualified_seal")
        );
    }

    #[test]
    fn tampered_full_view_payload_flips_only_that_check() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        dossier.full_view.payload["status"] = serde_json::json!("draft"); // tamper, jws not re-signed
        let report = verify_dossier(&dossier, None);

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
        let report = verify_dossier(&dossier, None);

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
        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", &signing_key, &manifest_value);

        let report = verify_dossier(&dossier, None);
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
        let report = verify_dossier(&dossier, None);
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
        use dpp_domain::operator::{OperatorRole, ResponsibleOperator};
        use dpp_domain::passport::PassportId;
        use dpp_domain::transfer::{TransferChain, TransferReason, TransferRecord};

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let from_key = SigningKey::from_bytes(&[3u8; 32]);
        let to_key = SigningKey::from_bytes(&[4u8; 32]);
        let mut dossier = valid_dossier(&signing_key);

        let operator = |did: &str| ResponsibleOperator {
            did: did.to_owned(),
            name: "Acme".into(),
            role: OperatorRole::Distributor,
            eu_operator_id: None,
            eu_operator_id_scheme: None,
            registered_trade_name: None,
            postal_address: None,
            electronic_address: None,
            country: "DE".into(),
            identifier: None,
        };
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
        record.from_signature = Some(sign("did:web:from.example", &from_key, &payload));
        // Signed by the dossier's *issuer* — the hosting node — over the
        // acceptance payload, which is what the verifier now checks it against.
        // Signing it with `to_key` over the initiation payload, as this once
        // did, is the shape that made the attestation indistinguishable from a
        // copy of `from_signature`.
        record.node_acceptance_attestation = Some(sign(
            "did:web:node.example",
            &signing_key,
            &acceptance_payload(&record),
        ));

        let mut chain = TransferChain::new(record.passport_id, operator("did:web:from.example"));
        chain
            .initiate_transfer(record)
            .expect("a completed, fully signed transfer from the original operator");
        dossier.transfer_chain = Some(chain);
        dossier.did_documents.insert(
            "did:web:from.example".to_string(),
            did_doc_for("did:web:from.example", &from_key),
        );
        dossier.did_documents.insert(
            "did:web:to.example".to_string(),
            did_doc_for("did:web:to.example", &to_key),
        );
        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", &signing_key, &manifest_value);

        // Sanity: clean chain verifies before we tamper it.
        let clean_report = verify_dossier(&dossier, None);
        assert!(clean_report.all_verified(), "{clean_report:?}");

        // Tamper the outgoing operator's signature, then re-sign the manifest so
        // only the transfer-chain check (not content_integrity) is isolated.
        //
        // Either signature would now do — both are verified, against different
        // parties — but this stays on `from_signature` so the test keeps
        // isolating the property it was written for: a broken transfer
        // signature flips this check and no other. The acceptance half has its
        // own tamper test in `transfer_chain`.
        // A record in a chain cannot be edited in place, so the tamper goes
        // through the stored form, as a forged dossier would.
        if let Some(chain) = &mut dossier.transfer_chain {
            let mut stored = serde_json::to_value(&*chain).unwrap();
            let signature = &mut stored["transfers"][0]["fromSignature"];
            *signature = serde_json::json!(format!("{}x", signature.as_str().unwrap()));
            *chain = serde_json::from_value(stored).unwrap();
        }
        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", &signing_key, &manifest_value);

        let report = verify_dossier(&dossier, None);
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
        let report = verify_dossier_json(&bytes, None).expect("parses");
        assert!(report.all_verified(), "{report:?}");
        assert_eq!(*by_name(&report, "input_fidelity"), CheckStatus::Pass);
    }

    #[test]
    fn unknown_top_level_field_is_a_parse_error() {
        let bytes = valid_dossier_bytes();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["notARealField"] = serde_json::json!("sneaky");
        let bytes = serde_json::to_vec(&value).unwrap();

        let err = verify_dossier_json(&bytes, None)
            .expect_err("unknown field must be a hard parse error, not a report");
        assert!(matches!(err, DossierParseError::Json(_)));
    }

    #[test]
    fn unknown_field_nested_in_a_tolerant_type_fails_input_fidelity() {
        // TransferRecord (a dpp-domain type) is not `deny_unknown_fields` —
        // an unknown field inside it parses fine and is silently dropped by
        // serde. `deny_unknown_fields` on our own types can't catch this;
        // `input_fidelity` must.
        use dpp_domain::operator::{OperatorRole, ResponsibleOperator};
        use dpp_domain::passport::PassportId;
        use dpp_domain::transfer::{TransferChain, TransferReason, TransferRecord};

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        let operator = |did: &str| ResponsibleOperator {
            did: did.to_owned(),
            name: "Acme".into(),
            role: OperatorRole::Distributor,
            eu_operator_id: None,
            eu_operator_id_scheme: None,
            registered_trade_name: None,
            postal_address: None,
            electronic_address: None,
            country: "DE".into(),
            identifier: None,
        };
        let record = TransferRecord {
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
        let mut chain = TransferChain::new(record.passport_id, operator("did:web:from.example"));
        chain
            .initiate_transfer(record)
            .expect("a completed, fully signed transfer from the original operator");
        dossier.transfer_chain = Some(chain);
        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).expect("test dossier canonicalises");
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", &signing_key, &manifest_value);

        let mut value = serde_json::to_value(&dossier).unwrap();
        value["transferChain"]["transfers"][0]["certificationStatus"] =
            serde_json::json!("approved");
        let bytes = serde_json::to_vec(&value).unwrap();

        let report = verify_dossier_json(&bytes, None)
            .expect("TransferRecord tolerates unknown fields, so this must parse");
        assert!(matches!(
            by_name(&report, "input_fidelity"),
            CheckStatus::Fail(_)
        ));
        assert!(!report.all_verified());
    }

    /// A dossier whose signed manifest commits to a `transferChain` member that
    /// dpp-core refuses to read: a record that says it completed and carries no
    /// signature.
    fn dossier_bytes_with_a_refused_chain(
        tamper_after_signing: bool,
    ) -> (Vec<u8>, serde_json::Value) {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut dossier = valid_dossier(&signing_key);
        let operator = |did: &str| serde_json::json!({ "did": did, "name": "Acme", "role": "distributor", "country": "DE" });
        let passport = "01990000-0000-7000-8000-000000000001";
        let mut chain = serde_json::json!({
            "passportId": passport,
            "originalOperator": operator("did:web:from.example"),
            "transfers": [{
                "transferId": "01990000-0000-7000-8000-0000000000aa",
                "passportId": passport,
                "fromOperator": operator("did:web:from.example"),
                "toOperator": operator("did:web:to.example"),
                "reason": "sale",
                "fromSignature": null,
                "nodeAcceptanceAttestation": null,
                "initiatedAt": "2026-11-01T00:00:00Z",
                "completedAt": "2026-11-02T00:00:00Z",
                "notes": null
            }]
        });
        let mut hashes = compute_content_hashes(&dossier).unwrap();
        hashes.insert("transferChain".into(), content_hash(&chain).unwrap());
        dossier.manifest.content_hashes = hashes;
        let manifest_value = serde_json::to_value(&dossier.manifest).unwrap();
        dossier.manifest_jws = sign("did:web:node.example", &signing_key, &manifest_value);

        if tamper_after_signing {
            chain["transfers"][0]["notes"] = serde_json::json!("changed after signing");
        }
        let mut value = serde_json::to_value(&dossier).unwrap();
        value["transferChain"] = chain.clone();
        (serde_json::to_vec(&value).unwrap(), chain)
    }

    #[test]
    fn a_chain_core_refuses_fails_only_the_transfer_chain_check() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(false);

        let report = verify_dossier_json(&bytes, None)
            .expect("a chain core refuses is a failed check, not an unreadable dossier");

        match by_name(&report, "transfer_chain") {
            CheckStatus::Fail(detail) => assert!(
                detail.contains("01990000-0000-7000-8000-0000000000aa")
                    && detail.contains("01990000-0000-7000-8000-000000000001"),
                "names the passport and the record core cited: {detail}"
            ),
            other => panic!("the transfer-chain check must fail, got {other:?}"),
        }
        let failed: Vec<&str> = report
            .checks
            .iter()
            .filter(|c| c.status.is_failure())
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            failed,
            ["transfer_chain"],
            "every other check is reported as usual: {report:?}"
        );
    }

    #[test]
    fn the_member_core_refuses_is_still_attested_by_the_manifest() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(true);

        let report = verify_dossier_json(&bytes, None).expect("parses");

        assert!(
            matches!(by_name(&report, "content_integrity"), CheckStatus::Fail(d) if d.contains("transferChain")),
            "{report:?}"
        );
    }

    /// `value` as text with every object's keys in reverse order and
    /// whitespace between every token.
    fn reversed_and_spaced(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let members: Vec<String> = map
                    .iter()
                    .rev()
                    .map(|(k, v)| format!("\n  {k:?} :  {}", reversed_and_spaced(v)))
                    .collect();
                format!("{{{}\n}}", members.join(" ,"))
            }
            serde_json::Value::Array(items) => {
                let items: Vec<String> = items.iter().map(reversed_and_spaced).collect();
                format!("[ {} ]", items.join(" , "))
            }
            other => other.to_string(),
        }
    }

    #[test]
    fn a_member_signed_as_the_generator_signs_it_passes_content_integrity_however_it_is_written() {
        let (bytes, chain) = dossier_bytes_with_a_refused_chain(false);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["transferChain"] = serde_json::json!("PLACEHOLDER");
        let text = serde_json::to_string(&value)
            .unwrap()
            .replace("\"PLACEHOLDER\"", &reversed_and_spaced(&chain));
        assert_ne!(
            text.matches("\"transferChain\"").count(),
            0,
            "the member is in the document"
        );

        let report = verify_dossier_json(text.as_bytes(), None).expect("parses");

        assert_eq!(*by_name(&report, "content_integrity"), CheckStatus::Pass);
        assert!(matches!(
            by_name(&report, "transfer_chain"),
            CheckStatus::Fail(_)
        ));
    }

    #[test]
    fn a_member_with_one_unknown_field_more_fails_content_integrity() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(false);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["transferChain"]["notARealField"] = serde_json::json!(1);

        let report = verify_dossier_json(&serde_json::to_vec(&value).unwrap(), None)
            .expect("core's chain tolerates an unknown field, so this is still a refused chain");

        assert!(
            matches!(by_name(&report, "content_integrity"), CheckStatus::Fail(d) if d.contains("transferChain")),
            "{report:?}"
        );
    }

    #[test]
    fn a_refused_chain_does_not_excuse_a_duplicated_key() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(false);
        let text = String::from_utf8(bytes).unwrap();
        // A second `manifestJws` ahead of the real one. A reader that keeps the
        // last of two keys would verify a document whose first value it never saw.
        let text = text.replacen('{', "{\"manifestJws\":\"first\",", 1);

        let err = verify_dossier_json(text.as_bytes(), None)
            .expect_err("a duplicated key is a parse error, whatever the chain is");
        assert!(matches!(err, DossierParseError::Json(_)));
    }

    #[test]
    fn a_refused_chain_does_not_excuse_a_duplicated_key_after_it() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(false);
        let text = String::from_utf8(bytes).unwrap();
        // A second `manifestJws` closing the document, after the chain. The typed
        // parse stops at the refused chain and never reaches it, and a `Value`
        // keeps the last of two keys, so only a read of the bytes can see it.
        let chain_at = text
            .find("\"transferChain\"")
            .expect("the chain is a member");
        let end = text.rfind('}').expect("the document is an object");
        assert!(chain_at < end);
        let text = format!("{},\"manifestJws\":\"last\"}}", &text[..end]);

        let err = verify_dossier_json(text.as_bytes(), None)
            .expect_err("a duplicated key is a parse error, wherever it sits");
        assert!(
            matches!(&err, DossierParseError::Json(e) if e.to_string().contains("duplicate key `manifestJws`")),
            "{err:?}"
        );
    }

    #[test]
    fn a_chain_that_is_malformed_not_refused_is_a_parse_error() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(false);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["transferChain"]
            .as_object_mut()
            .unwrap()
            .remove("transfers");

        let err = verify_dossier_json(&serde_json::to_vec(&value).unwrap(), None)
            .expect_err("a chain with no transfers member is malformed");
        assert!(matches!(err, DossierParseError::Json(_)));
    }

    #[test]
    fn a_refused_chain_does_not_excuse_a_dossier_malformed_elsewhere() {
        let (bytes, _) = dossier_bytes_with_a_refused_chain(false);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["notARealField"] = serde_json::json!("sneaky");

        let err = verify_dossier_json(&serde_json::to_vec(&value).unwrap(), None)
            .expect_err("an unrecognised field is still a parse error");
        assert!(matches!(err, DossierParseError::Json(_)));
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let err = verify_dossier_json(b"not json", None).unwrap_err();
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
            let _ = verify_dossier_json(&bytes, None);
        }
    }
}
