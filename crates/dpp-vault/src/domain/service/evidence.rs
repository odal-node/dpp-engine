//! Evidence dossiers: assemble, generate + persist, list, fetch, and verify
//! a passport's self-contained signed proof snapshot. See `dpp_types::evidence`
//! for the wire format. The audit trail's own wire type
//! (`dpp_types::audit::PassportAuditEntry`) is already the exact type the dossier
//! wants — no mapping step needed.

use std::collections::BTreeMap;

use dpp_domain::{error::DppError, passport::PassportId, status::PassportStatus};
use dpp_types::evidence::{
    DossierManifest, DossierV1, EvidenceDossierRecord, EvidenceDossierSummary, SignedLayer,
    VerificationReport, compute_content_hashes, content_hash,
};
use uuid::Uuid;

use super::PassportService;

impl PassportService {
    /// Generate an evidence dossier for a passport and persist it. Returns
    /// the stored record (id, actor, doc hash, and the dossier itself).
    #[tracing::instrument(skip(self, auth), fields(passport_id = %id))]
    pub async fn generate_evidence(
        &self,
        id: PassportId,
        auth: &dpp_types::auth::AuthContext,
    ) -> Result<EvidenceDossierRecord, DppError> {
        let dossier = self.assemble_dossier(id).await?;
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            DppError::Internal("evidence store not configured on this service".into())
        })?;
        let doc_hash = content_hash(
            &serde_json::to_value(&dossier).map_err(|e| DppError::Serialisation(e.to_string()))?,
        )
        .map_err(|e| DppError::Serialisation(e.to_string()))?;
        let record = EvidenceDossierRecord {
            id: Uuid::now_v7(),
            passport_id: id,
            actor: auth.user_id.clone(),
            created_at: dossier.manifest.created_at,
            doc_hash,
            dossier,
        };
        store.insert(&record).await?;
        Ok(record)
    }

    /// List stored dossier summaries for a passport, newest first.
    /// 404s if the passport itself doesn't exist.
    pub async fn list_evidence(
        &self,
        id: PassportId,
    ) -> Result<Vec<EvidenceDossierSummary>, DppError> {
        self.find_by_id(id).await?;
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            DppError::Internal("evidence store not configured on this service".into())
        })?;
        store.list_by_passport(id).await
    }

    /// Fetch one stored dossier by id.
    pub async fn get_evidence(&self, dossier_id: Uuid) -> Result<EvidenceDossierRecord, DppError> {
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            DppError::Internal("evidence store not configured on this service".into())
        })?;
        store
            .get(dossier_id)
            .await?
            .ok_or_else(|| DppError::NotFound(dossier_id.to_string()))
    }

    /// Verify a stored dossier's signatures and hash chains.
    pub async fn verify_evidence(&self, dossier_id: Uuid) -> Result<VerificationReport, DppError> {
        let record = self.get_evidence(dossier_id).await?;
        // The record already carries a typed `DossierV1` — verify it directly
        // rather than serialising to bytes and re-parsing through
        // `verify_dossier_json`, which exists for the *uploaded-document* path
        // where the input genuinely starts as untyped bytes.
        Ok(crate::domain::verify::verify_dossier(
            &record.dossier,
            self.seal_inspector.as_deref(),
        ))
    }

    /// Assemble the evidence dossier for a passport. Requires the passport to
    /// have been published at least once (a `Draft` has no signature to
    /// export yet).
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    async fn assemble_dossier(&self, id: PassportId) -> Result<DossierV1, DppError> {
        let passport = self.find_by_id(id).await?;
        if matches!(passport.status, PassportStatus::Draft) {
            return Err(DppError::Validation(
                "cannot export evidence for a draft passport — publish it first".into(),
            ));
        }

        let audit_raw = self.audit.list_by_passport(&id.to_string()).await?;

        // The exact bytes that were signed, recovered from the most recent
        // "published" audit entry — never reconstructed from the current
        // passport row, which may have since mutated (suspend/archive/eol
        // change `status` without re-signing). See `publish.rs` for why this
        // metadata is stamped there.
        let (full_view_payload, public_view_payload) = audit_raw
            .iter()
            .rev()
            .find(|e| e.action == "published")
            .and_then(|e| e.metadata.as_ref())
            .and_then(|m| Some((m.get("fullViewPayload")?.clone(), m.get("publicViewPayload")?.clone())))
            .ok_or_else(|| {
                DppError::Internal(format!(
                    "passport {id} is {:?} but has no \"published\" audit entry with a signed-payload snapshot",
                    passport.status
                ))
            })?;

        let jws_signature = passport.jws_signature.clone().ok_or_else(|| {
            DppError::Internal(format!(
                "passport {id} has no jws_signature despite non-draft status"
            ))
        })?;
        let public_jws_signature = passport.public_jws_signature.clone().ok_or_else(|| {
            DppError::Internal(format!(
                "passport {id} has no public_jws_signature despite non-draft status"
            ))
        })?;

        // The EOL record, if any, rides the same way — metadata on the
        // "deactivated" audit entry (declare_eol in eol.rs); there is no
        // separate EOL repository.
        let eol_event = audit_raw
            .iter()
            .rev()
            .find(|e| e.action == "deactivated")
            .and_then(|e| e.metadata.clone());

        let transfer_chain = match &self.transfer_store {
            Some(store) => store.get_chain(id).await?,
            None => None,
        };

        let own_doc = self.identity.own_did_document().await?;
        let issuer_did = own_doc
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DppError::Internal("identity service's DID document has no \"id\"".into())
            })?
            .to_string();

        let mut did_documents = BTreeMap::new();
        did_documents.insert(issuer_did.clone(), own_doc);

        // Best-effort: fetch each transfer counterparty's DID document over
        // HTTPS. An unresolvable remote DID is simply left out of the map —
        // the verifier then reports that signature as unverifiable rather
        // than silently skipping it (fail-closed, never false-green).
        if let Some(chain) = &transfer_chain {
            for record in &chain.transfers {
                for did in [&record.from_operator.did, &record.to_operator.did] {
                    if did_documents.contains_key(did) {
                        continue;
                    }
                    match fetch_remote_did_document(did).await {
                        Ok(doc) => {
                            did_documents.insert(did.clone(), doc);
                        }
                        Err(e) => {
                            tracing::warn!(
                                passport_id = %id,
                                did = %did,
                                error = %e,
                                "evidence export: could not fetch counterparty DID document (non-fatal — verifier will report Unverifiable)"
                            );
                        }
                    }
                }
            }
        }

        let ruleset_version = passport
            .compliance_result
            .as_ref()
            .and_then(|r| r.ruleset_version.clone());

        // Attest the component tree (BOM) when this passport declares one: verify
        // it now and embed the report, bound into the dossier via content_hashes.
        let component_graph = if passport.component_refs.is_empty() {
            None
        } else {
            let report = crate::domain::verify::verify_tree(
                &passport.component_refs,
                crate::domain::verify::fetch_public_json,
                dpp_domain::graph::DEFAULT_DEPTH_CAP,
                crate::domain::verify::DEFAULT_NODE_CAP,
            )
            .await;
            Some(serde_json::to_value(report).map_err(|e| DppError::Serialisation(e.to_string()))?)
        };

        // The qualified seal, with the preimage it was taken over. Included
        // because a dossier is what an authority is handed and the seal is the
        // one member carrying an eIDAS Art. 35(2) presumption — and because it
        // is unreachable from the dossier otherwise: the seal is stripped from
        // both views above, since it covers the full-payload signature rather
        // than any redaction of it. `None` when the seal is still queued.
        let qualified_seal = passport.seal.as_ref().and_then(|seal| {
            let jws = passport.jws_signature.as_ref()?;
            let payload_hash = crate::domain::service::seal::seal_digest(&passport)?;
            // Read once: `binding` and `validation` below must agree, and two
            // separate calls could in principle answer differently — which would
            // put a dossier on the record contradicting itself.
            let binding = self
                .seal_inspector
                .as_ref()
                .map_or(dpp_types::SealBinding::Unknown, |i| {
                    i.binding(seal, &payload_hash)
                });
            Some(serde_json::json!({
                "seal": seal,
                // Served so a verifier holding only this file has both the CAdES
                // and what it should be checked against, with no reconstruction.
                "signedOverJws": jws,
                "payloadHash": payload_hash,
                // Whether the seal actually covers the signature served beside
                // it — and this is not decoration.
                //
                // The JWS above is the passport's *current* one. A passport
                // re-published after sealing carries a seal over the previous
                // signature until the drain catches up, and if the drain is
                // exhausted that window has no end. A dossier pairing the two
                // silently would hand an authority a seal that does not verify
                // against the document beside it — which reads as tampering,
                // rather than as the stale seal it is.
                //
                // Reported rather than allowed to block generation: a dossier
                // must be producible in whatever state the passport is actually
                // in, and saying so plainly beats refusing to say anything.
                "binding": binding,
                // The same reading in ETSI EN 319 102-1's words — the vocabulary
                // an auditor's own validation tooling reports in, and the one
                // CIR (EU) 2025/1945 points at for qualified seals. Derived, not
                // a second check.
                //
                // It never says `totalPassed`: that requires the signer's
                // certificate to have been validated, which this node does not
                // do. A dossier reader seeing `coversThisSignature` and no such
                // caveat could reasonably conclude otherwise.
                "validation": binding.validation_status(),
                // Who issued the certificate behind the seal.
                //
                // The dossier already named *which* certificate, as a thumbprint
                // — enough to ask an auditor's question about, and not enough to
                // answer the first one anybody actually has. A self-signed
                // development seal and a QTSP's are the same field otherwise, and
                // telling them apart meant parsing the CAdES by hand.
                //
                // The one fact that decides whether anything else in this section
                // carries weight, so it travels with it rather than being
                // recoverable from it.
                "origin": self.seal_inspector.as_ref().and_then(|i| i.origin(seal)),
                // What the bytes carry, beside what was asked for — a seal
                // weaker than ordered is otherwise visible only in a drain log
                // that no dossier reader has.
                "evidencedLevel": self
                    .seal_inspector
                    .as_ref()
                    .and_then(|i| i.evidenced_level(seal)),
                // A third party's statement of when this was sealed, as opposed
                // to `seal.sealedAt`, which is the sealing node's own clock. An
                // authority reading a dossier has no other way to reach it — the
                // token is inside the CAdES.
                "attestedSealedAt": self
                    .seal_inspector
                    .as_ref()
                    .and_then(|i| i.attested_sealing_time(seal)),
                // Stamped at generation, like every other finding here. A reader
                // opening this file in 2035 needs to know the archival
                // protection had not already lapsed when it was made — and
                // cannot recompute it against the clock of the day it is read,
                // because that answer would be about a different moment.
                "archival": self.seal_inspector.as_ref().map_or(
                    dpp_types::ArchivalFreshness::Unknown,
                    |i| i.archival_freshness(seal, chrono::Utc::now()),
                ),
            }))
        });

        let mut dossier = DossierV1 {
            manifest: DossierManifest {
                format_version: "1".to_string(),
                passport_id: id.to_string(),
                issuer_did,
                created_at: chrono::Utc::now(),
                node_version: env!("CARGO_PKG_VERSION").to_string(),
                core_version: dpp_domain::VERSION.to_string(),
                ruleset_version,
                content_hashes: BTreeMap::new(),
            },
            manifest_jws: String::new(),
            full_view: SignedLayer {
                payload: full_view_payload,
                jws: jws_signature,
            },
            public_view: SignedLayer {
                payload: public_view_payload,
                jws: public_jws_signature,
            },
            did_documents,
            audit_entries: audit_raw,
            transfer_chain,
            eol_event,
            checkpoint: None,
            calc_receipts: Vec::new(),
            component_graph,
            qualified_seal,
        };

        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).map_err(|e| DppError::Serialisation(e.to_string()))?;
        let manifest_value = serde_json::to_value(&dossier.manifest)
            .map_err(|e| DppError::Serialisation(e.to_string()))?;
        let signed = self.identity.sign_passport(id, &manifest_value).await?;
        dossier.manifest_jws = signed.jws;

        Ok(dossier)
    }
}

/// Fetch a transfer counterparty's `did:web` document.
///
/// The DID comes from a `TransferRecord`, which a caller supplied verbatim on
/// `POST /dpp/{id}/transfer/initiate` — so the fetch target is chosen by an API
/// client, not by this operator, and the response is embedded in the dossier
/// this call returns. That combination is a read primitive, not a blind fetch,
/// which is why it goes through the shared guarded path
/// ([`dpp_common::outbound`]) rather than a bare client: the guard refuses
/// internal targets, redirects are not followed so a public host cannot bounce
/// into the internal network, the body is capped, and the request times out.
async fn fetch_remote_did_document(did: &str) -> Result<serde_json::Value, DppError> {
    let url = crate::domain::verify::did_web_url(did).map_err(DppError::Internal)?;
    dpp_common::outbound::fetch_json(
        &dpp_common::outbound::guarded_client(),
        &url,
        dpp_common::outbound::DEFAULT_MAX_BODY,
    )
    .await
    .map_err(|e| DppError::Internal(format!("{url}: {e}")))
}
